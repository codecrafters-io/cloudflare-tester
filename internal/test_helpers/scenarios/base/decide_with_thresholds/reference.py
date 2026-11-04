import argparse
import os

scenario = os.environ.get("THRESHOLD_SCENARIO", "pass_all")
import base64
import binascii
import unicodedata
import json
import http.client
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def inspection_texts(text, settings):
    if settings is None:
        return [text]

    def normalize(value):
        for character in settings["zero_width"]:
            value = value.replace(character, "")
        value = unicodedata.normalize("NFKC", value).casefold()
        return "".join(settings["homoglyphs"].get(character, character) for character in value)

    candidates = [normalize(text)]
    try:
        decoded = base64.b64decode(text, validate=True)
        candidates.append(normalize(decoded.decode("utf-8")))
    except (ValueError, binascii.Error):
        pass
    return candidates


def inspect_messages(body):
    """Keep each role and text group aligned with its classifier result."""
    try:
        messages = []
        for message in json.loads(body)["messages"]:
            texts = []
            content = message.get("content")
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if part.get("type") != "text" or not isinstance(part.get("text"), str):
                        return None
                    texts.append(part["text"])
            elif content is not None:
                return None
            messages.append((message.get("role"), texts))
        return messages
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def near_terms(text, first, second, max_gap):
    def positions(term):
        return [index for index in range(len(text)) if text.startswith(term, index)]

    for left in positions(first):
        for right in positions(second):
            if 0 <= right - (left + len(first)) <= max_gap:
                return True
            if 0 <= left - (right + len(second)) <= max_gap:
                return True
    return False


def score_heuristics(candidates, settings):
    score, signals = 0, []
    for signal in settings["signals"]:
        for text in candidates:
            matched = signal["term"] in text if signal["kind"] == "contains" else near_terms(
                text, signal["term"], signal["other"], signal["max_gap"]
            )
            if matched:
                score += signal["weight"]
                signals.append(signal["id"])
                break
    return score, signals


class NoDetectorRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def classify_messages(body, endpoint, opener):
    messages = json.loads(body)["messages"]
    if not messages:
        return []

    def classify(message):
        request = urllib.request.Request(
            endpoint.rstrip("/") + "/classify",
            data=json.dumps(message, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(request, timeout=0.2) as response:
            if response.status != 200:
                raise ValueError("Classifier did not return HTTP 200")
            score = json.loads(response.read())["score"]
            if type(score) is not int or not 0 <= score <= 100:
                raise ValueError("Invalid classifier score")
            return score

    scores = []
    available = True
    for message in messages:
        try:
            scores.append(classify(message))
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            available = False
    if scenario == "arrival_order" and available:
        return list(reversed(scores))
    return scores if available else None


def decision_rule(messages, scores, settings, heuristics, normalization):
    if scenario == "hardcoded_thresholds":
        settings = {"default":{"classifier_high":90,"classifier_medium":60,"heuristic_medium":3},"tool":{"classifier_high":80,"classifier_medium":40,"heuristic_medium":2}}
    seen = set()
    for (role, texts), classifier_score in zip(messages, scores):
        thresholds = settings["tool" if role == "tool" else "default"]
        if scenario == "ignore_tool_role":
            thresholds = settings["default"]
        if scenario == "tool_for_all_roles":
            thresholds = settings["tool"]
        if scenario == "classifier_max":
            classifier_score = max(scores, default=0)
        if (classifier_score > thresholds["classifier_high"] if scenario == "strict_high" else classifier_score >= thresholds["classifier_high"]):
            return "classifier_high"
        heuristic_score = 0
        if heuristics is not None:
            candidates = [candidate for text in texts for candidate in inspection_texts(text, normalization)]
            if scenario == "request_wide_heuristics":
                candidates = [candidate for _, group in messages for text in group for candidate in inspection_texts(text, normalization)]
            if scenario == "skip_message_normalization":
                candidates = texts
            if scenario == "global_signal_counts":
                remaining = {**heuristics, "signals": [signal for signal in heuristics["signals"] if signal["id"] not in seen]}
                heuristic_score, fired = score_heuristics(candidates, remaining)
                seen.update(fired)
            else:
                heuristic_score, _ = score_heuristics(candidates, heuristics)
        classifier_match = classifier_score > thresholds["classifier_medium"] if scenario == "strict_classifier_medium" else classifier_score >= thresholds["classifier_medium"]
        heuristic_match = heuristic_score > thresholds["heuristic_medium"] if scenario == "strict_heuristic_medium" else heuristic_score >= thresholds["heuristic_medium"]
        if (classifier_match or heuristic_match) if scenario == "or_instead_of_and" else (classifier_match and heuristic_match):
            return "combined_scores"
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin")
    parser.add_argument("--detector")
    parser.add_argument("--policy")
    args = parser.parse_args()

    with open(args.policy, encoding="utf-8") as policy_file:
        policy = json.load(policy_file)
    if scenario == "previous_stage":
        policy.pop("decisions", None)

    detector_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoDetectorRedirect())

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/health" else 404)
            self.end_headers()

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            messages = inspect_messages(body)
            if messages is None:
                self.send_error(400, "Could not inspect request")
                return
            inspection = [
                candidate
                for _, texts in messages
                for text in texts
                for candidate in inspection_texts(text, policy.get("normalization"))
            ]
            matched_rule = next(
                (
                    rule["id"]
                    for rule in policy.get("denylist", [])
                    if any(rule["term"] in text for text in inspection)
                ),
                "",
            )
            score_headers = {}
            heuristic_score = 0
            if "heuristics" in policy:
                score, signals = score_heuristics(inspection, policy["heuristics"])
                heuristic_score = score
                score_headers["X-Firewall-Score"] = str(score)
                if signals:
                    score_headers["X-Firewall-Signals"] = ",".join(signals)
                if not matched_rule and ("decisions" not in policy or scenario == "keep_heuristic_cutoff") and score >= policy["heuristics"]["threshold"]:
                    matched_rule = "heuristic_score"
            if "classifier" in policy:
                scores = classify_messages(body, args.detector, detector_opener)
                if scores is None:
                    score_headers["X-Firewall-Detector-Status"] = "unavailable"
                    if (not matched_rule and "heuristics" in policy
                            and heuristic_score >= policy["heuristics"]["threshold"] and scenario != "fallback_ignores_heuristics"):
                        matched_rule = "heuristic_score"
                else:
                    highest = max(scores, default=0)
                    score_headers["X-Firewall-Detector-Status"] = "ok"
                    score_headers["X-Firewall-Classifier-Score"] = str(highest)
                    if scenario == "keep_classifier_cutoff" and not matched_rule and highest >= policy["classifier"]["threshold"]:
                        matched_rule = "classifier_score"
                    if not matched_rule:
                        if "decisions" in policy:
                            matched_rule = decision_rule(messages, scores, policy["decisions"],
                                                         policy.get("heuristics"), policy.get("normalization"))
                        elif highest >= policy["classifier"]["threshold"]:
                            matched_rule = "classifier_score"
            if matched_rule and (policy.get("mode", "block") != "log" or scenario == "log_blocks"):
                data = json.dumps({"error": {
                    "message": "Blocked by firewall policy",
                    "type": "firewall_block",
                    "rule": matched_rule,
                }}).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in score_headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)
                return
            headers = {
                name: self.headers[name]
                for name in ("Authorization", "Content-Type")
                if name in self.headers
            }
            request = urllib.request.Request(
                args.origin.rstrip("/") + self.path,
                data=body,
                headers=headers,
                method="POST",
            )
            try:
                response = urllib.request.urlopen(request, timeout=2)
            except urllib.error.HTTPError as error:
                response = error
            except urllib.error.URLError:
                self.send_response(502)
                for name, value in score_headers.items():
                    self.send_header(name, value)
                self.end_headers()
                return
            with response:
                data = response.read()
                self.send_response(response.status)
                for name in ("Content-Type", "X-Request-Id"):
                    if name in response.headers:
                        self.send_header(name, response.headers[name])
                for name, value in score_headers.items():
                    self.send_header(name, value)
                if matched_rule:
                    self.send_header("X-Firewall-Match", matched_rule)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        def log_message(self, format, *values):
            pass

    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
