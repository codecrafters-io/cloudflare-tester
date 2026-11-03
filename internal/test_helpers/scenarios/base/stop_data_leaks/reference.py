import os
MODE = os.environ.get("MODE", "pass_all")
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, wait
import time
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

    deadline = time.monotonic() + 0.2
    workers = ThreadPoolExecutor(max_workers=len(messages))
    try:
        futures = [workers.submit(classify, message) for message in messages]
        _, pending = wait(futures, timeout=max(0, deadline - time.monotonic()))
        if pending:
            return None
        return [future.result() for future in futures]
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        return None
    finally:
        # A late result must not delay or change this request's decision.
        workers.shutdown(wait=False, cancel_futures=True)


def decision_rule(messages, scores, settings, heuristics, normalization):
    for (role, texts), classifier_score in zip(messages, scores):
        thresholds = settings["tool" if role == "tool" else "default"]
        if classifier_score >= thresholds["classifier_high"]:
            return "classifier_high"
        heuristic_score = 0
        if heuristics is not None:
            candidates = [candidate for text in texts for candidate in inspection_texts(text, normalization)]
            heuristic_score, _ = score_heuristics(candidates, heuristics)
        if (classifier_score >= thresholds["classifier_medium"]
                and heuristic_score >= thresholds["heuristic_medium"]):
            return "combined_scores"
    return ""



def redact_request(body, patterns):
    if MODE == "skip_redaction":
        return body
    request = json.loads(body)
    placeholders = {}
    changed = False
    occurrence = 0
    if MODE == "hardcoded_patterns":
        patterns = [re.compile(r"sk-[A-Za-z0-9]{8,}"), re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}")]

    def redact(text):
        nonlocal changed, occurrence
        result = []
        while text:
            best = None
            for pattern in patterns:
                match = pattern.search(text)
                if match and (best is None or (match.start() <= best.start() if MODE == "wrong_overlap_order" else match.start() < best.start())):
                    best = match
            if best is None:
                result.append(text)
                break
            occurrence += 1
            value = best.group()
            if MODE == "reuse_values":
                value += str(occurrence)
            if value not in placeholders:
                placeholders[value] = f"[REDACTED_{len(placeholders) + 1}]"
            result.extend((text[:best.start()], placeholders[value]))
            text = text[best.end():]
            changed = True
        return "".join(result)

    for message in request["messages"]:
        if MODE == "per_message_map":
            placeholders.clear()
        if MODE == "users_only" and message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = redact(content)
        elif isinstance(content, list) and MODE != "strings_only":
            for part in content:
                part["text"] = redact(part["text"])
    return json.dumps(request).encode() if changed else body


def contains_canary(body, canary):
    if MODE == "skip_output":
        return False
    if MODE == "hardcoded_canary":
        canary = "CANARY_COURSE_7F2A"
    if MODE == "raw_only_canary":
        return canary.encode() in body
    if MODE == "first_choice_only":
        try:
            return canary in json.loads(body)["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return False
    if canary.encode() in body:
        return True

    def contains(value):
        if isinstance(value, str):
            return canary in value
        if isinstance(value, list):
            return any(contains(child) for child in value)
        if isinstance(value, dict):
            return any(contains(child) for child in value.values())
        return False

    try:
        return contains(json.loads(body))
    except (ValueError, UnicodeDecodeError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin")
    parser.add_argument("--detector")
    parser.add_argument("--policy")
    args = parser.parse_args()

    with open(args.policy, encoding="utf-8") as policy_file:
        policy = json.load(policy_file)

    redaction_patterns = [re.compile(pattern) for pattern in policy.get("dlp", {}).get("patterns", [])]
    detector_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoDetectorRedirect())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

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
                if not matched_rule and "decisions" not in policy and score >= policy["heuristics"]["threshold"]:
                    matched_rule = "heuristic_score"
            detector_unavailable = False
            if "classifier" in policy:
                scores = classify_messages(body, args.detector, detector_opener)
                if scores is None:
                    score_headers["X-Firewall-Detector-Status"] = "unavailable"
                    detector_unavailable = policy["classifier"]["failure_mode"] == "fail_closed"
                    if detector_unavailable:
                        matched_rule = "detector_unavailable"
                    elif (not matched_rule and "heuristics" in policy
                            and heuristic_score >= policy["heuristics"]["threshold"]):
                        matched_rule = "heuristic_score"
                else:
                    highest = max(scores, default=0)
                    score_headers["X-Firewall-Detector-Status"] = "ok"
                    score_headers["X-Firewall-Classifier-Score"] = str(highest)
                    if not matched_rule:
                        if "decisions" in policy:
                            matched_rule = decision_rule(messages, scores, policy["decisions"],
                                                         policy.get("heuristics"), policy.get("normalization"))
                        elif highest >= policy["classifier"]["threshold"]:
                            matched_rule = "classifier_score"
            if matched_rule and (policy.get("mode", "block") != "log" or detector_unavailable):
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
            if "dlp" in policy:
                body = redact_request(body, redaction_patterns)
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
                if ("dlp" in policy and contains_canary(data, policy["dlp"]["canary"])
                        and not (MODE == "log_allows_canary" and policy.get("mode") == "log")):
                    data = json.dumps({"error": {"message": "Blocked outgoing canary",
                        "type": "firewall_block", "rule": "canary_leak"}}).encode()
                    if MODE == "leak_extra_field":
                        value = json.loads(data)
                        value["leaked"] = policy["dlp"]["canary"]
                        data = json.dumps(value).replace("C", "\\u0043").encode()
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    for name, value in score_headers.items():
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(data)
                    return
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

    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
