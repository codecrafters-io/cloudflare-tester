import argparse
import os

scenario = os.environ.get("CLASSIFIER_SCENARIO", "pass_all")
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


def message_texts(body):
    """Return every string the model reads, or None if the request can't be inspected."""
    try:
        texts = []
        for message in json.loads(body)["messages"]:
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
        return texts
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
    if scenario == "first_message_only":
        messages = messages[:1]
    if not messages:
        return []

    def classify(message):
        if scenario == "drop_role":
            message = {"content": message.get("content")}
        if scenario == "normalize_detector_input":
            message = json.loads(json.dumps(message))
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = content.casefold()
            elif isinstance(content, list):
                for part in content:
                    part["text"] = part["text"].casefold()
        request = urllib.request.Request(
            endpoint.rstrip("/") + "/classify",
            data=json.dumps(message, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", **({"Authorization": "Bearer course-test-key"} if scenario == "leak_authorization" else {})},
            method="POST",
        )
        with opener.open(request, timeout=2 if scenario in ("no_timeout", "wait_on_shutdown") else 0.2) as response:
            if response.status != 200:
                raise ValueError("Classifier did not return HTTP 200")
            score = json.loads(response.read())["score"]
            if type(score) is not int or not 0 <= score <= 100:
                raise ValueError("Invalid classifier score")
            return score

    if scenario == "sequential":
        return [classify(message) for message in messages]
    deadline = time.monotonic() + 0.2
    workers = ThreadPoolExecutor(max_workers=len(messages))
    try:
        futures = [workers.submit(classify, message) for message in messages]
        _, pending = wait(futures, timeout=None if scenario == "no_timeout" else max(0, deadline - time.monotonic()))
        if pending:
            return None
        return [future.result() for future in futures]
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        if scenario == "keep_partial_scores":
            good = [future.result() for future in futures if future.done() and future.exception() is None]
            return good or None
        return None
    finally:
        # A late result must not delay or change this request's decision.
        workers.shutdown(wait=scenario == "wait_on_shutdown", cancel_futures=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin")
    parser.add_argument("--detector")
    parser.add_argument("--policy")
    args = parser.parse_args()

    with open(args.policy, encoding="utf-8") as policy_file:
        policy = json.load(policy_file)

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
            texts = message_texts(body)
            if texts is None:
                self.send_error(400, "Could not inspect request")
                return
            inspection = [
                candidate
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
            if "heuristics" in policy:
                score, signals = score_heuristics(inspection, policy["heuristics"])
                score_headers["X-Firewall-Score"] = str(score)
                if signals:
                    score_headers["X-Firewall-Signals"] = ",".join(signals)
                if not matched_rule and score >= policy["heuristics"]["threshold"]:
                    matched_rule = "heuristic_score"
            if "classifier" in policy and scenario == "hardcoded_threshold":
                policy["classifier"]["threshold"] = 70
            detector_unavailable = False
            if "classifier" in policy and scenario != "previous_stage":
                scores = classify_messages(body, args.detector, detector_opener)
                if scores is None:
                    score_headers["X-Firewall-Detector-Status"] = "unavailable"
                    detector_unavailable = scenario == "always_closed" or (policy["classifier"]["failure_mode"] == "fail_closed" and scenario != "always_open")
                    if detector_unavailable:
                        matched_rule = "detector_unavailable"
                else:
                    highest = max(scores, default=0)
                    score_headers["X-Firewall-Detector-Status"] = "ok"
                    score_headers["X-Firewall-Classifier-Score"] = str(highest)
                    if not matched_rule and highest >= policy["classifier"]["threshold"]:
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
