import os
EXPORT_MODE=os.environ.get("EXPORT_MODE","pass_all")
import urllib.parse
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
    request = json.loads(body)
    placeholders = {}
    changed = False

    def redact(text):
        nonlocal changed
        result = []
        while text:
            best = None
            for pattern in patterns:
                match = pattern.search(text)
                if match and (best is None or match.start() < best.start()):
                    best = match
            if best is None:
                result.append(text)
                break
            value = best.group()
            if value not in placeholders:
                placeholders[value] = f"[REDACTED_{len(placeholders) + 1}]"
            result.extend((text[:best.start()], placeholders[value]))
            text = text[best.end():]
            changed = True
        return "".join(result)

    for message in request["messages"]:
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = redact(content)
        elif isinstance(content, list):
            for part in content:
                part["text"] = redact(part["text"])
    return json.dumps(request).encode() if changed else body


def contains_canary(body, canary):
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




def reject_json_constant(value):
    raise ValueError("Non-JSON number")


def tool_rule(calls, tools):
    if tools is None:
        return ""
    for call in calls:
        function = call.get("function", {})
        name = function.get("name")
        if name not in tools or call.get("type") != "function":
            return "tool_not_allowed"
        try:
            arguments = json.loads(function.get("arguments", ""), parse_constant=reject_json_constant)
        except (ValueError, TypeError):
            return "tool_arguments_invalid"
        if not isinstance(arguments, dict):
            return "tool_arguments_invalid"
        settings = tools[name]
        if not settings.get("url_argument"):
            continue
        raw = arguments.get(settings["url_argument"])
        if not isinstance(raw, str):
            return "tool_arguments_invalid"
        if any(ord(character) <= 32 or ord(character) == 127 or character == "\\" for character in raw):
            return "tool_destination_not_allowed"
        try:
            target = urllib.parse.urlsplit(raw)
            port = target.port
            if (target.scheme not in ("http", "https") or not target.hostname
                    or target.username is not None or target.netloc.endswith(":")
                    or (port is not None and not 1 <= port <= 65535)):
                return "tool_destination_not_allowed"
        except ValueError:
            return "tool_destination_not_allowed"
        if target.hostname.lower() not in [host.lower() for host in settings["allowed_hosts"]]:
            return "tool_destination_not_allowed"
    return ""


def response_tool_rule(body, tools):
    if tools is None:
        return ""
    try:
        response = json.loads(body)
        for choice in response.get("choices", []):
            rule = tool_rule(choice.get("message", {}).get("tool_calls") or [], tools)
            if rule:
                return rule
    except (ValueError, TypeError, AttributeError):
        return "tool_arguments_invalid"
    return ""



def private_values(body, settings):
    if settings is None:
        return []
    messages = json.loads(body)["messages"]
    if EXPORT_MODE == "all_results_private":
        return [value for message in messages if message.get("role")=="tool"
                for value in ([message["content"]] if not message["content"].startswith("{") else json.loads(message["content"]).values())]
    names = {call["id"]: call["function"]["name"]
             for message in messages if message.get("role") == "assistant"
             for call in message.get("tool_calls") or []}
    values = []
    for message in messages:
        if (message.get("role") == "tool"
                and (message.get("name") if EXPORT_MODE=="trust_result_name" else names.get(message.get("tool_call_id"))) in settings["private_tools"]):
            if EXPORT_MODE == "trust_result_name" and not message["content"].startswith("{"):
                continue
            if EXPORT_MODE == "whole_record_only":
                values.append(message["content"])
            else:
                values.extend(json.loads(message["content"]).values())
    if EXPORT_MODE == "persistent_state":
        private_values.retained = getattr(private_values,"retained",[]) + values
        return private_values.retained
    return values


def argument_strings(value):
    if isinstance(value, str):
        yield value
        if EXPORT_MODE == "skip_query_values":
            return
        try:
            target = urllib.parse.urlsplit(value)
            if target.scheme in ("http", "https") and target.netloc:
                for values in urllib.parse.parse_qs(target.query, keep_blank_values=True).values():
                    yield from values
        except ValueError:
            pass
    elif isinstance(value, list):
        for item in value:
            yield from argument_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from argument_strings(item)


def export_rule(calls, settings, values, normalization):
    if EXPORT_MODE == "skip_exports" or settings is None or not values:
        return ""
    if EXPORT_MODE == "hardcoded_exports":
        settings={"private_tools":["read_customer_record"],"allowed":[{"tool":"send_email","destination_argument":"to","email_domain":"crm.example.com"}]}
    if normalization is None:
        normalization = {"zero_width": [], "homoglyphs": {}}
    protected = [inspection_texts(value, normalization)[0] for value in values]
    if EXPORT_MODE == "first_call_only":
        calls=calls[:1]
    for call in calls:
        try:
            arguments = json.loads(call["function"]["arguments"], parse_constant=reject_json_constant)
        except (ValueError, TypeError):
            return "tool_arguments_invalid"
        if not isinstance(arguments, dict):
            return "tool_arguments_invalid"
        matched = any(value in candidate for text in argument_strings(arguments)
                      for candidate in ([inspection_texts(text, normalization)[0]] if EXPORT_MODE == "literal_only" else inspection_texts(text, normalization))
                      for value in protected if value)
        if not matched:
            continue
        approved = False
        for export in settings["allowed"]:
            if EXPORT_MODE != "destination_only" and export["tool"] != call["function"]["name"]:
                continue
            recipient = arguments.get(export["destination_argument"])
            if (isinstance(recipient, str) and recipient.count("@") == 1
                    and all(32 < ord(character) < 127 for character in recipient)):
                local, domain = recipient.split("@")
                if local and (export["email_domain"].lower() in domain.lower() if EXPORT_MODE == "substring_domain" else domain.lower() == export["email_domain"].lower()):
                    approved = True
                    break
        if not approved:
            return "private_export"
    return ""


def response_export_rule(body, settings, values, normalization):
    if EXPORT_MODE == "skip_nonstream" or settings is None or not values:
        return ""
    for choice in json.loads(body).get("choices", []):
        rule = export_rule(choice.get("message", {}).get("tool_calls") or [], settings, values, normalization)
        if rule:
            return rule
    return ""


def inspect_stream(origin, emit, canary, tools, exports, values, normalization):
    calls = {}
    pending = ""
    keep = max(0, len(canary) - 1)

    def emit_text(text):
        if text:
            emit({"id": "chatcmpl-firewall", "object": "chat.completion.chunk",
                  "created": 0, "model": "course-model", "choices": [
                      {"index": 0, "delta": {"content": text}, "finish_reason": None}]})

    for line in origin:
        if not line.startswith(b"data:"):
            continue
        data = line[5:].strip()
        if data == b"[DONE]":
            batch = [calls[index] for index in sorted(calls)]
            rule = "canary_leak" if batch and canary and contains_canary(json.dumps(batch).encode(), canary) else tool_rule(batch, tools)
            if not rule:
                rule = "" if EXPORT_MODE == "skip_stream" else export_rule(batch, exports, values, normalization)
            if EXPORT_MODE == "stream_non_atomic" and rule == "private_export" and len(batch)>1:
                emit({"id":"chatcmpl-firewall","object":"chat.completion.chunk","created":0,"model":"course-model","choices":[{"index":0,"delta":{"tool_calls":[batch[0]]},"finish_reason":None}]})
            if rule:
                emit({"error": {"message": ("Blocked Customer-4829" if EXPORT_MODE=="leak_stream_error" else "Blocked outgoing tool call"), "type": "firewall_block", "rule": rule}})
                return
            emit_text(pending)
            if batch:
                emit({"id": "chatcmpl-firewall", "object": "chat.completion.chunk",
                      "created": 0, "model": "course-model", "choices": [
                          {"index": 0, "delta": {"tool_calls": batch}, "finish_reason": "tool_calls"}]})
            emit("[DONE]")
            return
        chunk = json.loads(data)
        if not chunk.get("choices"):
            continue
        delta = chunk["choices"][0].get("delta", {})
        for fragment in delta.get("tool_calls") or []:
            index = fragment["index"]
            if index not in calls:
                calls[index] = {"index": index, "id": "", "type": "", "function": {"name": "", "arguments": ""}}
            call = calls[index]
            call["id"] += fragment.get("id", "")
            call["type"] += fragment.get("type", "")
            call["function"]["name"] += fragment.get("function", {}).get("name", "")
            call["function"]["arguments"] += fragment.get("function", {}).get("arguments", "")
        pending += delta.get("content") or ""
        if canary and canary in pending:
            emit({"error": {"message": "Blocked outgoing canary",
                            "type": "firewall_block", "rule": "canary_leak"}})
            return
        if len(pending) > keep:
            emit_text(pending[:len(pending) - keep])
            pending = pending[len(pending) - keep:]


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
            protected = private_values(body, policy.get("exports"))
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
            streaming = json.loads(body).get("stream") is True
            request = urllib.request.Request(
                args.origin.rstrip("/") + self.path,
                data=body,
                headers=headers,
                method="POST",
            )
            try:
                response = urllib.request.urlopen(request, timeout=5 if streaming else 2)
            except urllib.error.HTTPError as error:
                response = error
            except urllib.error.URLError:
                self.send_response(502)
                for name, value in score_headers.items():
                    self.send_header(name, value)
                self.end_headers()
                return
            with response:
                if (streaming and ("dlp" in policy or "tools" in policy or "exports" in policy)
                        and response.status == 200
                        and response.headers.get("Content-Type", "").startswith("text/event-stream")):
                    self.send_response(200)
                    for name in ("Content-Type", "X-Request-Id"):
                        if name in response.headers:
                            self.send_header(name, response.headers[name])
                    for name, value in score_headers.items():
                        self.send_header(name, value)
                    if matched_rule:
                        self.send_header("X-Firewall-Match", matched_rule)
                    self.end_headers()

                    def emit(value):
                        data = value if value == "[DONE]" else json.dumps(value)
                        self.wfile.write(("data: " + data + "\n\n").encode())
                        self.wfile.flush()

                    inspect_stream(response, emit, policy.get("dlp", {}).get("canary", ""), policy.get("tools"), policy.get("exports"), protected, policy.get("normalization"))
                    return
                data = response.read()
                rule = ""
                if "dlp" in policy and contains_canary(data, policy["dlp"]["canary"]):
                    rule = "canary_leak"
                if not rule and response.status == 200:
                    rule = response_tool_rule(data, policy.get("tools"))
                    if not rule:
                        rule = response_export_rule(data, policy.get("exports"), protected, policy.get("normalization"))
                if rule:
                    data = json.dumps({"error": {"message": ("Blocked Customer-4829" if EXPORT_MODE=="leak_nonstream_error" else "Blocked outgoing response"),
                        "type": "firewall_block", "rule": rule}}).encode()
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
