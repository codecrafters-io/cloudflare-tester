"""Offline normalization reference and focused regressions for stage 4."""

import argparse
import base64
import binascii
import unicodedata
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--origin", required=True)
parser.add_argument("--detector", required=True)
parser.add_argument("--policy", required=True)
args = parser.parse_args()
mode = os.environ.get("EVASION_SCENARIO", "pass_all")
policy = json.loads(Path(args.policy).read_text())


def normalize(value):
    settings = policy["normalization"]

    def remove_zero_width(value):
        for character in settings["zero_width"]:
            value = value.replace(character, "")
        return value

    if mode not in ("skip_zero_width", "zero_width_after_nfkc"):
        value = remove_zero_width(value)
    if mode != "skip_nfkc":
        value = unicodedata.normalize("NFKC", value)
    if mode != "skip_casefold":
        value = value.lower() if mode == "lower_only" else value.casefold()
    if mode == "zero_width_after_nfkc":
        value = remove_zero_width(value)
    if mode != "skip_homoglyphs":
        mapping = settings["homoglyphs"]
        if mode == "hardcoded_map":
            mapping = {"\u043e": "o"}
        value = "".join(mapping.get(character, character) for character in value)
    return value


def inspection_candidates(value):
    if "normalization" not in policy or mode == "previous_stage":
        return [value]
    candidates = [normalize(value)]
    if mode == "skip_base64":
        return candidates
    encoded = value.casefold() if mode == "fold_before_decode" else value
    for _ in range(2 if mode == "recursive_decode" else 1):
        try:
            decoded = base64.b64decode(encoded, validate=True)
            if mode == "canonical_base64" and base64.b64encode(decoded).decode() != encoded:
                break
            decoded = decoded.decode("utf-8")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            break
        candidates.append(decoded if mode == "skip_decoded_normalization" else normalize(decoded))
        if mode != "recursive_decode":
            break
        encoded = decoded
    return candidates


def message_texts(message):
    """Return the strings in one message to inspect, or None if they can't be inspected."""
    content = message.get("content")
    if content is None:
        if mode == "null_crash" and "content" in message:
            raise TypeError("null content")
        return []
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return None
    if mode == "skip_parts":
        return []
    texts = []
    for part in content:
        if not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str):
            return None
        texts.append(part["text"])
    return texts


def inspect(body):
    """Return (role, text) pairs for every inspectable string, or None to fail closed."""
    try:
        messages = json.loads(body)["messages"]
        if not isinstance(messages, list):
            return None
        pairs = []
        for message in messages:
            texts = message_texts(message)
            if texts is None:
                return None
            pairs += [(message.get("role"), text) for text in texts]
        return pairs
    except (ValueError, KeyError, TypeError, AttributeError):
        if mode == "null_crash":
            raise
        return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        pairs = inspect(body)
        if pairs is None:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        contents = [text for _, text in pairs]
        candidates = [candidate for content in contents for candidate in inspection_candidates(content)]
        rules = policy.get("denylist", [])
        rule = next((entry["id"] for entry in rules if any(entry["term"] in candidate for candidate in candidates)), "")
        blocked = rule and policy.get("mode", "block") == "block"
        if blocked:
            value = {"error": {"message": "Blocked by firewall policy", "type": "firewall_block", "rule": rule}}
            data = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if "normalization" in policy and mode == "rewrite_request":
            value = json.loads(body)
            for message in value["messages"]:
                message["content"] = normalize(message["content"])
            body = json.dumps(value, separators=(",", ":")).encode()
        headers = {key: self.headers[key] for key in ("Authorization", "Content-Type") if key in self.headers}
        request = urllib.request.Request(args.origin.rstrip("/") + self.path, data=body, headers=headers, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        except urllib.error.URLError:
            self.send_response(502)
            self.end_headers()
            return
        with response:
            data = response.read()
            self.send_response(response.status)
            for key in ("Content-Type", "X-Request-Id"):
                if key in response.headers:
                    self.send_header(key, response.headers[key])
            if rule:
                self.send_header("X-Firewall-Match", rule)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def log_message(self, format, *values):
        pass


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
