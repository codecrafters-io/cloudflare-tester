"""Offline policy reference and single-behavior regressions for stage 3."""

import argparse
import json
import os
import time
import threading
from pathlib import Path
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--origin", required=True)
parser.add_argument("--detector", required=True)
parser.add_argument("--policy", required=True)
args = parser.parse_args()
mode = os.environ.get("POLICY_SCENARIO", "pass_all")
policy = json.loads(Path(args.policy).read_text())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        messages = json.loads(body).get("messages", [])
        contents = [message.get("content", "") for message in messages]
        if mode == "user_only":
            contents = [message.get("content", "") for message in messages if message.get("role") == "user"]
        if mode == "scan_envelope":
            contents = [body.decode()]
        if mode == "join_messages":
            contents = ["".join(contents)]
        if mode == "lower_case":
            contents = [content.lower() for content in contents]
        rules = policy.get("denylist", [])
        if mode == "message_order":
            rule = next((entry["id"] for content in contents for entry in rules if entry["term"] in content), "")
        else:
            rule = next((entry["id"] for entry in rules if any(entry["term"] in content for content in contents)), "")
        if mode == "previous_stage":
            rule = ""
        blocked = rule and (policy.get("mode", "block") == "block" or mode == "log_blocks")
        if blocked:
            headers = {key: self.headers[key] for key in ("Authorization", "Content-Type") if key in self.headers}
            def leak():
                if mode == "leak_after_block":
                    time.sleep(0.05)
                request = urllib.request.Request(args.origin.rstrip("/") + self.path, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(request, timeout=2) as response:
                    response.read()
            if mode == "leak_before_block":
                leak()
            if mode == "leak_after_block":
                threading.Thread(target=leak, daemon=True).start()
            value = {"error": {"message": "Blocked by firewall policy", "type": "firewall_block", "rule": "wrong" if mode == "wrong_rule" else rule}}
            data = b"not JSON" if mode == "invalid_error" else json.dumps(value, separators=(",", ":")).encode()
            self.send_response(401 if mode == "wrong_status" else 403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if mode == "rewrite_request" and rule:
            body = json.dumps(json.loads(body), indent=2).encode()
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
            if mode == "rewrite_response" and rule:
                data += b"extra"
            self.send_response(response.status)
            for key in ("Content-Type", "X-Request-Id"):
                if key in response.headers:
                    self.send_header(key, response.headers[key])
            match = rule
            if mode == "no_match_header":
                match = ""
            if mode == "sticky_header":
                match = rule or Handler.last_match
                Handler.last_match = match
            if match:
                self.send_header("X-Firewall-Match", match)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    last_match = ""

    def log_message(self, format, *values):
        pass


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
