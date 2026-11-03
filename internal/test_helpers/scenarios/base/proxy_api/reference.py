"""Offline proxy reference and one-behavior regressions for stage 2."""

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--origin", required=True)
parser.add_argument("--detector", required=True)
parser.add_argument("--policy", required=True)
args = parser.parse_args()
mode = os.environ.get("PROXY_SCENARIO", "pass_all")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()

    def do_POST(self):
        if mode == "hang_request":
            time.sleep(60)
            return
        if self.path != "/v1/chat/completions" or mode == "stage1_only":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if mode == "change_request":
            body = b"{}"
        headers = {key: self.headers[key] for key in ("Authorization", "Content-Type") if key in self.headers}
        if mode == "wrong_host":
            headers["Host"] = self.headers["Host"]
        if mode == "drop_authorization":
            headers.pop("Authorization", None)
        request = urllib.request.Request(args.origin.rstrip("/") + self.path, data=body, headers=headers, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            if mode == "convert_origin_error":
                self.send_error(502)
                return
            response = error
        except urllib.error.URLError:
            self.send_response(500 if mode == "wrong_gateway" else 502)
            self.end_headers()
            return
        with response:
            data = response.read()
            if mode == "change_response" and b"course_marker" in data:
                value = json.loads(data)
                value.pop("course_marker")
                data = json.dumps(value, separators=(",", ":")).encode()
            if mode == "extra_response":
                data += b"\nextra"
            self.send_response(response.status)
            for key in ("Content-Type", "X-Request-Id"):
                if key == "X-Request-Id" and mode == "drop_response_header":
                    continue
                if key in response.headers:
                    self.send_header(key, response.headers[key])
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def log_message(self, format, *values):
        pass


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
