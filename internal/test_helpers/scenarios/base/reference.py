"""Deterministic stage-1 reference and deliberately broken server scenarios."""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--origin", required=True)
parser.add_argument("--detector", required=True)
parser.add_argument("--policy", required=True)
args = parser.parse_args()
assert args.origin == "http://127.0.0.1:8081"
assert args.detector == "http://127.0.0.1:8082"
assert json.loads(Path(args.policy).read_text()) == {}
assert Path.cwd().resolve() == Path(args.policy).resolve().parent

mode = os.environ.get("STAGE1_SCENARIO", "pass_all")
if mode == "exit_early":
    print("startup failed", file=sys.stderr)
    sys.exit(7)
if mode == "never_listens":
    time.sleep(60)
if mode == "delayed_start":
    time.sleep(0.2)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if mode == "slow_response":
            time.sleep(0.6)
        if mode == "never_responds":
            time.sleep(60)
            return
        if mode == "wrong_status":
            self.send_response(404)
        elif mode == "redirect" and self.path == "/health":
            self.send_response(302)
            self.send_header("Location", "/ready")
        else:
            self.send_response(200)
        self.end_headers()
        if mode == "response_body":
            self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass


class Server(HTTPServer):
    allow_reuse_address = True


with Server(("127.0.0.1", 8080), Handler) as server:
    if mode == "one_request":
        server.handle_request()
    else:
        server.serve_forever()
