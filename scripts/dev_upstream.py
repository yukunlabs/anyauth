#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


ANYAUTH_HEADERS = [
    "X-AnyAuth-Authenticated",
    "X-AnyAuth-Actor-Type",
    "X-AnyAuth-Sub",
    "X-AnyAuth-Name",
    "X-AnyAuth-Email",
    "X-AnyAuth-Human-Sub",
    "X-AnyAuth-Human-Name",
    "X-AnyAuth-Human-Email",
    "X-AnyAuth-Agent-ID",
    "X-AnyAuth-Agent-Name",
    "X-AnyAuth-Delegation-ID",
    "X-AnyAuth-Token-ID",
    "X-AnyAuth-Task-ID",
    "X-AnyAuth-Task-Name",
    "X-AnyAuth-Scopes",
]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"path={self.path}\n".encode())
        for name in ANYAUTH_HEADERS:
            self.wfile.write(f"{name}: {self.headers.get(name)}\n".encode())

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description="Run a tiny local upstream app for AnyAuth protect mode.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), Handler)
    print(f"Dev upstream listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDev upstream stopped.")


if __name__ == "__main__":
    main()
