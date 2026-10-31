#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ægis — Mission Control Launch Pad Server  (port 9000)
=======================================================
Serves the static launchpad/index.html on port 9000.
"""
import sys, os, argparse
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

_HERE = Path(__file__).resolve().parent / "launchpad"

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(_HERE), **kw)
    def log_message(self, fmt, *args):
        pass  # silent — uncomment below line to enable access log
        # print(f"[{self.log_date_time_string()}] {fmt % args}")
    def end_headers(self):
        # CORS — allows JS fetch() to reach all the suite ports
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store")
        super().end_headers()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ægis Mission Control — Launch Pad Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=9000, type=int)
    args = parser.parse_args()

    print(f"""
====================================================================
   Expedite Strike — Mission Control Launch Pad
====================================================================
   URL      ->  http://{args.host}:{args.port}/
   Serving  ->  {str(_HERE):<50}
   Apps     ->  10 services (ports 8050, 9012-9020)
====================================================================
""")

    server = HTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Launch Pad] Shutting down.")
        server.server_close()
