#!/usr/bin/env python3
"""
server.py - Line-based TCP server for the PUF device (step 4, transport only).

Every message is one line of text; binary fields travel as hex.
For now: print every line, answer HELLO with WELCOME.

Usage:
    python3 host/server.py              # listens on port 5555
    python3 host/server.py --port 6000
"""

import argparse
import socketserver


class Device(socketserver.StreamRequestHandler):
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[{peer}] connected")
        for raw in self.rfile:                      # one line at a time
            line = raw.decode(errors="replace").rstrip("\r\n")
            print(f"[{peer}] <- {line}")
            if line.startswith("HELLO "):
                self.send("WELCOME")
        print(f"[{peer}] closed")

    def send(self, line):
        self.wfile.write((line + "\n").encode())
        print(f"[{self.client_address[0]}:{self.client_address[1]}] -> {line}")


class Server(socketserver.TCPServer):
    allow_reuse_address = True                      # quick restarts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5555)
    args = ap.parse_args()
    with Server(("0.0.0.0", args.port), Device) as srv:
        print(f"listening on port {args.port}, Ctrl+C to stop")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print()


if __name__ == "__main__":
    main()
