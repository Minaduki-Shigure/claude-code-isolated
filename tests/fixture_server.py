#!/usr/bin/env python3
"""Offline upstream HTTP proxy, DoH service, and streaming Messages API fixture.

This server NEVER opens an outgoing connection. The integration harness puts it
on an internal Docker network. Addresses in CONNECT are recorded, then served
locally; a production policy exception is neither needed nor permitted.
"""

import argparse
import http.server
import ipaddress
import json
import os
import ssl
import threading
import time
import urllib.parse


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
REPLY = "ISOLATION_MOCK_SUCCESS"
TOOL_MARKER = "/workspace/model-tool-result.txt"
_audit_lock = threading.Lock()


def audit(kind, **fields):
    row = json.dumps({"kind": kind, **fields}, sort_keys=True)
    with _audit_lock:
        with open(os.environ["FIXTURE_AUDIT"], "a", encoding="utf-8") as stream:
            stream.write(row + "\n")


def dns_answer(name, record_type):
    name = name.lower().rstrip(".")
    answer = []
    if name == "cname-official.example.com":
        answer.append({"name": name, "type": 5, "TTL": 30, "data": "api.anthropic.com."})
    addresses = {
        "private.example.com": ["127.0.0.1"],
        "metadata.example.com": ["169.254.169.254"],
        "mixed.example.com": [PUBLIC_V4, "10.0.0.1"],
        "official-ip.example.com": ["160.79.104.7"],
        "ipv6-official.example.com": ["2607:6bc0::1"],
        "ipv6-private.example.com": ["::1"],
    }.get(name, [PUBLIC_V4, PUBLIC_V6])
    for address in addresses:
        version = ipaddress.ip_address(address).version
        if (record_type == 1 and version == 4) or (record_type == 28 and version == 6):
            answer.append({"name": name, "type": record_type, "TTL": 30, "data": address})
    return {
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": False,
        "Question": [{"name": name, "type": record_type}],
        "Answer": answer,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass  # Never log request headers, API keys, query strings, or bodies.

    def do_CONNECT(self):
        audit("connect", authority=self.path)
        try:
            authority = urllib.parse.urlsplit("//" + self.path)
            address = ipaddress.ip_address(authority.hostname)
            port = authority.port
            if port not in (80, 443):
                raise ValueError("port not allowed")
        except ValueError:
            self.respond(400, b"fixture requires a numeric CONNECT target")
            return
        if str(address) not in ("1.1.1.1", PUBLIC_V4, PUBLIC_V6):
            self.respond(502, b"unexpected upstream destination")
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        if port == 443:
            try:
                self.connection = self.server.tls_context.wrap_socket(
                    self.connection, server_side=True
                )
            except ssl.SSLError:
                self.close_connection = True
                return
            self.rfile = self.connection.makefile("rb", self.rbufsize)
            self.wfile = self.connection.makefile("wb", self.wbufsize)
        self.close_connection = False

    def respond(self, status, data, content_type="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def json_response(self, obj):
        self.respond(200, json.dumps(obj).encode(), "application/json")

    def location(self):
        parsed = urllib.parse.urlsplit(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":")[0]
        return host.lower().rstrip("."), parsed

    def do_GET(self):
        host, parsed = self.location()
        audit("request", method="GET", host=host, path=parsed.path)
        if parsed.path == "/__health":
            self.respond(200, b"ready")
        elif host == "cloudflare-dns.com" and parsed.path == "/dns-query":
            query = urllib.parse.parse_qs(parsed.query)
            name = query.get("name", [""])[0]
            typ = query.get("type", ["A"])[0]
            record_type = {"A": 1, "AAAA": 28}.get(typ, int(typ) if typ.isdigit() else 1)
            audit("dns", name=name.lower().rstrip("."), record_type=record_type)
            self.json_response(dns_answer(name, record_type))
        elif parsed.path == "/redirect-official":
            self.respond(302, b"", extra={"Location": "https://api.anthropic.com/"})
        elif parsed.path == "/v1/models":
            self.json_response({"data": [{"id": "claude-sonnet-4-5-20250929", "type": "model",
                                         "display_name": "Offline fixture model",
                                         "created_at": "2025-09-29T00:00:00Z"}],
                                "has_more": False, "first_id": "claude-sonnet-4-5-20250929",
                                "last_id": "claude-sonnet-4-5-20250929"})
        else:
            self.respond(200, b"OFFLINE_ALLOWED_TARGET\n")

    def do_POST(self):
        host, parsed = self.location()
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4 * 1024 * 1024:
            self.respond(413, b"request too large")
            return
        payload = json.loads(self.rfile.read(length) or b"{}")
        audit("request", method="POST", host=host, path=parsed.path,
              streaming=bool(payload.get("stream")))
        if parsed.path == "/v1/messages/count_tokens":
            self.json_response({"input_tokens": 64})
            return
        if parsed.path != "/v1/messages":
            self.respond(404, b"unsupported fixture endpoint")
            return
        has_tool_result = any(
            item.get("type") == "tool_result"
            for message in payload.get("messages", [])
            if isinstance(message.get("content"), list)
            for item in message["content"]
        )
        can_use_bash = any(tool.get("name") == "Bash" for tool in payload.get("tools", []))
        tool_turn = can_use_bash and not has_tool_result
        content = (
            [{"type": "tool_use", "id": "toolu_offline_test", "name": "Bash",
              "input": {"command": f"printf '%s\\n' '{REPLY}' > {TOOL_MARKER}",
                        "description": "Write the offline integration test marker"}}]
            if tool_turn else [{"type": "text", "text": REPLY}]
        )
        audit("model_turn", tool_turn=tool_turn, has_tool_result=has_tool_result)
        message = {
            "id": "msg_offline_fixture",
            "type": "message",
            "role": "assistant",
            "model": payload.get("model", "claude-sonnet-4-5-20250929"),
            "content": content,
            "stop_reason": "tool_use" if tool_turn else "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 64, "output_tokens": 12,
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
        }
        if not payload.get("stream"):
            self.json_response(message)
            return
        start = {**message, "content": [], "stop_reason": None,
                 "usage": {**message["usage"], "output_tokens": 1}}
        events = [{"type": "message_start", "message": start}]
        if tool_turn:
            block = {**content[0], "input": {}}
            events += [
                {"type": "content_block_start", "index": 0, "content_block": block},
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "input_json_delta",
                           "partial_json": json.dumps(content[0]["input"])}},
            ]
        else:
            events.append({"type": "content_block_start", "index": 0,
                           "content_block": {"type": "text", "text": ""}})
            for chunk in ("ISOLATION_", "MOCK_", "SUCCESS"):
                events.append({"type": "content_block_delta", "index": 0,
                               "delta": {"type": "text_delta", "text": chunk}})
        events += [
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": message["stop_reason"],
                                               "stop_sequence": None},
             "usage": {"output_tokens": 12}},
            {"type": "message_stop"},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for event in events:
            self.wfile.write(
                f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
            )
            self.wfile.flush()
            time.sleep(0.01)
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--blocked-port", type=int, default=18082)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--audit", required=True)
    args = parser.parse_args()
    os.environ["FIXTURE_AUDIT"] = args.audit
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.set_servername_callback(lambda _sock, name, _ctx: audit("tls", sni=name))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.daemon_threads = True
    server.tls_context = context
    # A live second port proves that the gateway firewall rejects traffic,
    # rather than mistaking "nothing is listening" for successful isolation.
    blocked = http.server.ThreadingHTTPServer(("0.0.0.0", args.blocked_port), Handler)
    blocked.daemon_threads = True
    blocked.tls_context = context
    threading.Thread(target=blocked.serve_forever, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
