#!/usr/bin/env python3
"""Canned NDJSON MCP server used as the upstream child by proxy e2e tests.

Behavior (deterministic, dependency-free):
- Reads newline-delimited JSON-RPC from stdin, one message per line.
- APPENDS every received (non-blank) line to $MOCK_LOG before anything else,
  so tests can prove exactly which lines reached the upstream (and, crucially,
  which never did).
- Answers:
    initialize  -> fixed protocolVersion/capabilities/serverInfo result
    tools/list  -> {"tools": <payload>} where payload is the JSON array in
                   $MOCK_TOOLS_FILE when set, else a built-in one-tool default
    tools/call  -> echoes the call arguments back inside a text content block
                   ("mock-echo:{...json args...}"), isError false
    other       -> empty result under the request id
- Notifications (no id) are logged but never answered.
- Exits cleanly (0) when stdin closes.

Environment:
  MOCK_LOG        side file receiving every received line (append mode)
  MOCK_TOOLS_FILE optional JSON file with the tools/list payload
"""

import json
import os
import sys

DEFAULT_TOOLS = [
    {
        "name": "echo",
        "description": "Echoes its input back",
        "inputSchema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
        },
    }
]


def tools_payload():
    path = os.environ.get("MOCK_TOOLS_FILE")
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_TOOLS


def send(msg):
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log(line):
    path = os.environ.get("MOCK_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def main():
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        log(line)
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "id" not in msg:
            continue
        rid = msg["id"]
        method = msg.get("method")
        if method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock-mcp", "version": "0.0.1"},
                    },
                }
            )
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid, "result": {"tools": tools_payload()}})
        elif method == "tools/call":
            args = msg.get("params", {}).get("arguments", {})
            send(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": "mock-echo:"
                                + json.dumps(args, sort_keys=True, separators=(",", ":")),
                            }
                        ],
                        "isError": False,
                    },
                }
            )
        else:
            send({"jsonrpc": "2.0", "id": rid, "result": {}})


if __name__ == "__main__":
    main()
