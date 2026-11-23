"""A fake stdio MCP server, started by `warden proxy`.

Usage: python e2e_mcp_server.py RECEIVED_LOG
Appends every line it receives to RECEIVED_LOG, so the scenario can prove what reached
it (and what didn't). Tools: read_file, write_file, run_cmd, "Bad Name". Right after
initialize it sends the client a sampling/createMessage request (the proxy must refuse
it) and a roots/list request (allowed by the proxy config).
"""

import json
import sys
from typing import Any

TOOLS = [
    {"name": name, "description": name, "inputSchema": {"type": "object"}}
    for name in ["read_file", "write_file", "run_cmd", "Bad Name"]
]


def send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main(log_path: str) -> None:
    for line in sys.stdin:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(line)
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict) or "method" not in message:
            continue
        message_id, method = message.get("id"), message["method"]
        if method == "initialize":
            info = {"name": "fake", "version": "1"}
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
            send({"jsonrpc": "2.0", "id": message_id, "result": {**result, "serverInfo": info}})
            sampling: dict[str, list[str]] = {"messages": []}
            send(
                {
                    "jsonrpc": "2.0",
                    "id": "srv-1",
                    "method": "sampling/createMessage",
                    "params": sampling,
                }
            )
            send({"jsonrpc": "2.0", "id": "srv-2", "method": "roots/list"})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": message_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = message.get("params", {})
            text = f"SERVER RAN {params.get('name')} {json.dumps(params.get('arguments'))}"
            content = [{"type": "text", "text": text}]
            send({"jsonrpc": "2.0", "id": message_id, "result": {"content": content}})
        elif message_id is not None:
            send({"jsonrpc": "2.0", "id": message_id, "result": {}})


if __name__ == "__main__":
    main(sys.argv[1])
