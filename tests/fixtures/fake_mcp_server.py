"""A tiny stdio MCP server for tests. Records every line it receives.

- initialize / tools/list / ping: canned answers
- tools/call "echo": returns the name and arguments it received, as JSON text
- tools/call "exit": exits with code 3; "big": one 5000-byte line; "partial": no newline
- tools/call "ask_client": first sends the client a request (roots/list)
Every received line is appended to the file named by FAKE_MCP_LOG.
"""

import json
import os
import sys

log_path = os.environ.get("FAKE_MCP_LOG")


def send(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if log_path:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(line)
    message = json.loads(line)
    method, request_id = message.get("method"), message.get("id")
    if method is None or request_id is None:
        continue  # a notification or a response
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"serverInfo": {"name": "fake"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{"name": "echo"}]}})
    elif method == "tools/call":
        name = message["params"]["name"]
        if name == "exit":
            sys.exit(3)
        if name == "big":  # one line longer than the proxy accepts in the tests
            sys.stdout.write("x" * 5000 + "\n")
            sys.stdout.flush()
            continue
        if name == "partial":  # last output has no newline, then exit
            sys.stdout.write('{"jsonrpc": "2.0", "id": 1, "result": {}}')
            sys.stdout.flush()
            sys.exit(0)
        if name == "ask_client":
            send({"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"})
        text = json.dumps({"name": name, "arguments": message["params"].get("arguments")})
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }
        )
    else:
        send({"jsonrpc": "2.0", "id": request_id, "result": {"method": method}})
