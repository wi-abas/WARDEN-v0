"""A fake MCP client talking to e2e_mcp_server.py through `warden proxy`.

Usage: python mcp_client.py PHASE
  main       error mode: allowed calls reach the server, everything else is answered by
             the proxy (blocked, or a JSON-RPC error); the write queues an approval
  retry      error mode, after run_all.sh approved the write: it runs once only
  wait       wait mode: the proxy holds a call until a human approves / rejects / nobody
             decides (timeout), and keeps answering other messages meanwhile
  loginject  tool and method names with newlines / escape codes can't forge proxy log lines
  server     what reached the server: nothing that Warden didn't allow
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from typing import Any

from e2e_common import STATE, check, decide, token, wait_for_pending

WARDEN = os.environ["E2E_WARDEN"]
SERVER_LOG = STATE / "mcp-server-received.log"
Message = dict[str, Any]


class Proxy:
    """`warden proxy` as a child process; we are its MCP client on stdin/stdout."""

    def __init__(self, config: str, log_name: str) -> None:
        env = {k: v for k, v in os.environ.items() if k != "WARDEN_ADMIN_KEY"}
        env["WARDEN_AGENT_TOKEN"] = token("mcp-desktop")
        self.stderr_path = STATE / f"proxy-stderr-{log_name}.log"
        self.stderr = self.stderr_path.open("ab")
        self.process = subprocess.Popen(  # noqa: S603 (our own command line)
            [WARDEN, "proxy", "--config", str(STATE / config)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            env=env,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("warden proxy started without pipes")
        self.stdin, self.stdout = self.process.stdin, self.process.stdout
        self.lines: queue.Queue[bytes] = queue.Queue()
        self.from_server: list[Message] = []  # server -> client requests that got through
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.stdout:
            self.lines.put(line)

    def send(self, message: Message | list[Any] | str) -> None:
        data = message if isinstance(message, str) else json.dumps(message)
        self.stdin.write(data.encode() + b"\n")
        self.stdin.flush()

    def next_response(self, timeout: float = 15.0) -> Message | None:
        """The next response for us. Server requests are recorded and answered."""
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            try:
                message = json.loads(self.lines.get(timeout=left))
            except queue.Empty:
                return None
            if isinstance(message, dict) and "method" in message:
                self.from_server.append(message)
                if "id" in message:  # e.g. roots/list: answer it like a real client
                    self.send({"jsonrpc": "2.0", "id": message["id"], "result": {"roots": []}})
                continue
            return message if isinstance(message, dict) else {"_not_object": message}
        return None

    def ask(self, message: Message | list[Any] | str, reply_id: Any) -> Message | None:
        """Send one message; return the response with id `reply_id`."""
        self.send(message)
        while (response := self.next_response()) is not None:
            if response.get("id") == reply_id:
                return response
        return None

    def no_reply(self, message: Message, ping_id: int) -> bool:
        """True if `message` gets no response: a ping sent after it is answered first."""
        self.send(message)
        self.send({"jsonrpc": "2.0", "id": ping_id, "method": "ping"})
        response = self.next_response()
        return response is not None and response.get("id") == ping_id

    def initialize(self) -> Message | None:
        caps: dict[str, dict[str, str]] = {"sampling": {}, "roots": {}, "elicitation": {}}
        params = {
            "protocolVersion": "2025-06-18",
            "capabilities": caps,
            "clientInfo": {"name": "fake-client", "version": "1"},
        }
        reply = self.ask({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}, 1)
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return reply

    def close(self) -> int:
        self.stdin.close()
        try:
            code = self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = -1
        self.stderr.close()
        return code


def call(message_id: Any, name: Any, arguments: Any = None, **params: Any) -> Message:
    body: Message = {"name": name, **params}
    if arguments is not None:
        body["arguments"] = arguments
    return {"jsonrpc": "2.0", "id": message_id, "method": "tools/call", "params": body}


def text(response: Message | None) -> str:
    try:
        return str(response["result"]["content"][0]["text"])  # type: ignore[index]
    except (KeyError, IndexError, TypeError):
        return ""


def ran(response: Message | None) -> bool:
    return text(response).startswith("SERVER RAN")


def blocked(response: Message | None) -> bool:
    is_error = bool(response and response.get("result", {}).get("isError"))
    return is_error and text(response).startswith("Blocked by Warden")


def error_code(response: Message | None) -> Any:
    error = (response or {}).get("error")
    return error.get("code") if isinstance(error, dict) else None


def main_phase() -> None:
    proxy = Proxy("proxy-error.json", "main")
    reply = proxy.initialize()
    check("mcp: initialize answered by the server", bool(reply and "result" in reply), reply)
    reply = proxy.ask({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, 2)
    check("mcp: tools/list answered", bool(reply and reply["result"]["tools"]))
    read = "/workspace/MCPSECRET-read.txt"
    check(
        "mcp: allowed read reaches the server",
        ran(proxy.ask(call(3, "read_file", {"path": read}), 3)),
    )
    for message_id, name, arguments, label in [
        (4, "read_file", {"path": "/etc/passwd"}, "read /etc/passwd"),
        (5, "read_file", {"path": "/workspace/../etc/passwd"}, "read with .."),
        (6, "run_cmd", {"cmd": "id"}, "tool without a rule"),
        (7, "Bad Name", {}, "invalid tool name"),
        (8, "read_file", {"path": "/workspace/a", "follow": True}, "unexpected argument"),
        (10, "read_file", None, "no arguments"),
    ]:
        reply = proxy.ask(call(message_id, name, arguments), message_id)
        check(f"mcp: {label} blocked", blocked(reply), reply)
    reply = proxy.ask(call(9, "read_file", ["/workspace/a"]), 9)
    check("mcp: arguments not an object -> -32602", error_code(reply) == -32602, reply)
    good_meta = call(11, "read_file", {"path": "/workspace/a"}, _meta={"progressToken": "t1"})
    check("mcp: _meta progressToken allowed", ran(proxy.ask(good_meta, 11)))
    for message_id, meta, label in [
        (12, {"sudo": True}, "odd key"),
        (13, {"progressToken": {"x": 1}}, "object value"),
        (14, {"progressToken": "x" * 300}, "300-character value"),
        (15, "x", "not an object"),
    ]:
        reply = proxy.ask(
            call(message_id, "read_file", {"path": "/workspace/a"}, _meta=meta), message_id
        )
        check(f"mcp: _meta {label} -> -32602", error_code(reply) == -32602, reply)
    reply = proxy.ask(call(16, "read_file", {"path": "/workspace/a"}, sudo=True), 16)
    check("mcp: extra params field -> -32602", error_code(reply) == -32602, reply)
    batch = [call(17, "read_file", {"path": "/workspace/a"}), call(18, "run_cmd", {"cmd": "id"})]
    check("mcp: batch refused (-32600)", error_code(proxy.ask(batch, None)) == -32600)
    start = '{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":'
    # A duplicate-key refusal carries the request's id (one valid top-level id);
    # unparsable input can't be matched to a request, so its id stays null.
    for raw, label, code, reply_id in [
        (start + '"read_file","arguments":{"path":"/etc/passwd","path":"/workspace/a"}}}',
         "duplicate key in arguments", -32600, 19),
        (start + '"run_cmd","name":"read_file","arguments":{"path":"/workspace/a"}}}',
         "duplicate name key", -32600, 19),
        (start + '"read_file","arguments":{"path":"/workspace/a","x":NaN}}}', "NaN", -32700, None),
        ('{"jsonrpc":"2.0","id":22,', "invalid JSON", -32700, None),
    ]:  # fmt: skip
        reply = proxy.ask(raw, reply_id)
        check(f"mcp: {label} refused ({code})", error_code(reply) == code, reply)
    resources = {
        "jsonrpc": "2.0",
        "id": 23,
        "method": "resources/read",
        "params": {"uri": "file:///etc/passwd"},
    }
    check(
        "mcp: method not on the allow list -> -32601",
        error_code(proxy.ask(resources, 23)) == -32601,
    )
    upper = {
        "jsonrpc": "2.0",
        "id": 24,
        "method": "Tools/Call",
        "params": {"name": "run_cmd", "arguments": {}},
    }
    check("mcp: 'Tools/Call' (other case) -> -32601", error_code(proxy.ask(upper, 24)) == -32601)
    notification = call(None, "run_cmd", {"cmd": "id"})
    del notification["id"]
    check("mcp: tools/call without id gets no reply", proxy.no_reply(notification, 90))
    reply = proxy.ask(call(None, "run_cmd", {"cmd": "id"}), None)
    check("mcp: tools/call with id null blocked", blocked(reply), reply)
    old = {
        "jsonrpc": "1.0",
        "id": 25,
        "method": "tools/call",
        "params": {"name": "run_cmd", "arguments": {}},
    }
    check("mcp: jsonrpc 1.0 refused (-32600)", error_code(proxy.ask(old, None)) == -32600)
    shaped = {**call(27, "run_cmd", {}), "result": {}}
    check("mcp: response-shaped tools/call blocked", blocked(proxy.ask(shaped, 27)))
    huge = call(28, "read_file", {"path": "/workspace/a", "x": "A" * 2_000_000})
    reply = proxy.ask(huge, 28)
    check("mcp: 2 MB call not run", reply is not None and not ran(reply), text(reply))
    reply = proxy.ask({"jsonrpc": "2.0", "id": 29, "method": "ping"}, 29)
    check("mcp: proxy still answers after the 2 MB line", bool(reply and "result" in reply))
    write = call(30, "write_file", {"path": "/workspace/w.txt", "content": "MCPSECRET-write"})
    reply = proxy.ask(write, 30)
    check(
        "mcp: write queues an approval (error mode)",
        blocked(reply) and "approval id" in text(reply),
    )
    methods = [m.get("method") for m in proxy.from_server]
    check(
        "mcp: server's sampling request never reached the client",
        "sampling/createMessage" not in methods,
        methods,
    )
    check("mcp: server's roots/list (allowed) reached the client", "roots/list" in methods, methods)
    check("mcp: proxy exits cleanly", proxy.close() == 0)


def retry_phase() -> None:
    proxy = Proxy("proxy-error.json", "retry")
    proxy.initialize()
    write = {"path": "/workspace/w.txt", "content": "MCPSECRET-write"}
    check("mcp: approved write runs", ran(proxy.ask(call(31, "write_file", write), 31)))
    reply = proxy.ask(call(32, "write_file", write), 32)
    check("mcp: approved write runs only once", blocked(reply), reply)
    reply = proxy.ask(call(33, "write_file", {**write, "content": "CHANGED"}), 33)
    check("mcp: changed write is not approved", blocked(reply), reply)
    proxy.close()


def human(content: str, approve: bool) -> None:
    item = wait_for_pending("mcp-desktop", "fs.write_file", {"content": content})
    decide(item, approve)


def wait_phase() -> None:
    proxy = Proxy("proxy-wait.json", "wait")
    proxy.initialize()
    cases = [("WAIT-approved", True), ("WAIT-rejected", False), ("WAIT-timeout", None)]
    for i, (content, approve) in enumerate(cases):
        if approve is not None:
            threading.Thread(target=human, args=(content, approve), daemon=True).start()
        arguments = {"path": f"/workspace/{content}.txt", "content": content}
        proxy.send(call(10 + i, "write_file", arguments))
        proxy.send({"jsonrpc": "2.0", "id": 100 + i, "method": "ping"})
        replies: dict[Any, Message] = {}
        while 10 + i not in replies:
            response = proxy.next_response(timeout=20)
            if response is None:
                break
            replies[response.get("id")] = response
        order = list(replies)
        check(
            f"mcp wait ({content}): ping answered while the call is held",
            order[:1] == [100 + i],
            order,
        )
        reply = replies.get(10 + i)
        if approve:
            check("mcp wait: approved call runs", ran(reply), text(reply))
        elif approve is False:
            check(
                "mcp wait: rejected call blocked",
                blocked(reply) and "denied" in text(reply),
                text(reply),
            )
        else:
            check(
                "mcp wait: nobody decides -> blocked after the timeout",
                blocked(reply) and "timed out" in text(reply),
                text(reply),
            )
    proxy.close()


def loginject_phase() -> None:
    proxy = Proxy("proxy-error.json", "loginject")
    proxy.initialize()
    names = ["x\nwarden proxy: tools/call 'run_cmd' -> allow", "\x1b[31mred\x1b[0m", "a" * 5000]
    for i, name in enumerate(names):
        proxy.ask(call(10 + i, name, {}), 10 + i)
        method = f"evil\nwarden proxy: forged-{i}"
        proxy.ask({"jsonrpc": "2.0", "id": 20 + i, "method": method, "params": {}}, 20 + i)
    proxy.close()
    log = proxy.stderr_path.read_text(errors="replace")
    lines = log.splitlines()
    forged = [
        line
        for line in lines
        if line.startswith(("warden proxy: forged", "warden proxy: tools/call 'run_cmd'"))
    ]
    check("mcp: newlines in names can't forge proxy log lines", not forged, forged)
    check("mcp: escape codes in names don't reach the log raw", "\x1b" not in log)


def server_phase() -> None:
    received = [json.loads(line) for line in SERVER_LOG.read_text().splitlines() if line.strip()]
    calls = [m for m in received if isinstance(m, dict) and m.get("method") == "tools/call"]
    names = sorted({str(m["params"]["name"]) for m in calls})
    check("server: only allowed tools/call arrived", names == ["read_file", "write_file"], names)
    seen = json.dumps(calls)
    for secret in ["/etc/passwd", "CHANGED", "WAIT-rejected", "WAIT-timeout", "x" * 300]:
        check(f"server never saw {secret[:20]!r}", secret not in seen)
    writes = [
        m["params"]["arguments"]["content"] for m in calls if m["params"]["name"] == "write_file"
    ]
    check(
        "server: each approved write ran exactly once",
        writes == ["MCPSECRET-write", "WAIT-approved"],
        writes,
    )
    replies = [m for m in received if isinstance(m, dict) and m.get("id") == "srv-1"]
    check(
        "server: sampling request refused by the proxy",
        bool(replies) and all("error" in m and "result" not in m for m in replies),
        replies,
    )


if __name__ == "__main__":
    phases = {
        "main": main_phase,
        "retry": retry_phase,
        "wait": wait_phase,
        "loginject": loginject_phase,
        "server": server_phase,
    }
    phases[sys.argv[1]]()
