"""Warden in 30 seconds: a pretend agent tries things, Warden decides.

Run:  uv run python examples/demo.py

Everything runs in this process (no server to start). Each step also checks
Warden's answer, so the script exits with 1 if anything behaves unexpectedly.
"""

import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from warden.api import create_app
from warden.audit import SQLiteAuditLog

POLICY = Path(__file__).parent / "demo-policy.json"
COLORS = {"allow": "\033[32m", "deny": "\033[31m", "require_approval": "\033[33m"}
USE_COLOR = sys.stdout.isatty()


def paint(decision: str) -> str:
    text = decision.upper()
    return f"{COLORS[decision]}{text}\033[0m" if USE_COLOR else text


class Demo:
    def __init__(self, client: TestClient, admin_key: str) -> None:
        self.client = client
        self.admin = {"X-Warden-Admin-Key": admin_key}
        self.ok = True

    def ask(
        self,
        story: str,
        tool: str,
        expected: str,
        approval_id: str | None = None,
        **arguments: object,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"agent_id": "demo-agent", "tool": tool, "arguments": arguments}
        if approval_id:
            body["approval_id"] = approval_id
        result: dict[str, Any] = self.client.post("/v1/evaluate", json=body).json()
        mark = "✓" if result["decision"] == expected else "✗ UNEXPECTED"
        self.ok &= result["decision"] == expected
        print(f"  {story}")
        print(f"    → {paint(result['decision'])}  ({result['reason']})  {mark}\n")
        return result


def run() -> bool:
    admin_key = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory() as tmp:
        audit = SQLiteAuditLog(Path(tmp) / "audit.db")
        client = TestClient(create_app(POLICY, audit_log=audit, admin_key=admin_key))
        d = Demo(client, admin_key)

        print("\n1. Simple rules\n")
        d.ask("Read /data/report.txt", "read_file", "allow", path="/data/report.txt")
        d.ask(
            "Read /data/../etc/passwd (path trick)", "read_file", "deny", path="/data/../etc/passwd"
        )
        d.ask("Delete /data/report.txt", "delete_file", "deny", path="/data/report.txt")
        d.ask("Use a tool nobody mentioned (shell)", "run_shell", "deny", cmd="rm -rf /")

        print("2. Email: colleagues only\n")
        d.ask("Email bob@mycompany.com", "send_email", "allow", to="bob@mycompany.com")
        d.ask("Email Bob@MyCompany.COM (case trick)", "send_email", "allow", to="Bob@MyCompany.COM")
        d.ask("Email someone@gmail.com", "send_email", "deny", to="someone@gmail.com")
        d.ask(
            "Email a colleague but sneak in a bcc",
            "send_email",
            "deny",
            to="bob@mycompany.com",
            bcc="attacker@evil.com",
        )

        print("3. Invoices and human approval\n")
        d.ask("Invoice €200", "send_invoice", "allow", to="acme", amount=200)
        first = d.ask("Invoice €5,000", "send_invoice", "require_approval", to="acme", amount=5000)
        approval_id = first["approval_id"]

        pending = client.get("/v1/approvals", headers=d.admin).json()
        print(
            f"  Human checks the queue: {len(pending)} pending, "
            f"{pending[0]['tool']} {pending[0]['arguments']}"
        )
        client.post(f"/v1/approvals/{approval_id}/approve", headers=d.admin)
        print("  Human approves it.\n")

        d.ask(
            "Agent changes the amount to €50,000 and reuses the approval",
            "send_invoice",
            "deny",
            approval_id=approval_id,
            to="acme",
            amount=50000,
        )
        d.ask(
            "Agent sends the exact approved invoice",
            "send_invoice",
            "allow",
            approval_id=approval_id,
            to="acme",
            amount=5000,
        )
        d.ask(
            "Agent tries to reuse the approval (replay)",
            "send_invoice",
            "deny",
            approval_id=approval_id,
            to="acme",
            amount=5000,
        )

        print("4. Audit log (newest first, arguments never stored)\n")
        for entry in audit.recent(limit=5):
            print(
                f"  {entry.timestamp[11:19]}  {entry.tool:<13} {entry.decision.value:<17}"
                f" {entry.reason}"
            )
        for event in audit.recent_events(limit=1):
            print(f"  {event.timestamp[11:19]}  event: {event.reason}")

    print("\nAll steps behaved as expected." if d.ok else "\nSomething was UNEXPECTED.")
    return d.ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
