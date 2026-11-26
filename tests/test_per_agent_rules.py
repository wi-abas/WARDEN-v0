"""Per-agent rules: a rule with "agents" applies only to those agents (exact match).

See docs/design/per-agent-rules.md. Security behaviour tested here:
- a per-agent allow never reaches another agent (or a differently-cased name),
- most restrictive still wins: a per-agent allow never beats a global deny,
- bad "agents" lists are refused (empty, null, duplicates, bad ids, too many),
- the server refuses to start without agent tokens, or with unknown agent names,
- `warden check` warns about unknown names (W014) and case look-alikes (W015).
"""

import json
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY
from pydantic import ValidationError

import warden.api
from warden import cli
from warden.agents import AgentEntry, AgentRegistry, add_agent, hash_token, new_token
from warden.api import StartupError, create_app
from warden.approvals import ApprovalStore
from warden.audit import SQLiteAuditLog
from warden.check import check_policy
from warden.engine import evaluate
from warden.identity import proof_key
from warden.models import ActionRequest, Decision, Rule
from warden.policy import Policy, load_policy, parse_policy
from warden.policy_tests import run as run_policy_tests
from warden.settings import Settings


def rule(id: str, effect: str, agents: object = ..., **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"id": id, "tool": "pay", "effect": effect, **extra}
    if agents is not ...:
        out["agents"] = agents
    return out


def policy(*rules: dict[str, Any], **extra: Any) -> Policy:
    return parse_policy(json.dumps({"rules": list(rules), **extra}))


def decide(p: Policy, agent: str, **arguments: Any) -> tuple[Decision, str | None]:
    request = ActionRequest(tool="pay", agent_id=agent, arguments=arguments)
    result = evaluate(request, p.rules, p.tools)
    return result.decision, result.matched_rule


def write(tmp_path: Path, name: str, data: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data))
    path.chmod(0o644)
    return path


# --- The rule shape ---------------------------------------------------------------------


def test_no_agents_key_means_every_agent() -> None:
    p = policy(rule("all", "allow"))
    assert p.rules[0].agents is None
    assert decide(p, "anyone") == (Decision.ALLOW, "all")


@pytest.mark.parametrize(
    ("agents", "why"),
    [
        ([], "at least 1"),  # a rule that would never apply
        (None, "leave it out"),  # "nobody" or "everybody"? Refused.
        (["a", "a"], "twice"),
        (["bad id"], "pattern"),
        (["a" * 129], "pattern"),
        ([""], "pattern"),
        ("billing-agent", "valid array"),  # a string is not a list of one
        ([1], "string"),
        ([f"a{i}" for i in range(101)], "at most 100"),
    ],
)
def test_bad_agent_lists_are_refused(agents: object, why: str) -> None:
    with pytest.raises(ValidationError, match=why):
        policy(rule("r", "allow", agents))


def test_load_policy_with_a_bad_agent_list_denies_everything(tmp_path: Path) -> None:
    path = write(tmp_path, "p.json", {"rules": [rule("r", "allow", [])]})
    assert load_policy(path).rules == ()


def test_applies_to_is_exact() -> None:
    r = Rule.model_validate_json(json.dumps(rule("r", "allow", ["billing-agent"])))
    assert r.applies_to("billing-agent")
    for other in ["Billing-agent", "billing-agent ", "billing", "billing-agent2", "billing-*"]:
        assert not r.applies_to(other)


def test_agents_appear_in_the_schema() -> None:
    schema = Policy.model_json_schema(by_alias=True)["$defs"]["Rule"]["properties"]["agents"]
    assert schema["type"] == "array" and schema["minItems"] == 1 and schema["uniqueItems"]


# --- The engine -------------------------------------------------------------------------


def test_per_agent_allow_applies_only_to_its_agents() -> None:
    p = policy(rule("billing-pays", "allow", ["billing-agent", "ops"]))
    assert decide(p, "billing-agent") == (Decision.ALLOW, "billing-pays")
    assert decide(p, "ops") == (Decision.ALLOW, "billing-pays")
    assert decide(p, "research-agent") == (Decision.DENY, None)


def test_matching_is_case_sensitive_and_never_a_prefix() -> None:
    p = policy(rule("billing-pays", "allow", ["billing-agent"]))
    for other in ["Billing-agent", "BILLING-AGENT", "billing", "billing-agent-2"]:
        assert decide(p, other) == (Decision.DENY, None)


def test_per_agent_allow_never_beats_a_global_deny() -> None:
    p = policy(rule("billing-pays", "allow", ["billing-agent"]), rule("nobody-pays", "deny"))
    assert decide(p, "billing-agent") == (Decision.DENY, "nobody-pays")


def test_per_agent_allow_never_beats_a_global_require_approval() -> None:
    p = policy(rule("a-pays", "allow", ["billing-agent"]), rule("z-ask", "require_approval"))
    assert decide(p, "billing-agent") == (Decision.REQUIRE_APPROVAL, "z-ask")


def test_per_agent_deny_beats_a_global_allow_for_its_agent_only() -> None:
    p = policy(rule("everyone", "allow"), rule("not-research", "deny", ["research-agent"]))
    assert decide(p, "research-agent") == (Decision.DENY, "not-research")
    assert decide(p, "billing-agent") == (Decision.ALLOW, "everyone")


def test_per_agent_conditions_still_apply() -> None:
    small = rule(
        "billing-small",
        "allow",
        ["billing-agent"],
        when=[{"arg": "amount", "op": "lte", "value": 500}],
    )
    p = policy(small)
    assert decide(p, "billing-agent", amount=500) == (Decision.ALLOW, "billing-small")
    assert decide(p, "billing-agent", amount=501) == (Decision.DENY, None)
    assert decide(p, "billing-agent") == (Decision.DENY, None)  # missing: allow fails closed
    assert decide(p, "other", amount=1) == (Decision.DENY, None)


def test_a_per_agent_deny_does_not_touch_other_agents_even_on_missing_arguments() -> None:
    # For another agent the rule doesn't exist, so its unreadable condition can't deny.
    deny = rule(
        "billing-big",
        "deny",
        ["billing-agent"],
        when=[{"arg": "amount", "op": "gt", "value": 500}],
    )
    p = policy(rule("everyone", "allow"), deny)
    assert decide(p, "billing-agent") == (Decision.DENY, "billing-big")  # fails closed
    assert decide(p, "other") == (Decision.ALLOW, "everyone")


def test_rule_order_does_not_matter() -> None:
    rules = [rule("b", "allow", ["x"]), rule("a", "deny", ["x"]), rule("c", "allow")]
    for order in (rules, rules[::-1]):
        p = policy(*order)
        assert decide(p, "x") == (Decision.DENY, "a")
        assert decide(p, "y") == (Decision.ALLOW, "c")


# --- Starting the server ---------------------------------------------------------------


def registry(*ids: str) -> tuple[AgentRegistry, dict[str, str]]:
    tokens = {agent: new_token() for agent in ids}
    entries = tuple(
        AgentEntry(id=a, token_sha256=hash_token(t), server_key=proof_key(t).hex())
        for a, t in tokens.items()
    )
    return AgentRegistry(entries), tokens


def app_for(tmp_path: Path, data: object, agents: AgentRegistry | None) -> Any:
    return create_app(
        policy_path=write(tmp_path, "p.json", data),
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        approvals=ApprovalStore(),
        admin_key=ADMIN_KEY,
        agents=agents,
    )


def test_refuses_per_agent_rules_without_agent_tokens(tmp_path: Path) -> None:
    data = {"rules": [rule("everyone", "deny"), rule("billing-pays", "allow", ["billing"])]}
    with pytest.raises(StartupError, match="rule 'billing-pays' is per-agent: start with --agents"):
        app_for(tmp_path, data, None)


def test_refuses_a_per_agent_deny_without_agent_tokens(tmp_path: Path) -> None:
    # A per-agent deny is dodged by typing another name: just as unsafe.
    data = {"rules": [rule("everyone", "allow"), rule("no-research", "deny", ["research"])]}
    with pytest.raises(StartupError, match="no-research"):
        app_for(tmp_path, data, None)


def test_refuses_an_agent_name_not_in_the_agents_file(tmp_path: Path) -> None:
    data = {"rules": [rule("everyone", "allow"), rule("no-research", "deny", ["reserach"])]}
    agents, _ = registry("research")
    with pytest.raises(StartupError, match="rule 'no-research' names agent 'reserach'"):
        app_for(tmp_path, data, agents)


def test_refuses_a_case_variant_of_a_known_agent(tmp_path: Path) -> None:
    data = {"rules": [rule("r", "allow", ["Research"])]}
    agents, _ = registry("research")
    with pytest.raises(StartupError, match="'Research'"):
        app_for(tmp_path, data, agents)


def test_refuses_an_unknown_agent_in_limits(tmp_path: Path) -> None:
    data = {
        "rules": [rule("r", "allow")],
        "limits": {"agents": {"ghost": {"requests_per_minute": 5}}},
    }
    agents, _ = registry("research")
    with pytest.raises(StartupError, match="limits.agents names agent 'ghost'"):
        app_for(tmp_path, data, agents)


def test_unknown_limits_agent_is_fine_without_tokens(tmp_path: Path) -> None:
    # Without tokens any name can be claimed anyway; nothing new to refuse here.
    data = {
        "rules": [rule("r", "allow")],
        "limits": {"agents": {"ghost": {"requests_per_minute": 5}}},
    }
    assert app_for(tmp_path, data, None) is not None


def test_policy_without_per_agent_rules_needs_no_tokens(tmp_path: Path) -> None:
    assert app_for(tmp_path, {"rules": [rule("r", "allow")]}, None) is not None


def test_api_per_agent_allow_follows_the_token(tmp_path: Path) -> None:
    data = {
        "rules": [rule("billing-pays", "allow", ["billing"])],
        "limits": {"agents": {"research": {"requests_per_minute": 100}}},
    }
    agents, tokens = registry("billing", "research")
    client = TestClient(app_for(tmp_path, data, agents))
    body = {"tool": "pay", "arguments": {"amount": 1}}

    def ask(token: str, **extra: Any) -> Any:
        return client.post(
            "/v1/evaluate", json={**body, **extra}, headers={"Authorization": f"Bearer {token}"}
        )

    allowed = ask(tokens["billing"])
    assert allowed.status_code == 200 and allowed.json()["decision"] == "allow"
    denied = ask(tokens["research"])
    assert denied.json()["decision"] == "deny"
    assert denied.json()["matched_rule"] is None
    # Claiming to be billing in the body doesn't help: the token decides who asks.
    claimed = ask(tokens["research"], agent_id="billing")
    assert claimed.json()["decision"] == "deny"
    assert client.post("/v1/evaluate", json={**body, "agent_id": "billing"}).status_code == 401


def test_serve_refuses_without_agents_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server started"))
    monkeypatch.setenv("WARDEN_ADMIN_KEY", "k" * 32)
    monkeypatch.delenv("WARDEN_AGENTS", raising=False)
    path = write(tmp_path, "p.json", {"rules": [rule("billing-pays", "allow", ["billing"])]})
    argv = ["serve", "--policy", str(path), "--audit-db", str(tmp_path / "a.db")]
    assert cli.main(argv) == 2
    assert "agent tokens are required" in capsys.readouterr().err
    # Even with --no-auth chosen on purpose, a per-agent rule needs real agent ids.
    assert cli.main([*argv, "--no-auth"]) == 2
    assert "rule 'billing-pays' is per-agent: start with --agents" in capsys.readouterr().err


def test_serve_starts_with_known_agents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: apps.append(app))
    monkeypatch.setenv("WARDEN_ADMIN_KEY", "k" * 32)
    agents = tmp_path / "agents.json"
    add_agent(agents, "billing")
    path = write(tmp_path, "p.json", {"rules": [rule("billing-pays", "allow", ["billing"])]})
    argv = ["serve", "--policy", str(path), "--audit-db", str(tmp_path / "a.db")]
    assert cli.main([*argv, "--agents", str(agents)]) == 0
    assert len(apps) == 1


def test_api_main_refuses_unknown_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server started"))
    agents = tmp_path / "agents.json"
    add_agent(agents, "billing")
    path = write(tmp_path, "p.json", {"rules": [rule("r", "allow", ["biling"])]})
    settings = Settings(policy=path, audit_db=tmp_path / "a.db", admin_key="k" * 32, agents=agents)
    with pytest.raises(StartupError, match="'biling'"):
        warden.api.main(settings)


# --- warden check -----------------------------------------------------------------------


def codes(tmp_path: Path, data: object, agents: list[str] | None = None) -> list[str]:
    agents_path = None
    if agents is not None:
        agents_path = tmp_path / "agents.json"
        for agent in agents:
            add_agent(agents_path, agent)
    report = check_policy(write(tmp_path, "p.json", data), agents_path)
    assert not report.errors
    return sorted(w.split(":")[0] for w in report.warnings)


def test_w014_unknown_agent_in_a_rule(tmp_path: Path) -> None:
    data = {"rules": [rule("r", "allow", ["billing", "biling"])]}
    assert codes(tmp_path, data, ["billing"]) == ["W014"]
    assert codes(tmp_path, data) == []  # without --agents there is nothing to compare


def test_w014_unknown_agent_in_limits(tmp_path: Path) -> None:
    data = {"rules": [rule("r", "allow")], "limits": {"agents": {"ghost": {}}}}
    report = check_policy(write(tmp_path, "p.json", data), _agents(tmp_path, "billing"))
    assert report.warnings == [
        'W014: limits.agents names agent "ghost", which isn\'t in the agents file (typo?); '
        "`warden serve` refuses to start with it."
    ]


def _agents(tmp_path: Path, *ids: str) -> Path:
    path = tmp_path / "agents.json"
    for agent in ids:
        add_agent(path, agent)
    return path


def test_w014_not_raised_for_known_agents(tmp_path: Path) -> None:
    data = {"rules": [rule("r", "allow", ["billing"])], "limits": {"agents": {"billing": {}}}}
    assert codes(tmp_path, data, ["billing", "research"]) == []


def test_w015_case_variants_in_the_policy(tmp_path: Path) -> None:
    data = {"rules": [rule("a", "allow", ["Billing"]), rule("b", "deny", ["billing"])]}
    report = check_policy(write(tmp_path, "p.json", data))
    assert [w for w in report.warnings if w.startswith("W015")] == [
        'W015: agent names "Billing", "billing" differ only in upper/lower case; agent ids '
        "are case-sensitive, so these are different agents (one agent written two ways?)."
    ]


def test_w015_case_variant_of_an_agents_file_name(tmp_path: Path) -> None:
    data = {"rules": [rule("a", "allow", ["Billing"])]}
    assert codes(tmp_path, data, ["billing"]) == ["W014", "W015"]


def test_note_per_agent_rules_need_agents_at_serve_time(tmp_path: Path) -> None:
    report = check_policy(write(tmp_path, "p.json", {"rules": [rule("r", "allow", ["x"])]}))
    assert report.warnings == [] and len(report.notes) == 1
    assert "--agents" in report.notes[0]
    with_file = check_policy(tmp_path / "p.json", _agents(tmp_path, "x"))
    assert with_file.notes == [] and with_file.warnings == []
    plain = check_policy(write(tmp_path, "q.json", {"rules": [rule("r", "allow")]}))
    assert plain.notes == []


def test_bad_agents_file_is_an_error(tmp_path: Path) -> None:
    bad = tmp_path / "agents.json"
    bad.write_text("not json")
    report = check_policy(write(tmp_path, "p.json", {"rules": [rule("r", "allow")]}), bad)
    assert report.errors and report.errors[0].startswith("agents file: ")


def test_w003_global_deny_kills_a_per_agent_allow(tmp_path: Path) -> None:
    data = {"rules": [rule("billing-pays", "allow", ["billing"]), rule("nobody", "deny")]}
    assert codes(tmp_path, data) == ["W003"]


def test_w003_per_agent_deny_does_not_kill_a_global_allow(tmp_path: Path) -> None:
    data = {"rules": [rule("everyone", "allow"), rule("not-research", "deny", ["research"])]}
    assert codes(tmp_path, data) == []


def test_w003_per_agent_deny_covering_all_the_allows_agents(tmp_path: Path) -> None:
    data = {
        "rules": [
            rule("pays", "allow", ["billing"]),
            rule("no-pay", "deny", ["billing", "research"]),
            rule("other-pays", "allow", ["ops", "billing"]),
        ]
    }
    # "pays" is dead (billing is always denied); "other-pays" still works for ops.
    report = check_policy(write(tmp_path, "p.json", data))
    assert [w for w in report.warnings if w.startswith("W003")] == [
        'W003: rule "pays" can never apply: "no-pay" always gives deny for pay.'
    ]


def test_w004_duplicates_need_the_same_agents(tmp_path: Path) -> None:
    same = {"rules": [rule("a", "allow", ["x", "y"]), rule("b", "allow", ["y", "x"])]}
    assert codes(tmp_path, same) == ["W004"]
    different = {"rules": [rule("a", "allow", ["x"]), rule("b", "allow", ["y"])]}
    assert codes(tmp_path, different) == []
    global_and_one = {"rules": [rule("a", "allow"), rule("b", "allow", ["y"])]}
    assert codes(tmp_path, global_and_one) == []


def test_cli_check_agents_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "p.json", {"rules": [rule("r", "allow", ["biling"])]})
    assert cli.main(["check", str(path), "--strict"]) == 0  # a note never fails --strict
    assert "NOTE: the policy has per-agent rules" in capsys.readouterr().out
    agents = _agents(tmp_path, "billing")
    assert cli.main(["check", str(path), "--agents", str(agents)]) == 0
    assert "W014" in capsys.readouterr().out
    assert cli.main(["check", str(path), "--agents", str(agents), "--strict"]) == 1


# --- warden test ------------------------------------------------------------------------


def test_policy_tests_use_the_case_agent_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "p.json", {"rules": [rule("billing-pays", "allow", ["billing"])]})

    def case(agent: str | None, expect: str) -> dict[str, Any]:
        request: dict[str, Any] = {"tool": "pay", "arguments": {}}
        if agent is not None:
            request["agent_id"] = agent
        return {"name": f"{agent} {expect}", "request": request, "expect": expect}

    good = [case("billing", "allow"), case("research", "deny"), case(None, "deny")]
    tests = write(tmp_path, "t.json", {"policy": "p.json", "cases": good})
    assert run_policy_tests(tests, None) == 0
    wrong = write(tmp_path, "w.json", {"policy": "p.json", "cases": [case("research", "allow")]})
    assert run_policy_tests(wrong, None) == 1
    capsys.readouterr()
