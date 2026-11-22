"""Per-agent tokens: who is asking, proven by a secret instead of self-declared.

The agents file stores, per agent, the SHA-256 hash of its token, never the token:
    {"agents": [{"id": "billing-agent", "token_sha256": "<64 hex characters>"}]}

Tokens are 256-bit random values ("wdn_" + 43 URL-safe characters), so a fast hash is
safe (there's nothing to brute-force). Every lookup compares against EVERY stored hash
with secrets.compare_digest, so timing reveals nothing about which hash came close.
See docs/design/agent-tokens.md.
"""

import hashlib
import json
import os
import re
import secrets
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from warden.models import AGENT_ID_PATTERN
from warden.policy import DuplicateKeyError, describe_errors, no_duplicate_keys

DEFAULT_AGENTS_PATH = Path("warden-agents.json")
TOKEN_PREFIX = "wdn_"  # noqa: S105 (a public prefix, not a secret)
TOKEN_PATTERN = r"^wdn_[A-Za-z0-9_\-]{43}$"  # noqa: S105
MAX_AGENTS = 1000


class AgentsError(ValueError):
    """The agents file is missing, unreadable or invalid. Never contains tokens."""


class AgentEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(pattern=AGENT_ID_PATTERN)
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentsFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    agents: tuple[AgentEntry, ...] = Field(default=(), max_length=MAX_AGENTS)

    @model_validator(mode="after")
    def unique(self) -> "AgentsFile":
        ids = [a.id for a in self.agents]
        if len(set(ids)) != len(ids):
            raise ValueError("an agent id is listed twice")
        hashes = [a.token_sha256 for a in self.agents]
        if len(set(hashes)) != len(hashes):
            raise ValueError("two agents share a token")
        return self


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AgentRegistry:
    """Maps a presented token to its agent id."""

    def __init__(self, entries: tuple[AgentEntry, ...]) -> None:
        self._entries = entries

    @property
    def agent_ids(self) -> list[str]:
        return [entry.id for entry in self._entries]

    def identify(self, token: str) -> str | None:
        """The agent this token belongs to, or None. Constant time over all agents."""
        if not re.fullmatch(TOKEN_PATTERN, token):
            return None
        presented = hash_token(token).encode()
        found: str | None = None
        for entry in self._entries:  # no early exit: same work whichever entry matches
            if secrets.compare_digest(presented, entry.token_sha256.encode()):
                found = entry.id
        return found

    def identify_header(self, authorization: str | None) -> str | None:
        """Agent id from an "Authorization: Bearer <token>" header, or None."""
        if authorization is None:
            return None
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            return None
        return self.identify(token.strip())


def read_agents_file(path: Path) -> AgentsFile:
    try:
        raw = path.read_text(encoding="utf-8")
        json.loads(raw, object_pairs_hook=no_duplicate_keys)
        return AgentsFile.model_validate_json(raw)
    except DuplicateKeyError as exc:
        raise AgentsError(f"{path}: {exc}") from None
    except ValidationError as exc:
        raise AgentsError(f"{path}: {'; '.join(describe_errors(exc))}") from None
    except (OSError, ValueError) as exc:
        raise AgentsError(f"{path}: can't read it ({type(exc).__name__})") from None


def load_agents(path: Path) -> AgentRegistry:
    return AgentRegistry(read_agents_file(path).agents)


def _write_private(path: Path, data: AgentsFile) -> None:
    """Write atomically (temp file + rename) with mode 600: never a half-written file."""
    text = json.dumps(data.model_dump(), indent=2) + "\n"
    folder = path.resolve().parent
    fd, temp = tempfile.mkstemp(dir=folder, prefix=".warden-agents-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def add_agent(path: Path, agent_id: str) -> str:
    """Register `agent_id` with a new token. Returns the token (shown once, not stored)."""
    if not re.fullmatch(AGENT_ID_PATTERN, agent_id):
        raise AgentsError("agent id may use letters, digits, '_', '.', '-' (1 to 128)")
    current = read_agents_file(path) if path.exists() else AgentsFile()
    if agent_id in [a.id for a in current.agents]:
        raise AgentsError(f"agent {agent_id!r} already exists (remove it first to rotate)")
    token = new_token()
    entry = AgentEntry(id=agent_id, token_sha256=hash_token(token))
    _write_private(path, AgentsFile(agents=(*current.agents, entry)))
    return token


def remove_agent(path: Path, agent_id: str) -> bool:
    """Remove `agent_id`. False if it wasn't there."""
    current = read_agents_file(path)
    kept = tuple(a for a in current.agents if a.id != agent_id)
    if len(kept) == len(current.agents):
        return False
    _write_private(path, AgentsFile(agents=kept))
    return True
