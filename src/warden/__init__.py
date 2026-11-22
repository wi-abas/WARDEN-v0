"""Warden: a deterministic security and policy layer for AI agent tool calls."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("warden")
except PackageNotFoundError:  # running from source without installing
    __version__ = "unknown"
