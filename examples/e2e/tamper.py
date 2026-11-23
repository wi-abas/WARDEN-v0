"""Make a tampered COPY of the audit database (the real one is never touched).

Usage: python tamper.py AUDIT_DB COPY MODE
  flip      turn the first 'deny' decision into 'allow'
  truncate  delete the newest decision (only a checkpoint can notice this)
"""

import sqlite3
import sys


def main(source: str, target: str, mode: str) -> None:
    with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
        src.backup(dst)
        if mode == "flip":
            dst.execute(
                "UPDATE decisions SET decision = 'allow'"
                " WHERE id = (SELECT min(id) FROM decisions WHERE decision = 'deny')"
            )
        elif mode == "truncate":
            dst.execute("DELETE FROM decisions WHERE id = (SELECT max(id) FROM decisions)")
        else:
            sys.exit(f"unknown mode {mode!r}")
    src.close()
    dst.close()


if __name__ == "__main__":
    main(*sys.argv[1:4])
