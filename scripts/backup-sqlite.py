#!/usr/bin/env python3
"""Consistent online SQLite backup, including committed WAL data; never overwrite."""
import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import quote


def backup(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    destination = destination.absolute()
    if source == destination or destination.exists():
        raise ValueError("backup destination must be a new file")
    if not destination.parent.is_dir():
        raise ValueError("create a private backup directory first (mode 700)")
    fd, temporary = tempfile.mkstemp(prefix=".relay-backup-", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(f"file:{quote(str(source), safe='/')}?mode=ro", uri=True)) as src:
            with closing(sqlite3.connect(temporary)) as dst, dst:
                src.backup(dst)
                if dst.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise ValueError("SQLite backup integrity check failed")
        with open(temporary, "rb") as stream:
            os.fsync(stream.fileno())
        # Atomic publication with no replacement, including a racing caller.
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    backup(args.source, args.destination)
    print(f"Verified SQLite backup: {args.destination}")
