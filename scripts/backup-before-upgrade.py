#!/usr/bin/env python3
"""Stop the existing Compose panel and verify a private pre-upgrade backup.

On failure the original container is restarted; on success deploy.sh starts the
new version. No production operation happens unless an operator runs deploy.sh.
"""
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def postgres_environment(url):
    parsed = urlsplit(url)
    result = {
        "PGHOST": parsed.hostname or "localhost",
        "PGPORT": str(parsed.port or 5432),
        "PGDATABASE": unquote(parsed.path.removeprefix("/")),
    }
    if parsed.username is not None:
        result["PGUSER"] = unquote(parsed.username)
    if parsed.password is not None:
        result["PGPASSWORD"] = unquote(parsed.password)
    allowed = {"host", "port", "sslmode", "sslrootcert", "sslcert", "sslkey", "options", "application_name", "connect_timeout"}
    for key, values in parse_qs(parsed.query).items():
        if key not in allowed:
            raise ValueError("unsupported PostgreSQL backup connection option; use a coordinated manual backup")
        result["PG" + key.upper()] = values[-1]
    return result


def main():
    compose = ["docker", "compose", "-f", sys.argv[1]]
    container = subprocess.check_output(compose + ["ps", "-a", "-q", "panel"], text=True).strip()
    if not container:
        print("No existing panel container; no managed database to snapshot.")
        return
    if "\n" in container:
        raise ValueError("stop all replicas and take a coordinated backup before upgrading")
    inspected = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    old_env = dict(value.split("=", 1) for value in inspected["Config"].get("Env", []) if "=" in value)
    # Snapshot the database actually used by the OLD process, not a newly
    # edited .env that may point at a different, empty database.
    url = old_env.get("DATABASE_URL", "sqlite:/app/data/data.db?mode=rwc")
    pg = url.startswith(("postgres://", "postgresql://"))
    embedded = os.environ.get("RELAYPANEL_DB_MODE") == "embedded-postgres"
    pg_image=os.environ.get("RELAYPANEL_PG_BACKUP_IMAGE","postgres:16-alpine")
    if pg and not embedded:
        # Prepare the dump tool before stopping any working service.
        run(["docker", "pull", pg_image])
    root = Path(os.environ.get("RELAYPANEL_BACKUP_DIR", "backups")).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=time.strftime("pre-upgrade-%Y%m%d-%H%M%S-"), dir=root))
    os.chmod(directory, 0o700)
    was_running = inspected["State"]["Running"]
    pg_env = postgres_environment(url) if pg else {}
    backup_env = {**os.environ, **pg_env}
    forwarded_env = [argument for key in pg_env for argument in ("--env", key)]
    stop_attempted = False
    try:
        # A stop command may stop the process before returning an error (for
        # example, a lost daemon response). Recovery must cover that case too.
        stop_attempted = True
        run(compose + ["stop", "panel"])
        if pg:
            archive = directory / "postgres.dump"
            command = (compose + ["exec", "-T"] + forwarded_env + ["postgres", "pg_dump", "--format=custom"] if embedded else
                       ["docker", "run", "--rm", "--network", "host"] + forwarded_env + [pg_image, "pg_dump", "--format=custom"])
            with archive.open("wb") as stream:
                os.chmod(archive, 0o600)
                run(command, stdout=stream, env=backup_env)
            with archive.open("rb") as stream:
                if stream.read(5) != b"PGDMP":
                    raise ValueError("PostgreSQL dump is empty or not a custom archive")
            # Parse the entire archive catalogue, not just its filename/header.
            with archive.open("rb") as stream:
                command = (compose + ["exec", "-T", "postgres", "pg_restore", "--list"] if embedded else
                           ["docker", "run", "--rm", "-i", "--network", "none", pg_image, "pg_restore", "--list"])
                run(command, stdin=stream, stdout=subprocess.DEVNULL)
        else:
            path = url.removeprefix("sqlite:").split("?", 1)[0]
            while path.startswith("//"):
                path = path[1:]
            if not path.startswith("/app/data/") or ".." in Path(path).parts:
                raise ValueError("custom SQLite paths require a manual coordinated backup; automatic backup only supports /app/data")
            copied = directory / "data"
            copied.mkdir(mode=0o700)
            run(["docker", "cp", f"{container}:/app/data/.", str(copied)])
            database = copied / path.removeprefix("/app/data/")
            if not database.resolve().is_relative_to(copied.resolve()):
                raise ValueError("SQLite snapshot must not escape the copied data directory")
            with closing(sqlite3.connect(database)) as conn, conn:
                if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise ValueError("copied SQLite database failed integrity_check")
                if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] < 1:
                    raise ValueError("snapshot does not contain the expected panel database")
        if Path(".env").exists():
            target = directory / "environment.env"
            target.write_bytes(Path(".env").read_bytes())
            os.chmod(target, 0o600)
        (directory / "previous-container.json").write_text(json.dumps(inspected, indent=2))
        (directory / "manifest.json").write_text(json.dumps({"container": container, "backend": "postgres" if pg else "sqlite",
            "created_at_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}, indent=2))
        for path in directory.rglob("*"):
            if path.is_file() and not path.is_symlink():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        fd=os.open(directory,os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        print(f"Verified pre-upgrade backup: {directory}")
    except BaseException:
        if stop_attempted and was_running:
            subprocess.run(["docker", "start", container], check=False)
        raise


if __name__ == "__main__":
    os.umask(0o077)
    main()
