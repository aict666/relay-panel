#!/usr/bin/env python3
"""Verify the deployment backup helper against an isolated local PostgreSQL DB.

Requires TEST_PG_URL to a disposable local test instance and a built panel image.
Docker uses host networking; no production connection should be supplied.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit, urlunsplit
import uuid

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("upgrade_backup", ROOT / "scripts/backup-before-upgrade.py")
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def main():
    parsed = urlsplit(os.environ["TEST_PG_URL"])
    if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("container backup test only accepts an isolated local test PostgreSQL server")
    name = "relay_backup_" + uuid.uuid4().hex[:12]
    restored = name + "_restored"
    project = "relay-pg-backup-" + uuid.uuid4().hex[:12]
    def url(database):
        return urlunsplit((parsed.scheme, parsed.netloc, "/" + database, parsed.query, ""))
    def sql(database, statement):
        env = {**os.environ, **upgrade.postgres_environment(url(database))}
        return subprocess.check_output(["psql", "--no-psqlrc", "-qAt", "--set", "ON_ERROR_STOP=1"], input=statement, text=True, env=env).strip()
    def run(*args, **kwargs):
        return subprocess.run(list(args), check=True, **kwargs)
    source = subprocess.check_output(["git", "show", "v1.3.22:crates/panel/src/db/pg_schema.rs"], cwd=ROOT, text=True)
    baseline = re.search(r'pub const PG_SCHEMA_SQL: &str = r#"(.*?)"#;', source, re.S).group(1)
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        directory = Path(temporary)
        with closing(socket.socket()) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        compose_file = directory / "compose.json"
        compose_file.write_text(json.dumps({"services": {"panel": {"image": sys.argv[1], "network_mode": "host", "environment": {
            "DATABASE_URL": url(name), "LISTEN": f"127.0.0.1:{port}", "JWT_SECRET": "synthetic-pg-backup-test-secret-32-bytes", "GEOIP_ENABLED": "false"}}}}))
        compose = ["docker", "compose", "--project-name", project, "-f", str(compose_file)]
        try:
            sql("postgres", f'CREATE DATABASE "{name}"; CREATE DATABASE "{restored}";')
            sql(name, baseline + "\nINSERT INTO schema_version(version) VALUES(44) ON CONFLICT DO NOTHING; UPDATE users SET balance='123.45',traffic_used=456 WHERE id=1;")
            run(*compose, "up", "-d")
            for _ in range(160):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health", timeout=1) as response:
                        assert json.load(response)["status"] == "ok"
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("PostgreSQL panel image health timeout")
            env = {**os.environ, "COMPOSE_PROJECT_NAME": project, "RELAYPANEL_DB_MODE": "external-postgres", "RELAYPANEL_BACKUP_DIR": str(directory / "backups")}
            run(sys.executable, str(ROOT / "scripts/backup-before-upgrade.py"), str(compose_file), cwd=directory, env=env)
            snapshot = next((directory / "backups").glob("*/postgres.dump"))
            restored_sql = subprocess.check_output(["pg_restore", "--no-owner", "--no-privileges", "--file=-", str(snapshot)], text=True)
            sql(restored, restored_sql)
            assert sql(restored, "SELECT balance,traffic_used FROM users WHERE id=1;") == "123.45|456"
            assert sql(restored, "SELECT amount_cents FROM balance_ledger WHERE user_id=1;") == "12345"
            print("PASS: actual external-PostgreSQL deployment helper dump, archive validation and restore")
        finally:
            subprocess.run(compose + ["down", "--volumes"], check=False)
            sql("postgres", f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE); DROP DATABASE IF EXISTS "{restored}" WITH (FORCE);')


if __name__ == "__main__":
    main()
