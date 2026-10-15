#!/usr/bin/env python3
"""Upgrade and restore a synthetic pre-hardening SQLite database. Never uses production data."""
import importlib.util
from contextlib import closing
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit,urlunsplit,unquote,parse_qs
import uuid

ROOT = Path(__file__).resolve().parents[1]
LEGACY_NOTICE = "INSERT INTO announcements(title,content,published_at,expires_at) VALUES('expiry-fixture','test-only','2026-01-01 00:00:00','2026-9-1 00:00:00');"
spec = importlib.util.spec_from_file_location("backup", ROOT / "scripts/backup-sqlite.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def boot(binary, database, directory, url=None, expect_failure=False):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {**os.environ, "DATABASE_URL": url or f"sqlite:{database}?mode=rwc", "LISTEN": f"127.0.0.1:{port}",
           "JWT_SECRET": "synthetic-upgrade-test-secret-32-bytes", "GEOIP_ENABLED": "false"}
    with open(directory / "panel.log", "ab") as log:
        process = subprocess.Popen([str(binary)], env=env, cwd=directory, stdout=log, stderr=log)
        try:
            for _ in range(200):
                if process.poll() is not None:
                    if expect_failure:
                        assert process.returncode != 0, "invalid migration state must fail startup"
                        return
                    raise AssertionError(f"panel stopped; inspect {directory / 'panel.log'}")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health", timeout=1) as response:
                        assert json.load(response)["status"] == "ok"
                    assert not expect_failure, "invalid opening balance was silently accepted"
                    return
                except OSError:
                    time.sleep(0.05)
            raise AssertionError("panel health timeout")
        finally:
            process.terminate()
            process.wait(timeout=10)


def postgres_upgrade(binary,directory):
    url=os.environ.get("TEST_PG_URL")
    if not url:
        if os.environ.get("RELAY_REQUIRE_PG_TESTS"):
            raise AssertionError("TEST_PG_URL required for PostgreSQL migration/restore gate")
        print("SKIP: PostgreSQL upgrade/restore (TEST_PG_URL is unset)")
        return
    parsed=urlsplit(url)
    def db_url(name):
        return urlunsplit((parsed.scheme,parsed.netloc,"/"+name,parsed.query,""))
    def environment(name):
        # PGDATABASE does not expand a URI when supplied only as an environment
        # default. Keep credentials out of command arguments and split libpq env.
        env={**os.environ,"PGDATABASE":name,"PGHOST":parsed.hostname or "localhost","PGPORT":str(parsed.port or 5432)}
        if parsed.username is not None:
            env["PGUSER"]=unquote(parsed.username)
        if parsed.password is not None:
            env["PGPASSWORD"]=unquote(parsed.password)
        for key,values in parse_qs(parsed.query).items():
            if key in ("sslmode","sslrootcert","sslcert","sslkey","options","host","port"):
                env["PG"+key.upper()]=values[-1]
        return env
    def sql(name,statement):
        env=environment(name)
        return subprocess.check_output(["psql","--no-psqlrc","--quiet","--tuples-only","--no-align","--set","ON_ERROR_STOP=1"],input=statement,text=True,env=env).strip()
    name="relay_upgrade_"+uuid.uuid4().hex[:12]
    restored="relay_restore_"+uuid.uuid4().hex[:12]
    source=subprocess.check_output(["git","show","v1.3.22:crates/panel/src/db/pg_schema.rs"],cwd=ROOT,text=True)
    baseline=re.search(r'pub const PG_SCHEMA_SQL: &str = r#"(.*?)"#;',source,re.S).group(1)
    try:
        sql("postgres",f'CREATE DATABASE "{name}"; CREATE DATABASE "{restored}";')
        sql(name,baseline+"\nINSERT INTO schema_version(version) VALUES(44) ON CONFLICT DO NOTHING; UPDATE users SET balance='123.45',traffic_used=456,traffic_limit=10000 WHERE id=1;"+LEGACY_NOTICE)
        archive=directory/"postgres-before-upgrade.dump"
        subprocess.run(["pg_dump","--format=custom","--file",str(archive)],env=environment(name),check=True)
        sql(name,"INSERT INTO users(username,password,balance) VALUES('invalid-opening','test-only','not-money');")
        boot(binary,None,directory,db_url(name),expect_failure=True)
        assert sql(name,"SELECT MAX(version) FROM schema_version;")=="47", "failed revision 48 must not be marked complete"
        assert sql(name,"SELECT COUNT(*) FROM balance_ledger;")=="0", "opening ledger migration must roll back atomically in PostgreSQL"
        assert sql(name,"SELECT expires_at FROM announcements WHERE title='expiry-fixture';")=="2026-9-1 00:00:00", "revision 48 timestamp correction must also roll back"
        sql(name,"UPDATE users SET balance='1.23' WHERE username='invalid-opening';")
        boot(binary,None,directory,db_url(name))
        expected=sql(name,"SELECT balance,traffic_used,traffic_limit FROM users WHERE id=1;")
        assert expected=="123.45|456|10000",expected
        assert sql(name,"SELECT amount_cents,balance_after FROM balance_ledger WHERE user_id=1;")=="12345|123.45"
        assert sql(name,"SELECT expires_at FROM announcements WHERE title='expiry-fixture';")=="2026-09-01 00:00:00"
        boot(binary,None,directory,db_url(name))
        assert sql(name,"SELECT COUNT(*) FROM balance_ledger WHERE user_id=1;")=="1"
        restored_sql=subprocess.check_output(["pg_restore","--no-owner","--no-privileges","--file=-",str(archive)],text=True)
        sql(restored,restored_sql)
        boot(binary,None,directory,db_url(restored))
        assert sql(restored,"SELECT balance,traffic_used,traffic_limit FROM users WHERE id=1;")==expected
        assert sql(restored,"SELECT amount_cents FROM balance_ledger WHERE user_id=1;")=="12345"
        assert sql(restored,"SELECT expires_at FROM announcements WHERE title='expiry-fixture';")=="2026-09-01 00:00:00"
        print("PASS: PostgreSQL 44→48 upgrade, failed migration rollback/recovery, idempotent restart, pg_dump, and pg_restore")
    finally:
        sql("postgres",f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE); DROP DATABASE IF EXISTS "{restored}" WITH (FORCE);')


def main():
    binary = Path(os.environ.get("RELAY_PANEL_BIN", ROOT / "target/debug/relay-panel")).resolve(strict=True)
    # Pin the release predecessor, not HEAD (HEAD will change after committing).
    source = subprocess.check_output(["git", "show", "v1.3.22:crates/panel/src/db/schema.rs"], cwd=ROOT, text=True)
    baseline = re.search(r'pub const SCHEMA_SQL: &str = r#"(.*?)"#;', source, re.S).group(1)
    with tempfile.TemporaryDirectory(prefix="relay-billing-upgrade-", dir=os.environ.get("TMPDIR")) as temporary:
        directory = Path(temporary)
        database = directory / "legacy.db"
        with closing(sqlite3.connect(database)) as conn, conn:
            conn.executescript(baseline)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("UPDATE users SET balance='123.45',traffic_used=456,traffic_limit=10000 WHERE id=1")
            conn.execute(LEGACY_NOTICE)
            conn.commit()
            backup.backup(database, directory / "before-upgrade.db")
            try:
                backup.backup(database, directory / "before-upgrade.db")
                raise AssertionError("backup overwrote a prior snapshot")
            except ValueError:
                pass
        with closing(sqlite3.connect(database)) as conn, conn:
            conn.execute("INSERT INTO users(username,password,balance) VALUES('invalid-opening','test-only','not-money')")
        boot(binary, database, directory, expect_failure=True)
        with closing(sqlite3.connect(database)) as conn, conn:
            conn.execute("UPDATE users SET balance='1.23' WHERE username='invalid-opening'")
        boot(binary, database, directory)
        with closing(sqlite3.connect(database)) as conn, conn:
            expected = conn.execute("SELECT balance,traffic_used,traffic_limit FROM users WHERE id=1").fetchone()
            assert expected == ("123.45", 456, 10000), expected
            assert conn.execute("SELECT amount_cents,balance_after FROM balance_ledger WHERE user_id=1").fetchall() == [(12345, "123.45")]
            assert conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
            assert conn.execute("SELECT expires_at FROM announcements WHERE title='expiry-fixture'").fetchone() == ("2026-09-01 00:00:00",)
        # Repeated migration must neither duplicate opening entries nor reset usage.
        boot(binary, database, directory)
        with closing(sqlite3.connect(database)) as conn, conn:
            assert conn.execute("SELECT COUNT(*) FROM balance_ledger WHERE user_id=1").fetchone() == (1,)
        restored = directory / "restored.db"
        shutil.copyfile(directory / "before-upgrade.db", restored)
        boot(binary, restored, directory)
        with closing(sqlite3.connect(restored)) as conn, conn:
            assert conn.execute("SELECT balance,traffic_used,traffic_limit FROM users WHERE id=1").fetchone() == expected
            assert conn.execute("SELECT amount_cents FROM balance_ledger WHERE user_id=1").fetchone() == (12345,)
            assert conn.execute("SELECT expires_at FROM announcements WHERE title='expiry-fixture'").fetchone() == ("2026-09-01 00:00:00",)
        print("PASS: legacy SQLite upgrade, failed migration recovery, idempotent restart, WAL-safe backup, and pre-upgrade restore")
        postgres_upgrade(binary,directory)


if __name__ == "__main__":
    main()
