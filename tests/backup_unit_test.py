"""Offline tests for upgrade backup failure safety. No Docker/database services."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("upgrade_backup", ROOT / "scripts/backup-before-upgrade.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupSafety(unittest.TestCase):
    def test_postgres_credentials_are_forwarded_via_libpq_environment(self):
        env = backup.postgres_environment("postgres://relay:p%40ss@db.test:5544/billing?sslmode=verify-full")
        self.assertEqual(env, {"PGHOST": "db.test", "PGPORT": "5544", "PGDATABASE": "billing", "PGUSER": "relay", "PGPASSWORD": "p@ss", "PGSSLMODE": "verify-full"})
        with self.assertRaisesRegex(ValueError, "unsupported"):
            backup.postgres_environment("postgres://db/billing?unsafe_unknown=true")
    def exercise(self, fail_copy=False, was_running=True, fail_stop=False):
        with tempfile.TemporaryDirectory(prefix="relay-backup-unit-") as temporary:
            directory = Path(temporary)
            database = directory / "data.db"
            with contextlib.closing(sqlite3.connect(database)) as conn, conn:
                conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY,balance TEXT)")
                conn.execute("INSERT INTO users VALUES(1,'123.45')")
            inspection = {"Config": {"Env": ["DATABASE_URL=sqlite:/app/data/data.db?mode=rwc"]}, "State": {"Running": was_running}}
            commands = []

            def output(args, **_):
                if args[0:2] == ["docker", "inspect"]:
                    return json.dumps([inspection])
                return "old-panel-container\n"

            def run(args, **_):
                commands.append(args)
                if fail_stop and "stop" in args:
                    raise RuntimeError("synthetic lost stop response")
                if args[:2] == ["docker", "cp"]:
                    if fail_copy:
                        raise RuntimeError("synthetic failed copy")
                    shutil.copyfile(database, Path(args[-1]) / "data.db")
                return subprocess.CompletedProcess(args, 0)

            with patch.object(backup.sys, "argv", ["backup", "compose.yaml"]), \
                    patch.dict(os.environ, {"RELAYPANEL_BACKUP_DIR": str(directory / "backups"), "DATABASE_URL": "sqlite:/wrong-new-env.db"}), \
                    patch.object(backup.subprocess, "check_output", side_effect=output), \
                    patch.object(backup.subprocess, "run", side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()):
                if fail_copy or fail_stop:
                    with self.assertRaisesRegex(RuntimeError, "synthetic"):
                        backup.main()
                    self.assertEqual(["docker", "start", "old-panel-container"] in commands, was_running)
                    self.assertFalse(list((directory / "backups").glob("*/manifest.json")))
                else:
                    backup.main()
                    self.assertNotIn(["docker", "start", "old-panel-container"], commands)
                    snapshot = next((directory / "backups").glob("*/manifest.json")).parent
                    self.assertEqual(json.loads((snapshot / "manifest.json").read_text())["backend"], "sqlite")
                    with contextlib.closing(sqlite3.connect(snapshot / "data/data.db")) as conn, conn:
                        self.assertEqual(conn.execute("SELECT balance FROM users").fetchone(), ("123.45",))

    def test_uses_old_container_database_not_new_environment(self):
        self.exercise()

    def test_failed_backup_restarts_exact_old_container_without_recreate(self):
        self.exercise(fail_copy=True)

    def test_failed_backup_does_not_start_previously_stopped_service(self):
        self.exercise(fail_copy=True, was_running=False)

    def test_lost_stop_response_attempts_original_container_recovery(self):
        self.exercise(fail_stop=True)

    def test_failed_stop_does_not_start_previously_stopped_service(self):
        self.exercise(fail_stop=True, was_running=False)


if __name__ == "__main__":
    unittest.main()
