#!/usr/bin/env python3
"""Smoke-test a local panel image, root-owned legacy volume, backup and restart.

Uses uniquely named temporary Docker resources only. Does not publish images.
"""
import json
from contextlib import closing
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    image = sys.argv[1]
    if not re.fullmatch(r"[A-Za-z0-9._/:-]+", image):
        raise ValueError("invalid image name")
    identity = "relay-smoke-" + uuid.uuid4().hex[:12]
    volume = identity + "-data"
    seed = identity + "-seed"
    source = subprocess.check_output(["git", "show", "v1.3.22:crates/panel/src/db/schema.rs"], cwd=ROOT, text=True)
    baseline = re.search(r'pub const SCHEMA_SQL: &str = r#"(.*?)"#;', source, re.S).group(1)
    with tempfile.TemporaryDirectory(prefix=identity + "-") as temporary:
        directory = Path(temporary)
        compose_file = directory / "compose.yaml"
        compose_file.write_text(f"""services:
  panel:
    image: {image}
    ports: ['127.0.0.1::18888']
    environment:
      JWT_SECRET: synthetic-container-test-secret-32-bytes
      PANEL_KEY: synthetic-test-key
      GEOIP_ENABLED: 'false'
    volumes: ['data:/app/data']
volumes:
  data:
    external: true
    name: {volume}
""")
        compose = ["docker", "compose", "--project-name", identity, "-f", str(compose_file)]
        database = directory / "legacy.db"
        with closing(sqlite3.connect(database)) as conn, conn:
            conn.executescript(baseline)
            conn.execute("UPDATE users SET balance='123.45',traffic_used=456,traffic_limit=10000 WHERE id=1")
        try:
            run(["docker", "volume", "create", volume], stdout=subprocess.DEVNULL)
            run(["docker", "create", "--name", seed, "--volume", f"{volume}:/app/data", image], stdout=subprocess.DEVNULL)
            run(["docker", "cp", str(database), f"{seed}:/app/data/data.db"])
            run(["docker", "rm", seed], stdout=subprocess.DEVNULL)

            def wait_health(url):
                for _ in range(160):
                    try:
                        with urllib.request.urlopen(url + "/api/v1/health", timeout=1) as response:
                            health = json.load(response)
                            assert health["status"] == "ok"
                        return url, health
                    except OSError:
                        time.sleep(0.1)
                run(compose + ["logs", "panel"])
                raise AssertionError(f"container health timeout: {url}")

            def start():
                run(compose + ["up", "-d"])
                binding = subprocess.check_output(compose + ["port", "panel", "18888"], text=True).strip()
                return wait_health("http://" + binding)

            url, health = start()
            version = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "crates/panel/Cargo.toml").read_text(), re.M).group(1)
            assert health["version"] == version, health
            status = subprocess.check_output(compose + ["exec", "-T", "panel", "cat", "/proc/1/status"], text=True)
            assert re.search(r"^Uid:\s+10001\s+10001\s+10001\s+10001$", status, re.M), status
            with urllib.request.urlopen(url) as response:
                html = response.read().decode()
            css_url = re.search(r'href="([^"]+\.css)"', html).group(1)
            with urllib.request.urlopen(url + css_url) as response:
                css = response.read().decode()
            assert not re.search(r"url\([\"']?data:.*?(?:font|woff)", css), "CSP-incompatible embedded font"

            # The helper must discover the existing project when invoked by
            # deploy.sh (which uses the project name resolved by Compose).
            env = {**os.environ, "COMPOSE_PROJECT_NAME": identity, "RELAYPANEL_BACKUP_DIR": str(directory / "backups"),
                   "DATABASE_URL": "sqlite:/wrong-new-config.db?mode=rwc"}
            run([sys.executable, str(ROOT / "scripts/backup-before-upgrade.py"), str(compose_file)], cwd=directory, env=env)
            snapshots = list((directory / "backups").glob("*/manifest.json"))
            assert len(snapshots) == 1
            snapshot = snapshots[0].parent
            assert json.loads(snapshots[0].read_text())["backend"] == "sqlite"
            with closing(sqlite3.connect(snapshot / "data/data.db")) as conn, conn:
                assert conn.execute("SELECT balance,traffic_used,traffic_limit FROM users WHERE id=1").fetchone() == ("123.45", 456, 10000)
                assert conn.execute("SELECT COUNT(*) FROM balance_ledger WHERE user_id=1").fetchone() == (1,)
            # Restore the snapshot into the stopped volume, then restart the
            # same candidate. Existing WAL/SHM are part of the copied directory.
            container = subprocess.check_output(compose + ["ps", "-a", "-q", "panel"], text=True).strip()
            run(["docker", "cp", str(snapshot / "data") + "/.", container + ":/app/data/"])
            start()
            # A valid SQLx path with traversal is deliberately outside the
            # helper's automatic-backup policy. Rejection happens AFTER stop;
            # prove the helper restarts the exact old container by itself.
            compose_file.write_text(compose_file.read_text().replace("      GEOIP_ENABLED: 'false'",
                "      GEOIP_ENABLED: 'false'\n      DATABASE_URL: 'sqlite:/app/data/../data/data.db?mode=rwc'"))
            url, _ = start()
            original = subprocess.check_output(compose + ["ps", "-a", "-q", "panel"], text=True).strip()
            rejected = subprocess.run([sys.executable, str(ROOT / "scripts/backup-before-upgrade.py"), str(compose_file)],
                cwd=directory, env=env, capture_output=True, text=True)
            assert rejected.returncode != 0 and "custom SQLite paths" in rejected.stderr, rejected.stderr
            assert subprocess.check_output(["docker", "inspect", "--format", "{{.State.Running}}", original], text=True).strip() == "true"
            assert subprocess.check_output(compose + ["ps", "-a", "-q", "panel"], text=True).strip() == original
            # Docker reallocates an ephemeral published port even when starting
            # the SAME container. Discover it again without starting/recreating
            # anything: doing that here would mask a failed helper recovery.
            recovered_binding = subprocess.check_output(compose + ["port", "panel", "18888"], text=True).strip()
            recovered_url, recovered_health = wait_health("http://" + recovered_binding)
            assert recovered_health["version"] == version, recovered_health
            if recovered_url != url:
                print(f"Recovered original container; ephemeral binding changed: {url} -> {recovered_url}")
            assert len(list((directory / "backups").glob("*/manifest.json"))) == 1
            print(f"PASS: candidate {version} image, uid 10001, root-owned volume upgrade, CSP fonts, actual-db backup, restore, rejected backup restores exact old container")
        finally:
            subprocess.run(compose + ["down"], check=False, stdout=subprocess.DEVNULL)
            subprocess.run(["docker", "rm", "-f", seed], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "volume", "rm", volume], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
