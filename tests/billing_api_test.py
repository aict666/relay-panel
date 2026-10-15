#!/usr/bin/env python3
"""Exercise the real HTTP charging workflow in an isolated SQLite instance.

--serve keeps the synthetic fixture alive for a browser smoke test; SIGTERM
shuts it down and removes only the temporary fixture. Never uses existing data.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "billing-test-pass-1"
ADMIN_PASSWORD = "billing-admin-pass-1"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    binary = Path(os.environ.get("RELAY_PANEL_BIN", target / "debug/relay-panel"))
    with tempfile.TemporaryDirectory(prefix="relay-billing-api-") as temporary:
        directory = Path(temporary)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        env = {**os.environ, "DATABASE_URL": f"sqlite:{directory / 'data.db'}?mode=rwc", "LISTEN": f"127.0.0.1:{port}",
               "JWT_SECRET": "synthetic-billing-api-test-secret-32-bytes", "GEOIP_ENABLED": "false",
               "PUBLIC_DIR": str(ROOT / "frontend/dist")}
        with open(directory / "panel.log", "wb") as log:
            process = subprocess.Popen([str(binary)], cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            def api(method, path, token=None, body=None, code=0, status=200):
                request = urllib.request.Request(base + "/api/v1" + path,
                    data=json.dumps(body).encode() if body is not None else None, method=method,
                    headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
                try:
                    response = urllib.request.urlopen(request, timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    raw = response.read()
                    if "application/json" in response.headers.get("Content-Type", ""):
                        result = json.loads(raw)
                    else:
                        assert response.status >= 400, "success must use the API envelope"
                        result = {"code": response.status, "data": None}
                    assert response.status == status and result["code"] == code, (method, path, response.status, result)
                return result.get("data")

            for _ in range(200):
                if process.poll() is not None:
                    raise AssertionError("synthetic panel failed to start")
                text = (directory / "panel.log").read_text(errors="replace")
                credential = re.search(r"密码:\s*([0-9a-f]{32})", text)
                if credential:
                    try:
                        urllib.request.urlopen(base + "/api/v1/health", timeout=1).close()
                        break
                    except OSError:
                        pass
                time.sleep(0.1)
            else:
                raise AssertionError("synthetic panel health timeout")
            admin = api("POST", "/auth/login", body={"username": "admin", "password": credential.group(1)})["token"]
            api("PUT", "/user/password", admin, {"current_password": credential.group(1), "new_password": ADMIN_PASSWORD})
            admin = api("POST", "/auth/login", body={"username": "admin", "password": ADMIN_PASSWORD})["token"]
            notice = api("POST", "/admin/announcements", admin, {"content": "expired timestamp fixture", "expires_at": "2000-9-1 00:00:00"})
            assert api("GET", "/admin/announcements", admin)["items"][0]["expires_at"] == "2000-09-01 00:00:00"
            assert api("GET", "/user/announcements/active", admin) is None
            api("PUT", f"/admin/announcements/{notice}", admin, {"content": "edited fixture", "expires_at": "2000-8-1 00:00:00"})
            assert api("GET", "/admin/announcements", admin)["items"][0]["expires_at"] == "2000-08-01 00:00:00"
            group = api("POST", "/groups", admin, {"name": "Billing test line", "group_type": "in", "connect_host": "127.0.0.1", "port_range": "20000-30000"})
            plan = api("POST", "/admin/plans", admin, {"name": "Monthly billing fixture", "max_rules": 3, "traffic": 1000,
                "price": "10", "plan_type": "monthly", "duration_days": 30, "reset_traffic": True, "device_group_ids": [group["id"]]})
            pid = plan
            api("PUT", "/admin/settings/registration", admin, {"enabled": True, "default_plan_id": pid, "allowed_plan_ids": [pid]})
            for name in ("billing_user", "other_user"):
                api("POST", "/auth/register", body={"username": name, "password": PASSWORD, "plan_id": pid})
            buyer = api("POST", "/auth/login", body={"username": "billing_user", "password": PASSWORD})["token"]
            other = api("POST", "/auth/login", body={"username": "other_user", "password": PASSWORD})["token"]
            me = api("GET", "/user/me", buyer)
            uid = me["id"]
            assert me["account_status"] == "pending" and me["plan_id"] is None and not me["available_groups"], me
            api("GET", "/user/balance-ledger", code=401, status=401)
            api("GET", f"/admin/users/{uid}/balance-ledger", other, code=403, status=403)
            assert api("GET", f"/user/balance-ledger?user_id={uid}", other) == []
            api("POST", "/user/buy-plan", buyer, {"plan_id": pid}, code=400)
            api("PUT", "/user/plan/auto-renew", buyer, {"enabled": True}, code=400)
            codes = api("POST", "/admin/redeem-codes", admin, {"count": 1, "amount": "100"})
            api("POST", "/user/redeem", buyer, {"code": codes["codes"][0]})
            api("POST", "/user/redeem", buyer, {"code": codes["codes"][0]}, code=400)
            catalog = next(item for item in api("GET", "/plans", buyer) if item["id"] == pid)
            intent = {"plan_id": pid, "request_id": "api-confirmed-purchase", "expected_current_plan_id": 0,
                      "expected_price": catalog["price"], "expected_revision": catalog["purchase_revision"], "auto_renew": False}
            with ThreadPoolExecutor(max_workers=2) as executor:
                list(executor.map(lambda _: api("POST", "/user/buy-plan", buyer, intent), range(2)))
            me = api("GET", "/user/me", buyer)
            assert me["balance"] == "90" and me["account_status"] == "active" and me["prepaid_cycles"] == 0
            assert me["available_groups"] == [group["name"]]
            api("POST", "/user/buy-plan", buyer, {**intent, "auto_renew": True}, code=409)
            api("POST", "/rules", buyer, {"name": "Billing usage fixture", "listen_port": 21001,
                "protocol": "tcp", "device_group_in": group["id"], "forward_mode": "direct", "target_addr": "127.0.0.1", "target_port": 8080})
            rule = api("GET", "/rules", buyer)[0]
            report = {"batch_id": "api-traffic-batch", "reports": [{"rule_id": rule["id"], "upload": 300, "download": 200}]}
            api("POST", "/node/report_traffic", group["token"], report)
            api("POST", "/node/report_traffic", group["token"], report)
            assert api("GET", "/user/me", buyer)["traffic_used"] == 500
            future = {**intent, "request_id": "api-prepayment", "expected_current_plan_id": pid}
            api("POST", "/user/buy-plan", buyer, future)
            me = api("GET", "/user/me", buyer)
            assert me["balance"] == "80" and me["traffic_used"] == 500 and me["prepaid_cycles"] == 1
            api("PUT", f"/admin/users/{uid}/plan", admin, {"expected_plan_id": pid, "clear": True}, code=409)
            api("PUT", f"/admin/users/{uid}", admin, {"balance": "100", "expected_balance": "90", "max_rules": 1}, code=409)
            assert api("GET", "/user/me", buyer)["max_rules"] == 3
            api("PUT", f"/admin/users/{uid}", admin, {"balance": "85", "expected_balance": "80"})
            ledger = api("GET", "/user/balance-ledger", buyer)
            assert [entry["kind"] for entry in ledger] == ["admin_adjustment", "prepayment", "purchase", "redeem", "opening"], ledger
            assert sum(entry["amount_cents"] for entry in ledger) == 8500
            assert api("GET", f"/admin/users/{uid}/balance-ledger", admin) == ledger
            assert api("GET", "/user/balance-ledger?limit=1&offset=1", buyer) == ledger[1:2]
            assert api("GET", f"/user/balance-ledger?user_id={uid}", other) == []
            api("PUT", f"/admin/plans/{pid}", admin, {"hidden": True, "price": "20", "traffic": 9999})
            api("POST", "/user/buy-plan", buyer, intent)
            api("POST", "/user/buy-plan", buyer, future)
            assert api("GET", "/user/me", buyer)["balance"] == "85"
            assert len(api("GET", "/user/orders", buyer)) == 2
            api("PUT", f"/admin/plans/{pid}", admin, {"hidden": False})
            print("PASS: HTTP registration → recharge → concurrent purchase → traffic dedup → prepayment → balance CAS → ledger permissions/pagination → hidden-product replay", flush=True)
            if args.serve:
                signal.signal(signal.SIGTERM, lambda *_: exit(0))
                print(f"Browser fixture: {base} (synthetic billing_user/admin only)", flush=True)
                signal.pause()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
