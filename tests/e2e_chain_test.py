#!/usr/bin/env python3
"""
Multi-hop chain end-to-end test (local, no remote servers).

Topology (3 processes on loopback):
  client → entry-node(:CHAIN_ENTRY_PORT)
         → exit-node(:auto hop port)
         → echo target(:ECHO_PORT)

Optional mid hop when MID=1:
  entry → mid → exit → echo

Requires: cargo build -p relay-panel -p relay-node
Exit 0 on success.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E2E_PROFILE = os.environ.get("RELAY_E2E_PROFILE", "debug")
if E2E_PROFILE not in ("debug", "release"):
    raise ValueError("RELAY_E2E_PROFILE must be 'debug' or 'release'")
PANEL_BIN = os.path.join(PROJECT_ROOT, "target", E2E_PROFILE, "relay-panel")
NODE_BIN = os.path.join(PROJECT_ROOT, "target", E2E_PROFILE, "relay-node")
if sys.platform == "win32":
    PANEL_BIN += ".exe"
    NODE_BIN += ".exe"

BASE_URL = "http://127.0.0.1:18889/api/v1"


def config_protocol_version():
    """Read the shared wire version so the E2E gate cannot drift."""
    source_path = os.path.join(
        PROJECT_ROOT, "crates", "shared", "src", "protocol.rs"
    )
    with open(source_path, encoding="utf-8") as source:
        match = re.search(
            r"pub const CONFIG_PROTOCOL_VERSION:\s*u32\s*=\s*(\d+)\s*;",
            source.read(),
        )
    if match is None:
        raise AssertionError("CONFIG_PROTOCOL_VERSION constant not found")
    return match.group(1)


CONFIG_PROTOCOL_VERSION = config_protocol_version()
ECHO_PORT = 18881
CHAIN_ENTRY_PORT = 19001
UDP_CHAIN_ENTRY_PORT = 19002
TCPUDP_CHAIN_ENTRY_PORT = 19003
ADMIN_PW = "admin-chain-e2e-pass-1"


def api(method, path, token=None, body=None, extra_headers=None, timeout=15):
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def wait_for_port(host, port, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                break
            self.request.sendall(data)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class ReusableThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


def start_echo():
    tcp = ReusableThreadingTCPServer(("127.0.0.1", ECHO_PORT), TCPHandler)
    try:
        udp = ReusableThreadingUDPServer(("127.0.0.1", ECHO_PORT), UDPHandler)
    except Exception:
        tcp.server_close()
        raise
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    print(f"[echo] TCP+UDP :{ECHO_PORT}")
    return [tcp, udp]


def tcp_roundtrip(port, payload, timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                b = s.recv(8192)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            if sum(len(c) for c in chunks) >= len(payload):
                break
        return b"".join(chunks)


def udp_roundtrip(port, payload, timeout=8):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, ("127.0.0.1", port))
        data, peer = sock.recvfrom(65535)
        assert peer[1] == port, peer
        return data


def wait_for_node_config(node_token, predicate, timeout=45):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = api(
                "GET",
                "/node/config",
                token=node_token,
                extra_headers={"X-Config-Protocol-Version": CONFIG_PROTOCOL_VERSION},
            )
            if predicate(last):
                return last
        except Exception:
            pass
        time.sleep(1)
    raise AssertionError(f"node config did not reach expected state: {last}")


def main():
    assert os.path.isfile(PANEL_BIN), f"missing {PANEL_BIN}; run cargo build first"
    assert os.path.isfile(NODE_BIN), f"missing {NODE_BIN}; run cargo build first"

    work = tempfile.mkdtemp(prefix="relay-chain-e2e-")
    db = os.path.join(work, "data.db")
    procs = []
    process_logs = []
    echo = None

    def open_process_log(name):
        path = os.path.join(work, f"{name}.log")
        handle = open(path, "wb")
        process_logs.append((name, path, handle))
        return handle

    try:
        echo = start_echo()
        assert wait_for_port("127.0.0.1", ECHO_PORT, 5)

        panel_env = dict(
            os.environ,
            LISTEN="127.0.0.1:18889",
            DATABASE_URL=f"sqlite:{db}?mode=rwc",
            RUST_LOG="info",
            REGISTRATION_ENABLED="1",
        )
        panel = subprocess.Popen(
            [PANEL_BIN],
            env=panel_env,
            cwd=work,
            stdout=open_process_log("panel"),
            stderr=subprocess.STDOUT,
        )
        procs.append(panel)
        print(f"[panel] PID {panel.pid}")
        assert wait_for_port("127.0.0.1", 18889), "panel did not start"

        r = api("POST", "/auth/login", body={"username": "admin", "password": "admin123"})
        assert r["code"] == 0, r
        token = r["data"]["token"]
        chg = api(
            "PUT",
            "/user/password",
            token,
            {"current_password": "admin123", "new_password": ADMIN_PW},
        )
        assert chg["code"] == 0, chg
        r = api("POST", "/auth/login", body={"username": "admin", "password": ADMIN_PW})
        assert r["code"] == 0, r
        token = r["data"]["token"]
        print("[ok] admin ready")

        # Groups: entry (in) + exit (out). Optional mid.
        with_mid = os.environ.get("CHAIN_MID", "0") == "1"

        entry_g = api(
            "POST",
            "/groups",
            token,
            {
                "name": "chain-entry",
                "group_type": "in",
                "connect_host": "127.0.0.1",
                "port_range": "19000-19999",
            },
        )
        assert entry_g["code"] == 0, entry_g
        entry_id = entry_g["data"]["id"]
        entry_token = entry_g["data"]["token"]

        hop_ids = [entry_id]
        mid_token = None
        if with_mid:
            mid_g = api(
                "POST",
                "/groups",
                token,
                {
                    "name": "chain-mid",
                    "group_type": "out",
                    "connect_host": "127.0.0.1",
                    "port_range": "20000-20999",
                },
            )
            assert mid_g["code"] == 0, mid_g
            hop_ids.append(mid_g["data"]["id"])
            mid_token = mid_g["data"]["token"]

        exit_g = api(
            "POST",
            "/groups",
            token,
            {
                "name": "chain-exit",
                "group_type": "out",
                "connect_host": "127.0.0.1",
                "port_range": "21000-21999",
            },
        )
        assert exit_g["code"] == 0, exit_g
        hop_ids.append(exit_g["data"]["id"])
        exit_token = exit_g["data"]["token"]
        print(f"[ok] groups hops={hop_ids} mid={with_mid}")

        rule = api(
            "POST",
            "/rules",
            token,
            {
                "name": "chain-rule",
                "listen_port": CHAIN_ENTRY_PORT,
                "protocol": "tcp",
                "device_group_in": entry_id,
                "forward_mode": "chain",
                "route_mode": "chain",
                "hops": hop_ids,
                "target_addr": "127.0.0.1",
                "target_port": ECHO_PORT,
                "public_transport": "raw",
            },
        )
        assert rule["code"] == 0, rule

        udp_rule = api(
            "POST",
            "/rules",
            token,
            {
                "name": "udp-chain-rule",
                "listen_port": UDP_CHAIN_ENTRY_PORT,
                "protocol": "udp",
                "device_group_in": entry_id,
                "forward_mode": "chain",
                "route_mode": "chain",
                "hops": hop_ids,
                "target_addr": "127.0.0.1",
                "target_port": ECHO_PORT,
                "public_transport": "raw",
            },
        )
        assert udp_rule["code"] == 0, udp_rule

        tcpudp_rule = api(
            "POST",
            "/rules",
            token,
            {
                "name": "tcpudp-chain-rule",
                "listen_port": TCPUDP_CHAIN_ENTRY_PORT,
                "protocol": "tcp_udp",
                "device_group_in": entry_id,
                "forward_mode": "chain",
                "route_mode": "chain",
                "hops": hop_ids,
                "target_addr": "127.0.0.1",
                "target_port": ECHO_PORT,
                "public_transport": "raw",
            },
        )
        assert tcpudp_rule["code"] == 0, tcpudp_rule

        rules = {r["name"]: r for r in api("GET", "/rules", token)["data"]}
        chain = rules["chain-rule"]
        assert chain["route_mode"] == "chain", chain
        assert len(chain.get("hops") or []) == len(hop_ids), chain
        hop_ports = {h["position"]: h["listen_port"] for h in chain["hops"]}
        print(f"[ok] chain rule id={chain['id']} hop_ports={hop_ports}")

        def start_node(name, node_token):
            env = dict(
                os.environ,
                PANEL_URL="http://127.0.0.1:18889",
                NODE_TOKEN=node_token,
                POLL_INTERVAL="2",
                RUST_LOG="info",
            )
            p = subprocess.Popen(
                [NODE_BIN],
                env=env,
                cwd=work,
                stdout=open_process_log(f"node-{name}"),
                stderr=subprocess.STDOUT,
            )
            procs.append(p)
            print(f"[node:{name}] PID {p.pid}")
            return p

        start_node("entry", entry_token)
        if mid_token:
            start_node("mid", mid_token)
        start_node("exit", exit_token)

        assert wait_for_port("127.0.0.1", CHAIN_ENTRY_PORT, 45), "entry listener not up"
        assert wait_for_port("127.0.0.1", TCPUDP_CHAIN_ENTRY_PORT, 45), "tcp_udp TCP entry not up"
        # Exit hop auto port should also be listening.
        exit_port = hop_ports[len(hop_ids) - 1]
        assert wait_for_port("127.0.0.1", exit_port, 20), f"exit hop :{exit_port} not up"
        print(f"[ok] listeners up entry=:{CHAIN_ENTRY_PORT} exit=:{exit_port}")

        # Verify config for entry/exit via node API gate.
        tcp_rule_id = chain["id"]
        udp_rule_id = rules["udp-chain-rule"]["id"]
        tcpudp_rule_id = rules["tcpudp-chain-rule"]["id"]
        cfg_entry = wait_for_node_config(
            entry_token,
            lambda cfg: any(
                listener["rule_id"] == udp_rule_id
                and listener["protocol"] == "udp"
                and listener.get("uot_role") == "ingress"
                and listener.get("zero_rtt") is True
                for listener in cfg["listeners"]
            )
            and any(
                listener["rule_id"] == tcpudp_rule_id
                and listener["protocol"] == "tcp"
                and listener.get("tcp_fast_open") is True
                for listener in cfg["listeners"]
            ),
        )
        assert any(l["port"] == CHAIN_ENTRY_PORT for l in cfg_entry["listeners"]), cfg_entry
        entry_l = next(l for l in cfg_entry["listeners"] if l["port"] == CHAIN_ENTRY_PORT)
        assert entry_l.get("count_traffic", True) is True
        # entry targets next hop host:port
        assert entry_l["targets"], entry_l
        print(f"[ok] entry config targets={entry_l['targets']} count_traffic=true")

        cfg_exit = wait_for_node_config(
            exit_token,
            lambda cfg: any(
                listener["rule_id"] == udp_rule_id
                and listener["protocol"] == "uot"
                and listener.get("uot_role") == "egress"
                for listener in cfg["listeners"]
            )
            and any(
                listener["rule_id"] == tcpudp_rule_id
                and listener["protocol"] == "uot"
                and listener.get("uot_role") == "egress"
                for listener in cfg["listeners"]
            ),
        )
        exit_l = next(
            l
            for l in cfg_exit["listeners"]
            if l["rule_id"] == tcp_rule_id and l["port"] == exit_port
        )
        assert exit_l["targets"] == [f"127.0.0.1:{ECHO_PORT}"], exit_l
        assert exit_l.get("count_traffic", True) is False
        print("[ok] exit config targets final echo, count_traffic=false")

        payload = b"chain-e2e-" + b"Z" * 1500 + b"\n"
        resp = tcp_roundtrip(CHAIN_ENTRY_PORT, payload)
        assert resp == payload, f"TCP chain mismatch got={resp[:40]!r} len={len(resp)}"
        print(f"[ok] TCP chain forwarded {len(payload)} bytes entry→…→exit→echo")

        udp_payload = b"uot-chain-e2e-" + bytes(range(256)) * 4
        udp_resp = udp_roundtrip(UDP_CHAIN_ENTRY_PORT, udp_payload)
        assert udp_resp == udp_payload, f"UOT UDP mismatch len={len(udp_resp)}"
        print(f"[ok] UDP chain forwarded {len(udp_payload)} bytes through authenticated warm UOT")

        mixed_tcp = b"tcpudp-tcp-" + b"T" * 1024
        assert tcp_roundtrip(TCPUDP_CHAIN_ENTRY_PORT, mixed_tcp) == mixed_tcp
        mixed_udp = b"tcpudp-uot-" + b"U" * 1024
        assert udp_roundtrip(TCPUDP_CHAIN_ENTRY_PORT, mixed_udp) == mixed_udp
        print("[ok] tcp_udp chain forwarded raw TCP (TFO-enabled) and UDP-over-UOT")

        # Traffic should accrue on the rule (entry hop only).
        time.sleep(6)
        rules = {r["name"]: r for r in api("GET", "/rules", token)["data"]}
        used = rules["chain-rule"]["traffic_used"]
        assert used > 0, f"expected traffic_used > 0, got {used}"
        assert rules["udp-chain-rule"]["traffic_used"] > 0
        assert rules["tcpudp-chain-rule"]["traffic_used"] > 0
        # Rough upper bound: not multiplied by hop count (upload+download ~ 2x payload)
        # Allow generous slack for protocol overhead / multiple reports.
        assert used < len(payload) * 10, f"traffic suspiciously high (multi-count?): {used}"
        print(f"[ok] traffic_used={used}B (single-count sanity)")

        print("\n=== CHAIN E2E PASSED ===")
        return 0
    except Exception as e:
        print(f"\n=== CHAIN E2E FAILED: {e} ===", file=sys.stderr)
        # Each child writes to a file instead of an unread PIPE, which avoids
        # deadlocking when verbose logs exceed the operating system pipe buffer.
        for name, path, handle in process_logs:
            try:
                handle.flush()
                with open(path, "rb") as log:
                    out = log.read()
                if out:
                    print(
                        f"--- {name} log tail ---\n"
                        + out.decode("utf-8", errors="replace")[-4000:],
                        file=sys.stderr,
                    )
            except OSError:
                pass
        return 1
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                    p.wait(timeout=3)
                except Exception:
                    pass
        for _, _, handle in process_logs:
            try:
                handle.close()
            except Exception:
                pass
        if echo is not None:
            for server in echo:
                try:
                    server.shutdown()
                    server.server_close()
                except Exception:
                    pass
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
