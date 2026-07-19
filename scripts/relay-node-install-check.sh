#!/usr/bin/env bash
# Hermetic regression test for relay-node-install.sh. No real /opt, systemd or
# network state is touched; command shims and override roots model an existing
# active node, a successful custom-name upgrade, and a failed upgrade rollback.
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
    echo "relay-node installer check: skipped (Linux-only installer)"
    exit 0
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHECK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/relay-node-install-check.XXXXXX")
trap 'rm -rf "$CHECK_DIR"' EXIT
MOCK_BIN="$CHECK_DIR/mock-bin"
INSTALL_ROOT="$CHECK_DIR/opt"
SYSTEMD_DIR="$CHECK_DIR/systemd"
STATE_DIR="$CHECK_DIR/state"
SERVICE_NAME="custom-node"
INSTALL_DIR="$INSTALL_ROOT/$SERVICE_NAME"
SERVICE_FILE="$SYSTEMD_DIR/$SERVICE_NAME.service"
mkdir -p "$MOCK_BIN" "$INSTALL_DIR" "$SYSTEMD_DIR" "$STATE_DIR"

cat > "$MOCK_BIN/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    -s) echo Linux ;;
    -m) echo x86_64 ;;
    *) echo Linux ;;
esac
EOF
cat > "$MOCK_BIN/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ]; then echo 0; else /usr/bin/id "$@"; fi
EOF
cat > "$MOCK_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output="$2"; shift 2 ;;
        http://*|https://*) url="$1"; shift ;;
        *) shift ;;
    esac
done
[ -n "$output" ] || exit 2
if [[ "$url" == *.sha256 ]]; then
    [ "${MOCK_CHECKSUM_MISSING:-0}" != "1" ] || exit 22
    sha256sum "$MOCK_DOWNLOAD_BINARY" | awk '{print $1 "  relay-node"}' > "$output"
else
    cp "$MOCK_DOWNLOAD_BINARY" "$output"
fi
EOF
cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
command_name="${1:-}"
service_name="${*: -1}"
service_name="${service_name%.service}"
case "$command_name" in
    cat)
        [ -f "$MOCK_SYSTEMD_DIR/${service_name}.service" ]
        ;;
    is-active)
        [ -f "$MOCK_STATE_DIR/active" ]
        ;;
    is-enabled)
        [ -f "$MOCK_STATE_DIR/enabled" ]
        ;;
    stop)
        rm -f "$MOCK_STATE_DIR/active"
        ;;
    restart)
        count=0
        [ ! -f "$MOCK_STATE_DIR/restart-count" ] || count=$(cat "$MOCK_STATE_DIR/restart-count")
        count=$((count + 1))
        echo "$count" > "$MOCK_STATE_DIR/restart-count"
        if [ "${MOCK_FAIL_FIRST_RESTART:-0}" = "1" ] && [ "$count" = "1" ]; then
            exit 1
        fi
        : > "$MOCK_STATE_DIR/active"
        ;;
    show)
        [ -f "$MOCK_STATE_DIR/active" ] && echo 4242 || echo 0
        ;;
    enable)
        : > "$MOCK_STATE_DIR/enabled"
        ;;
    disable)
        rm -f "$MOCK_STATE_DIR/enabled"
        ;;
    daemon-reload|status)
        ;;
    *)
        echo "unexpected systemctl command: $*" >&2
        exit 2
        ;;
esac
EOF
cat > "$MOCK_BIN/journalctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$MOCK_BIN"/*

TARGET_VERSION=$(/bin/bash --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)

seed_old_install() {
    rm -rf "$INSTALL_DIR" "$SYSTEMD_DIR" "$STATE_DIR"
    mkdir -p "$INSTALL_DIR" "$SYSTEMD_DIR" "$STATE_DIR"
    cp /bin/ls "$INSTALL_DIR/relay-node"
    chmod +x "$INSTALL_DIR/relay-node"
    printf '%s\n' 'old-start-script' > "$INSTALL_DIR/start.sh"
    printf '%s\n' 'old-service-file' > "$SERVICE_FILE"
    : > "$STATE_DIR/active"
    : > "$STATE_DIR/enabled"
}

run_installer() {
    local requested_service="${1:-$SERVICE_NAME}"
    PATH="$MOCK_BIN:$PATH" \
    MOCK_DOWNLOAD_BINARY=/bin/bash \
    MOCK_SYSTEMD_DIR="$SYSTEMD_DIR" \
    MOCK_STATE_DIR="$STATE_DIR" \
    MOCK_FAIL_FIRST_RESTART="${MOCK_FAIL_FIRST_RESTART:-0}" \
    MOCK_CHECKSUM_MISSING="${MOCK_CHECKSUM_MISSING:-0}" \
    RELAY_NODE_INSTALL_ROOT="$INSTALL_ROOT" \
    RELAY_NODE_SYSTEMD_DIR="$SYSTEMD_DIR" \
    RELAY_NODE_BASE_URL="https://mirror.invalid/relay-panel" \
    RELAY_NODE_CHECKSUM_URL="https://checksums.invalid/relay-node.sha256" \
    bash "$ROOT_DIR/scripts/relay-node-install.sh" \
        --service-name "$requested_service" \
        --token 'token-with-&-characters' \
        --url 'https://panel.invalid/api?x=1&y=2' \
        --version "$TARGET_VERSION"
}

seed_old_install
if run_installer '..' >/dev/null 2>&1; then
    echo "installer accepted a path-like service name" >&2
    exit 1
fi
cmp -s /bin/ls "$INSTALL_DIR/relay-node"
grep -Fx 'old-start-script' "$INSTALL_DIR/start.sh" >/dev/null
echo "[ok] unsafe service names are rejected before mutation"

seed_old_install
run_installer >/dev/null
cmp -s /bin/bash "$INSTALL_DIR/relay-node"
grep -F "cd $INSTALL_DIR" "$INSTALL_DIR/start.sh" >/dev/null
grep -F "RELAY_NODE_DATA_DIR=$INSTALL_DIR" "$INSTALL_DIR/start.sh" >/dev/null
generated_panel=$(unset PANEL_URL; eval "$(grep '^export PANEL_URL=' "$INSTALL_DIR/start.sh")"; printf '%s' "$PANEL_URL")
generated_token=$(unset NODE_TOKEN; eval "$(grep '^export NODE_TOKEN=' "$INSTALL_DIR/start.sh")"; printf '%s' "$NODE_TOKEN")
[ "$generated_panel" = 'https://panel.invalid/api?x=1&y=2' ]
[ "$generated_token" = 'token-with-&-characters' ]
[ -f "$STATE_DIR/active" ]
[ ! -e "$INSTALL_DIR/relay-node.rollback" ]
echo "[ok] custom service name + safe generated paths"

seed_old_install
rm -f "$STATE_DIR/enabled"
if MOCK_FAIL_FIRST_RESTART=1 run_installer >/dev/null 2>&1; then
    echo "installer unexpectedly succeeded when the service restart failed" >&2
    exit 1
fi
cmp -s /bin/ls "$INSTALL_DIR/relay-node"
grep -Fx 'old-start-script' "$INSTALL_DIR/start.sh" >/dev/null
grep -Fx 'old-service-file' "$SERVICE_FILE" >/dev/null
[ -f "$STATE_DIR/active" ]
[ ! -e "$STATE_DIR/enabled" ]
echo "[ok] failed upgrade restored binary, start script and service"

rm -rf "$INSTALL_DIR" "$STATE_DIR"
rm -f "$SERVICE_FILE"
mkdir -p "$STATE_DIR"
if MOCK_FAIL_FIRST_RESTART=1 run_installer >/dev/null 2>&1; then
    echo "fresh installer unexpectedly succeeded when restart failed" >&2
    exit 1
fi
[ ! -e "$INSTALL_DIR/relay-node" ]
[ ! -e "$INSTALL_DIR/start.sh" ]
[ ! -e "$INSTALL_DIR/relay-node.env" ]
[ ! -e "$SERVICE_FILE" ]
[ ! -d "$INSTALL_DIR" ]
[ ! -e "$STATE_DIR/active" ]
[ ! -e "$STATE_DIR/enabled" ]
echo "[ok] failed fresh install removed its files and service state"

seed_old_install
if MOCK_CHECKSUM_MISSING=1 run_installer >/dev/null 2>&1; then
    echo "installer accepted a mirror download without a trusted checksum" >&2
    exit 1
fi
cmp -s /bin/ls "$INSTALL_DIR/relay-node"
grep -Fx 'old-start-script' "$INSTALL_DIR/start.sh" >/dev/null
echo "[ok] mirror checksum is mandatory and failure is non-destructive"

echo "relay-node installer checks passed"
