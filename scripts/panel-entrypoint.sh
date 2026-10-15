#!/bin/sh
set -eu
# Root is used only to make legacy root-owned SQLite volumes upgradeable.
# The application always runs as the dedicated uid unless an operator has
# explicitly supplied another non-root --user. Never chown arbitrary DB paths.
if [ "$(id -u)" = 0 ]; then
    test ! -L /app/data || { echo 'Refusing symlink at /app/data' >&2; exit 1; }
    mkdir -p /app/data
    chown -R -h relay:relay /app/data
    exec gosu relay:relay "$@"
fi
exec "$@"
