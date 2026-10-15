#!/usr/bin/env python3
"""Reject private state files, private keys and non-example public IPv4 literals."""
import fnmatch
import ipaddress
from pathlib import Path
import re
import subprocess
import sys

PRIVATE_NAMES = (
    '.env', '*.pem', '*.key', '*.p12', '*.pfx', 'id_rsa', 'id_ed25519', 'id_ecdsa',
    '*.db', '*.db-*', '*.sqlite', '*.sqlite3', '*.sqlite-*', '*.sqlite3-*',
    '*.dump', '*.sql.gz', '*.backup', '*.bak', '*.log', 'HANDOFF*.md',
    'node-id', 'config-cache.json', 'traffic-outbox-*.json', 'traffic-outbox-*.lock',
    'token.txt', 'node_token.txt', 'tok.txt',
)
# Existing generic test placeholders, public DNS services and example.com.
# New examples should use RFC 5737 documentation networks instead.
PUBLIC_EXAMPLES = {
    '1.1.1.1', '1.2.3.4', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5',
    '5.6.7.8', '8.8.8.8', '9.9.9.9', '93.184.216.34',
}
IPV4 = re.compile(rb'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
PRIVATE_KEY = re.compile(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----')


def inspect(path, data):
    name = Path(path).name
    issues = []
    example = name == '.env.example' or name.endswith('.example')
    if (name.startswith('.env.') and not example) or any(fnmatch.fnmatchcase(name, pattern) for pattern in PRIVATE_NAMES):
        issues.append('private state/credential filename')
    if data.startswith(b'SQLite format 3\0'):
        issues.append('SQLite database content')
    if PRIVATE_KEY.search(data):
        issues.append('private key material')
    if Path(path).name not in ('Cargo.lock', 'package-lock.json'):
        for match in IPV4.finditer(data):
            try:
                value = match.group().decode()
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global and value not in PUBLIC_EXAMPLES:
                line = data.count(b'\n', 0, match.start()) + 1
                issues.append(f'non-example public IPv4 literal at line {line}')
    return issues


def main():
    root = Path(__file__).resolve().parents[1]
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    failures = []
    for path in filter(None, paths):
        file = root / path
        if file.is_file():
            failures.extend((path, issue) for issue in inspect(path, file.read_bytes()))
    for path, issue in failures:
        # Never echo the suspected credential or address into public CI logs.
        print(f'{path}: {issue}', file=sys.stderr)
    if failures:
        return 1
    print('Tracked-file privacy checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
