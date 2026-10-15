#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('privacy_check', Path(__file__).resolve().parents[1] / 'scripts/check-sensitive-files.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class PrivacyCheckTests(unittest.TestCase):
    def test_private_state_names(self):
        for name in ['.env', '.env.production', 'HANDOFF-local.md', 'id_ed25519',
                     'database.sqlite3', 'database.dump', 'backup.sql.gz', 'private.pem',
                     'config-cache.json', 'node-id', 'traffic-outbox-example.json']:
            with self.subTest(name=name):
                self.assertTrue(CHECK.inspect(name, b''))

    def test_source_and_examples_are_allowed(self):
        for name in ['.env.example', '.env.production.example', 'schema.sql', 'src/main.rs']:
            with self.subTest(name=name):
                self.assertFalse(CHECK.inspect(name, b''))

    def test_database_signature(self):
        self.assertTrue(CHECK.inspect('renamed.dat', b'SQLite format 3\0'))

    def test_private_key_signature(self):
        marker = b'-----BEGIN ' + b'OPENSSH PRIVATE KEY-----'
        self.assertTrue(CHECK.inspect('renamed.txt', marker))

    def test_documentation_and_generic_networks(self):
        for address in ['203.0.113.93', '192.0.2.1', '198.51.100.2', '127.0.0.1', '10.0.0.1', '8.8.8.8']:
            with self.subTest(address=address):
                self.assertFalse(CHECK.inspect('example.rs', address.encode()))

    def test_unapproved_public_address_is_not_echoed(self):
        # Construct a public address rather than publishing an operational IP.
        address = '.'.join(map(str, [8, 7, 6, 5]))
        issues = CHECK.inspect('example.rs', address.encode())
        self.assertTrue(issues)
        self.assertNotIn(address, str(issues))


if __name__ == '__main__':
    unittest.main()
