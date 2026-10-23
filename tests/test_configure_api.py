"""Validate the public API URL and the matching browser connect-src policy."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import configure_api


class ConfigureAPITests(unittest.TestCase):
    def test_https_application_base_and_exact_origin(self):
        self.assertEqual(configure_api.validate_base('https://Example.COM:8443/cyberwatch'),
                         ('https://example.com:8443/cyberwatch/', 'https://example.com:8443'))

    def test_loopback_http_for_local_development(self):
        for host in ['localhost', '127.0.0.1', '[::1]']:
            with self.subTest(host=host):
                base, origin = configure_api.validate_base(f'http://{host}:8000/')
                self.assertEqual(base, origin + '/')

    def test_credentials_non_https_and_policy_injection_rejected(self):
        for value in ['http://example.com', 'https://user:secret@example.com',
                      'https://example.com/?token=abc', 'https://example.com/#fragment',
                      'https://example.com:99999', 'javascript:alert(1)',
                      'https://example.com/../api', 'https://example.com/%2e%2e/api',
                      'https://example.com/%5capi', 'https://example.com/"',
                      "https://example.com;script-src/", 'https://exam\nple.com']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                configure_api.validate_base(value)

    def test_config_and_csp_are_updated_and_reset_together(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'dist').mkdir()
            index = root / 'dist/index.html'
            original = '<meta content="default-src \'self\'; connect-src \'self\'; img-src \'self\';">'
            index.write_text(original)
            with patch.object(configure_api, 'ROOT', root), contextlib.redirect_stdout(io.StringIO()):
                with patch('sys.argv', ['configure_api.py', 'https://feeds.example/app/']):
                    configure_api.main()
                self.assertEqual(json.loads((root / 'dist/config.json').read_text()),
                                 {'apiBase': 'https://feeds.example/app/'})
                self.assertIn("connect-src 'self' https://feeds.example;", index.read_text())
                with patch('sys.argv', ['configure_api.py', '--reset']):
                    configure_api.main()
                self.assertEqual(index.read_text(), original)
                self.assertEqual(json.loads((root / 'dist/config.json').read_text()), {'apiBase': 'auto'})

    def test_missing_policy_does_not_write_half_a_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'dist').mkdir()
            (root / 'dist/index.html').write_text('<html></html>')
            with patch.object(configure_api, 'ROOT', root), patch('sys.argv', ['configure_api.py', 'https://feeds.example/']):
                with self.assertRaises(SystemExit):
                    configure_api.main()
            self.assertFalse((root / 'dist/config.json').exists())


if __name__ == '__main__':
    unittest.main()
