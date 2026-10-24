"""Offline checks for isolated identity preservation and cache bypass."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen
import uuid

spec = importlib.util.spec_from_file_location(
    'bridge', Path(__file__).resolve().parents[1] / 'scripts/keeper_v3_anisette_bridge.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class FreshHeadersTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'anisette_state'
        self.identifier = bytes(range(16))
        self.adi = b'private-adi-state'
        self.original = plistlib.dumps({
            'keychain_identifier': self.identifier, 'adi_pb': self.adi})
        self.state.write_bytes(self.original)
        self.identity = {'client_info': '<provider identity>', 'user_agent': 'provider-agent'}

    def headers(self, otp):
        return io.BytesIO(json.dumps({
            'X-Apple-I-MD': otp, 'X-Apple-I-MD-M': 'private-machine-id',
            'X-Apple-I-MD-RINFO': '17106176'}).encode())

    def test_each_call_posts_same_isolated_identity_without_cache(self):
        with patch.object(b, 'urlopen', side_effect=[self.headers('otp-1'), self.headers('otp-2')]) as send:
            first = b.fetch_fresh_anisette(self.state, 'https://provider.test/v3/get_headers', self.identity)
            second = b.fetch_fresh_anisette(self.state, 'https://provider.test/v3/get_headers', self.identity)
        self.assertEqual(send.call_count, 2)
        for call in send.call_args_list:
            request = call.args[0]
            self.assertEqual(request.get_method(), 'POST')
            self.assertEqual(request.get_header('User-agent'), self.identity['user_agent'])
            self.assertEqual(json.loads(request.data), {
                'identifier': base64.b64encode(self.identifier).decode(),
                'adi_pb': base64.b64encode(self.adi).decode()})
        self.assertEqual(first['X-Apple-I-MD'], 'otp-1')
        self.assertEqual(second['X-Apple-I-MD'], 'otp-2')
        self.assertEqual(first['X-Mme-Device-Id'], str(uuid.UUID(bytes=self.identifier)))
        self.assertEqual(first['X-Apple-I-MD-LU'], hashlib.sha256(self.identifier).hexdigest())
        self.assertEqual(first['X-MMe-Client-Info'], self.identity['client_info'])
        self.assertEqual(first['X-Apple-I-SRL-NO'], '2')
        self.assertEqual(self.state.read_bytes(), self.original)

    def test_rejects_bad_state_and_incomplete_provider_data(self):
        for state in [
            {'keychain_identifier': b'short', 'adi_pb': self.adi},
            {'keychain_identifier': self.identifier, 'adi_pb': b''},
        ]:
            self.state.write_bytes(plistlib.dumps(state))
            with patch.object(b, 'urlopen') as send, self.assertRaises(ValueError):
                b.fetch_fresh_anisette(self.state, 'https://provider.test/v3/get_headers', self.identity)
            send.assert_not_called()
        self.state.write_bytes(self.original)
        with patch.object(b, 'urlopen', return_value=io.BytesIO(b'{"result":"GetHeadersError","message":"private-error"}')):
            with self.assertRaises(ValueError) as caught:
                b.fetch_fresh_anisette(self.state, 'https://provider.test/v3/get_headers', self.identity)
            self.assertNotIn('private-error', str(caught.exception))
        with self.assertRaises(ValueError):
            b.fetch_fresh_anisette(self.state, 'http://provider.test/v3/get_headers', self.identity)
        with patch.object(b, 'urlopen', return_value=io.BytesIO(b'x' * 65537)):
            with self.assertRaises(ValueError):
                b.fetch_fresh_anisette(self.state, 'https://provider.test/v3/get_headers', self.identity)

    def test_http_fresh_mode_never_falls_back_to_cached_rpc(self):
        server = b.ThreadingHTTPServer(('127.0.0.1', 0), b.Handler)
        server.fresh_state_file = self.state
        server.fresh_lock = threading.Lock()
        server.provider_identity = self.identity
        server.headers_url = 'https://provider.test/v3/get_headers'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(b, 'fetch_anisette') as cached:
                with patch.object(b, 'urlopen', side_effect=[self.headers('otp-1'), self.headers('otp-2')]) as send:
                    for expected in ['otp-1', 'otp-2']:
                        with urlopen('http://127.0.0.1:' + str(server.server_port)) as result:
                            self.assertEqual(json.load(result)['X-Apple-I-MD'], expected)
                    self.assertEqual(send.call_count, 2)
                with patch.object(b, 'fetch_fresh_anisette', side_effect=ValueError('private-error')):
                    with self.assertRaises(HTTPError) as caught:
                        urlopen('http://127.0.0.1:' + str(server.server_port))
                    self.assertEqual(caught.exception.code, 502)
                    self.assertNotIn(b'private-error', caught.exception.read())
                output = io.StringIO()
                upstream = HTTPError('https://provider.test/v3/get_headers', 403,
                                     'private-error', {}, io.BytesIO(b'private-body'))
                with patch.object(b, 'fetch_fresh_anisette', side_effect=upstream), contextlib.redirect_stdout(output):
                    with self.assertRaises(HTTPError) as caught:
                        urlopen('http://127.0.0.1:' + str(server.server_port))
                    self.assertEqual(caught.exception.code, 502)
                    self.assertNotIn(b'private', caught.exception.read())
                self.assertIn('upstream HTTP 403', output.getvalue())
                self.assertNotIn('private', output.getvalue())
                self.assertNotIn('provider.test', output.getvalue())
                cached.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


if __name__ == '__main__':
    unittest.main()
