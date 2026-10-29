import base64
import contextlib
import hashlib
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import plistlib
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import official_auth_anisette_adapter as adapter


class OfficialAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'isolated.plist'
        self.identity = {'client_info': '<TestMac> <macOS;27.0> <com.apple.akd/1.0>',
                         'user_agent': 'synthetic-agent'}
        self.state = {'keychain_identifier': b'x' * 16, 'adi_pb': b'synthetic-adi',
                      'provider_url': 'https://example.invalid',
                      'provisioned_client_info': self.identity['client_info'],
                      'provisioned_user_agent': self.identity['user_agent']}
        self.save()
        self.before = self.path.read_bytes()
        self.provider = adapter.IsolatedProvider(self.path, 'https://example.invalid')

    def save(self):
        self.path.write_bytes(plistlib.dumps(self.state))

    def tearDown(self):
        self.tmp.cleanup()

    def fake_exchange(self, request):
        if request.full_url.endswith('/client_info'):
            return dict(self.identity)
        self.request = request
        return {'X-Apple-I-MD-M': 'synthetic-machine', 'X-Apple-I-MD': 'synthetic-otp',
                'X-Apple-I-MD-RINFO': '1'}

    def test_fresh_and_resync_wire_with_immutable_state_and_matched_identity(self):
        with patch.object(adapter, 'exchange', side_effect=self.fake_exchange):
            for sim in (None, 'synthetic-sim'):
                result = self.provider.headers(sim)
                self.assertEqual(result['X-MMe-Client-Info'], result['provisionedClientInfo'])
                self.assertEqual(result['authenticationUserAgent'], result['provisionedUserAgent'])
                self.assertEqual(self.request.get_header('User-agent'), self.identity['user_agent'])
                body = json.loads(self.request.data)
                self.assertEqual(base64.b64decode(body['adi_pb']), self.state['adi_pb'])
                self.assertEqual('sim' in body, sim is not None)
                if sim:
                    self.assertEqual(body['sim'], sim)
                    self.assertEqual(body['device_id'], result['X-Mme-Device-Id'])
                    self.assertEqual(body['md_lu'], hashlib.sha256(b'x'*16).hexdigest())
        self.assertEqual(self.before, self.path.read_bytes())

    def test_provider_drift_or_missing_record_fails_without_provisioning(self):
        with patch.object(adapter, 'exchange', return_value={'client_info': 'wrong', 'user_agent': 'wrong'}) as exchange:
            with self.assertRaises(ValueError): self.provider.headers()
            self.assertEqual(exchange.call_count, 1)
        del self.state['provisioned_user_agent']
        self.save()
        with patch.object(adapter, 'exchange') as exchange:
            with self.assertRaises(ValueError): self.provider.headers()
            exchange.assert_not_called()

    def test_explicit_recorded_identity_mode_never_rewrites_it(self):
        self.provider.identity_source = 'provisioned'
        def exchange(request):
            if request.full_url.endswith('/client_info'):
                return {'client_info': 'obsolete-advertisement', 'user_agent': 'obsolete'}
            return self.fake_exchange(request)
        with patch.object(adapter, 'exchange', side_effect=exchange):
            result = self.provider.headers()
        self.assertEqual(result['X-MMe-Client-Info'], self.identity['client_info'])
        self.assertEqual(self.before, self.path.read_bytes())

    def test_failure_redacts_http_state_and_resync_values(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), adapter.Handler)
        server.provider = self.provider
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(adapter, 'exchange', side_effect=ValueError('PRIVATE-ACCOUNT')):
                for request in (Request('http://127.0.0.1:%d/' % server.server_port),
                    Request('http://127.0.0.1:%d/resync' % server.server_port,
                            data=json.dumps({'sim': 'PRIVATE-SIM'}).encode())):
                    with self.assertRaises(HTTPError) as caught: urlopen(request)
                    self.assertEqual(caught.exception.code, 502)
                    body = caught.exception.read().decode()
                    self.assertNotIn('PRIVATE', body)
                    self.assertIn('no-store', caught.exception.headers['Cache-Control'])
            with patch.object(self.provider, 'headers') as headers:
                request = Request('http://127.0.0.1:%d/resync' % server.server_port,
                                  data=b'{"sim":null}')
                with self.assertRaises(HTTPError) as caught: urlopen(request)
                self.assertEqual(caught.exception.code, 400)
                headers.assert_not_called()
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_verified_tls_no_redirects_and_no_retry(self):
        context = ssl.create_default_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertIsNone(adapter.NoRedirect().redirect_request(None,None,302,'',{},'https://other.invalid'))
        with patch.object(adapter, 'build_opener') as build, patch.object(adapter.ssl, 'create_default_context', return_value=context):
            build.return_value.open.side_effect = HTTPError('https://example.invalid',503,'PRIVATE',{},io.BytesIO())
            with self.assertRaises(HTTPError): adapter.exchange(Request('https://example.invalid'))
            self.assertEqual(build.return_value.open.call_count, 1)

    def test_unsafe_provider_or_bad_sim_rejected(self):
        for url in ('http://example.invalid','https://user:pass@example.invalid','https://example.invalid/?secret=1'):
            with self.assertRaises(ValueError): adapter.IsolatedProvider(self.path,url)
        with patch.object(adapter, 'exchange', return_value=self.identity):
            for sim in ('', 'x'*65537, 1):
                with self.assertRaises(ValueError): self.provider.headers(sim)


if __name__ == '__main__':
    unittest.main()
