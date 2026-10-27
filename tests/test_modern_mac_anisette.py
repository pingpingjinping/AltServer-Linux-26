"""Offline protocol, transport and rollback checks; never contact Apple or a Pi."""
import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


t = module('modern_mac_trial', SCRIPTS / 'anisette-modern-mac-trial.py')
b = t.bridge
OLD = {'client_info': '<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.akd/1.0>',
       'user_agent': 'akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0'}
CURRENT = {'client_info': b.CURRENT_MAC_CLIENT_INFO, 'user_agent': b.CURRENT_MAC_USER_AGENT}


def error(code):
    return HTTPError('https://provider.test/v3/get_headers', code, 'PRIVATE reason', {},
                     io.BytesIO(b'PRIVATE response'))


class RetryTests(unittest.TestCase):
    def test_retry_502_then_success_reuses_request_and_redacts_body(self):
        request = object()
        output = io.StringIO()
        with patch.object(b, 'urlopen', side_effect=[error(502), io.BytesIO(b'{}')]) as send, \
                patch.object(b.time, 'sleep') as sleep, redirect_stdout(output):
            self.assertEqual(b.request_headers(request), b'{}')
        self.assertEqual(send.call_count, 2)
        self.assertTrue(all(call.args[0] is request for call in send.call_args_list))
        self.assertTrue(all(0 < call.kwargs['timeout'] <= 5 for call in send.call_args_list))
        sleep.assert_called_once_with(1)
        self.assertIn('502', output.getvalue())
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_three_provider_5xx_attempts_maximum(self):
        with patch.object(b, 'urlopen', side_effect=[error(503), error(502), error(504)]) as send, \
                patch.object(b.time, 'sleep') as sleep, redirect_stdout(io.StringIO()):
            with self.assertRaises(HTTPError) as caught:
                b.request_headers(object())
        self.assertEqual(caught.exception.code, 504)
        self.assertEqual(send.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_4xx_and_transport_timeout_are_not_retried(self):
        for fail in (error(403), error(415), TimeoutError('PRIVATE')):
            with self.subTest(failure=type(fail).__name__), \
                    patch.object(b, 'urlopen', side_effect=fail) as send, \
                    patch.object(b.time, 'sleep') as sleep:
                with self.assertRaises(type(fail)):
                    b.request_headers(object())
                self.assertEqual(send.call_count, 1)
                sleep.assert_not_called()

    def test_expired_window_prevents_another_request(self):
        with patch.object(b, 'urlopen', side_effect=error(502)) as send, \
                patch.object(b.time, 'monotonic', side_effect=[0, 0, 21]), \
                patch.object(b.time, 'sleep') as sleep:
            with self.assertRaises(TimeoutError):
                b.request_headers(object())
        self.assertEqual(send.call_count, 1)
        sleep.assert_not_called()

    def test_slow_body_checks_deadline_and_size_is_bounded(self):
        with patch.object(b.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaises(TimeoutError):
                b.read_response(io.BytesIO(b'x' * 10000), deadline=20)
        with self.assertRaises(ValueError):
            b.read_response(io.BytesIO(b'x' * 65537))


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.plist'
        self.ws = Mock()
        self.ws.receive_json.side_effect = [
            {'result': 'GiveIdentifier'}, {'result': 'GiveStartProvisioningData'},
            {'result': 'GiveEndProvisioningData', 'cpim': 'private-cpim'},
            {'result': 'ProvisioningSuccess', 'adi_pb': base64.b64encode(b'private-new-adi').decode()}]
        bag = {'urls': {'midStartProvisioning': 'https://gsa.apple.com/start',
                        'midFinishProvisioning': 'https://gsa.apple.com/finish'}}
        self.responses = [bag, {'Response': {'spim': 'private-spim'}},
                          {'Response': {'ptm': 'private-ptm', 'tk': 'private-tk'}}]

    def provision(self, responses=None):
        with patch.object(b, 'ProvisioningSocket', return_value=self.ws), \
                patch.object(b, 'urlopen', side_effect=[io.BytesIO(plistlib.dumps(x))
                                                       for x in (responses or self.responses)]) as send:
            b.provision_current_mac_state(self.path, t.URL, CURRENT)
        return send

    def test_new_state_and_all_apple_calls_use_same_current_profile(self):
        send = self.provision()
        state = plistlib.loads(self.path.read_bytes())
        self.assertEqual(state['adi_pb'], b'private-new-adi')
        self.assertEqual(len(state['keychain_identifier']), 16)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(state['provisioned_client_info'], CURRENT['client_info'])
        b.validate_current_mac_state(self.path, t.URL, CURRENT)
        identifiers, local_ids = set(), set()
        for call in send.call_args_list:
            request = call.args[0]
            self.assertEqual(request.get_header('User-agent'), CURRENT['user_agent'])
            self.assertEqual(request.get_header('X-mme-client-info'), CURRENT['client_info'])
            identifiers.add(request.get_header('X-mme-device-id'))
            local_ids.add(request.get_header('X-apple-i-md-lu'))
            self.assertNotIn('Apple-ID', str(request.headers))
        self.assertEqual(len(identifiers), 1)
        self.assertEqual(local_ids, {hashlib.sha256(state['keychain_identifier']).hexdigest()})
        self.assertEqual(self.ws.send_json.call_args_list[0].args[0],
                         {'identifier': base64.b64encode(state['keychain_identifier']).decode()})
        self.assertEqual(plistlib.loads(send.call_args_list[-1].args[0].data)['Request'],
                         {'cpim': 'private-cpim'})
        self.ws.close.assert_called_once()

    def test_old_mac_is_upgraded_and_current_mac_is_preserved(self):
        self.assertEqual(b.current_mac_identity(OLD), CURRENT)
        newer = {'client_info': '<Mac14,2> <macOS;14.6;23G80>', 'user_agent': 'Mac UA'}
        self.assertEqual(b.current_mac_identity(newer), newer)
        with self.assertRaises(ValueError):
            b.current_mac_identity({'client_info': '<Pixel 8> <Android;14>', 'user_agent': 'android'})

    def test_existing_state_and_old_profile_are_never_reprovisioned(self):
        self.path.write_bytes(b'old-private-state')
        with patch.object(b, 'urlopen') as send, self.assertRaises(ValueError):
            b.provision_current_mac_state(self.path, t.URL, CURRENT)
        send.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b'old-private-state')
        self.path.unlink()
        with patch.object(b, 'urlopen') as send, self.assertRaises(ValueError):
            b.provision_current_mac_state(self.path, t.URL, OLD)
        send.assert_not_called()

    def test_legacy_or_mismatched_state_is_rejected(self):
        self.path.write_bytes(plistlib.dumps({'keychain_identifier': bytes(16), 'adi_pb': b'legacy'}))
        with self.assertRaises(ValueError):
            b.validate_current_mac_state(self.path, t.URL, CURRENT)
        self.path.unlink()
        self.provision()
        for provider, identity in [('https://different.test', CURRENT), (t.URL, OLD),
                                   (t.URL, dict(CURRENT, user_agent='different'))]:
            with self.assertRaises(ValueError):
                b.validate_current_mac_state(self.path, provider, identity)

    def test_rejected_or_out_of_order_provisioning_leaves_no_state(self):
        for messages in ([{'result': 'InvalidIdentifier'}], [{'result': 'ProvisioningSuccess'}],
                         [{'result': 'GiveEndProvisioningData', 'cpim': 'private'}]):
            self.ws.receive_json.side_effect = messages
            with self.assertRaises(ValueError):
                self.provision()
            self.assertFalse(self.path.exists())

    def test_bad_apple_response_and_non_apple_bag_are_rejected(self):
        bad = [self.responses[0], {'Response': {'Status': {'ec': -1, 'em': 'private'}}}]
        with self.assertRaises(ValueError):
            self.provision(bad)
        self.assertFalse(self.path.exists())
        self.ws.receive_json.side_effect = [{'result': 'GiveIdentifier'},
                                            {'result': 'GiveStartProvisioningData'}]
        bag = {'urls': {'midStartProvisioning': 'https://apple.com.attacker.test/start',
                        'midFinishProvisioning': 'https://gsa.apple.com/finish'}}
        with self.assertRaises(ValueError):
            self.provision([bag])
        self.assertFalse(self.path.exists())


class FakeSocket:
    def __init__(self, content):
        self.data = bytearray(content)
        self.sent = []
        self.closed = False

    def recv(self, size):
        result = bytes(self.data[:size])
        del self.data[:size]
        return result

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class WebSocketTests(unittest.TestCase):
    def connection(self, frames=b'', accept=True):
        key = base64.b64encode(bytes(16)).decode()
        value = base64.b64encode(hashlib.sha1(
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        response = ('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                    'Connection: Upgrade\r\nSec-WebSocket-Accept: '
                    + (value if accept else 'invalid') + '\r\n\r\n').encode()
        sock = FakeSocket(response + frames)
        with patch.object(b.socket, 'create_connection', return_value=sock), \
                patch.object(b.ssl, 'create_default_context') as context, \
                patch.object(b.secrets, 'token_bytes', return_value=bytes(16)):
            context.return_value.wrap_socket.return_value = sock
            if not accept:
                with self.assertRaises(ValueError):
                    b.ProvisioningSocket('https://provider.test', b.time.monotonic() + 60)
                self.assertTrue(sock.closed)
                return
            ws = b.ProvisioningSocket('https://provider.test', b.time.monotonic() + 60)
        return ws, sock

    def test_validates_handshake_and_accepts_fragmented_json_with_ping(self):
        first, last = b'{"res', b'ult":"x"}'
        ws, sock = self.connection(bytes((0x01, len(first))) + first + b'\x89\x01p' +
                                   bytes((0x80, len(last))) + last)
        self.assertEqual(ws.receive_json(), {'result': 'x'})
        self.assertEqual(sock.sent[-1][0], 0x8a)
        self.assertTrue(sock.sent[-1][1] & 0x80)  # client pong is masked
        ws.close()
        self.assertTrue(sock.closed)

    def test_invalid_accept_mask_and_oversize_frames_are_rejected(self):
        self.connection(accept=False)
        for frame in (b'\x81\x80', b'\x81\x7f' + struct.pack('>Q', 2 * 1024 * 1024),
                      b'\x80\x00', b'\x88\x00'):
            ws, _ = self.connection(frame)
            with self.assertRaises(ValueError):
                ws.receive_json()
            ws.close()


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'run').mkdir()
        self.commands = []
        self.trial = t.ModernMacTrial(root=self.root, runner=self.run_command, pause=lambda _: None,
                                     owner=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
        self.trial.endpoint = Mock()
        self.trial.check = Mock()
        base = self.trial.at(t.common.BASE)
        base.mkdir(parents=True)
        for name in ('APPLIED', 'bridge.py', 'anisette-state.plist'):
            (base / name).write_text('private-original-' + name)
        self.permanent = ('[Service]\nExecStart=\nExecStart=/usr/bin/env '
                          '"ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971" '
                          '"ALTSERVER_GSA_USER_AGENT=original UA" '
                          '"/opt/altserver-keeper-v3/AltServer-aarch64"\n')
        self.trial.write(self.trial.permanent_dropin, self.permanent)
        self.addCleanup(patch.stopall)
        patch.object(b, 'fetch_provider_identity', return_value=OLD).start()
        self.provision = patch.object(b, 'provision_current_mac_state', side_effect=self.new_state).start()

    def run_command(self, args, **kwargs):
        self.commands.append(args)
        return subprocess.CompletedProcess(args, 0, 'not-found' if 'LoadState' in args else '', '')

    def new_state(self, path, provider, identity):
        path.write_bytes(plistlib.dumps({'keychain_identifier': bytes(16), 'adi_pb': b'private-new',
                                         'provider_url': provider,
                                         'provisioned_client_info': identity['client_info'],
                                         'provisioned_user_agent': identity['user_agent']}))

    def test_trial_uses_new_code_and_state_and_rollback_preserves_baseline(self):
        self.trial.apply('modern-mac')
        unit = self.trial.unit.read_text()
        self.assertIn('/run/altserver-identity-trial/bridge.py', unit)
        self.assertIn('--current-mac', unit)
        self.assertIn(CURRENT['user_agent'], self.trial.dropin.read_text())
        self.assertIn('16972', self.trial.dropin.read_text())
        self.assertEqual((self.trial.home / 'modern-state.plist').stat().st_mode & 0o777, 0o600)
        self.provision.assert_called_once_with(self.trial.home / 'modern-state.plist', t.URL, CURRENT)
        self.assertEqual((self.trial.home / 'bridge.py').read_bytes(),
                         (SCRIPTS / 'keeper_v3_anisette_bridge.py').read_bytes())
        self.assertFalse(any(cmd[0] == 'docker' for cmd in self.commands))
        self.trial.rollback()
        self.assertEqual(self.trial.permanent_dropin.read_text(), self.permanent)
        for name in ('APPLIED', 'bridge.py', 'anisette-state.plist'):
            self.assertEqual(self.trial.at(t.common.BASE / name).read_text(), 'private-original-' + name)
        self.assertFalse(self.trial.home.exists())

    def test_provisioning_failure_does_not_switch_altserver(self):
        self.provision.side_effect = ValueError('private provider failure')
        with self.assertRaises(ValueError):
            self.trial.apply('modern-mac')
        self.assertNotIn(['systemctl', 'restart', t.common.ALT], self.commands)
        self.assertFalse(self.trial.home.exists())

    def test_failed_probe_and_switch_automatically_restore_baseline(self):
        self.trial.check.side_effect = [None, ValueError('private probe failure')]
        with self.assertRaises(ValueError):
            self.trial.apply('modern-mac')
        self.assertFalse(self.trial.dropin.exists())
        self.assertEqual(self.trial.permanent_dropin.read_text(), self.permanent)
        self.trial.check.side_effect = None
        self.trial.endpoint.side_effect = lambda port: (_ for _ in ()).throw(
            RuntimeError('wrong endpoint')) if port == 16972 else None
        with self.assertRaises(RuntimeError):
            self.trial.apply('modern-mac')
        self.trial.endpoint.assert_called_with(16971)
        self.assertFalse(self.trial.home.exists())

    def test_missing_ua_and_other_trial_types_are_rejected(self):
        self.trial.permanent_dropin.write_text(self.permanent.replace(
            '"ALTSERVER_GSA_USER_AGENT=original UA" ', ''))
        with self.assertRaises(RuntimeError):
            self.trial.apply('modern-mac')
        self.assertFalse(self.trial.home.exists())
        self.trial.write(self.trial.permanent_dropin, self.permanent)
        self.trial.home.mkdir()
        (self.trial.home / 'manifest.json').write_text(json.dumps({'kind': 'provider'}))
        with self.assertRaises(RuntimeError):
            self.trial.rollback()
        self.assertTrue(self.trial.home.exists())


if __name__ == '__main__':
    unittest.main()
