"""No-network checks for provisioning isolation and transactional cleanup."""
import importlib.util
import io
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

path = Path(__file__).resolve().parents[1] / 'scripts/anisette-provider-trial.py'
spec = importlib.util.spec_from_file_location('provider_trial', path)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

IMAGE = 'sha256:' + 'a' * 64
CID = 'b' * 64


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'run').mkdir()
        self.commands = []
        self.container_exists = False
        self.container_state = {'Running': True, 'ExitCode': 0, 'OOMKilled': False,
                                'Error': 'PRIVATE-ERROR-MUST-NOT-BE-PRINTED'}
        self.labels = {}
        self.create_args = None
        self.bridge = Mock()
        self.bridge.fetch_provider_identity.return_value = {
            'client_info': '<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.akd/1.0)>',
            'user_agent': 'provider-UA'}
        self.bridge.fetch_anisette.side_effect = self.generate_state
        self.trial = p.ProviderTrial(root=self.root, runner=self.run_command,
                                     pause=lambda _: None, bridge=self.bridge,
                                     owner=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
        self.trial.check = Mock()
        self.trial.endpoint = Mock()
        base = self.trial.at(p.common.BASE)
        base.mkdir(parents=True)
        for name in ('APPLIED', 'bridge.py', 'anisette-state.plist'):
            (base / name).write_text('original-' + name)
        self.original = (base / 'anisette-state.plist').read_bytes()
        self.permanent = ('[Service]\nExecStart=\nExecStart=/usr/bin/env '
                          'ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971 '
                          '/opt/altserver-keeper-v3/AltServer-aarch64\n')
        self.trial.write(self.trial.permanent_dropin, self.permanent)

    def generate_state(self, port):
        self.assertEqual(port, p.BOOTSTRAP_PORT)
        state = self.trial.home / 'bootstrap/state/anisette_state'
        state.parent.mkdir()
        state.write_bytes(plistlib.dumps({'keychain_identifier': bytes(range(16)),
                                         'adi_pb': b'new-test-provisioning'}))
        return {'unused': 'private test response'}

    def run_command(self, args, **kwargs):
        self.commands.append(args)
        output, code = '', 0
        if args[:2] == ['docker', 'inspect']:
            if p.SOURCE_CONTAINER in args:
                output = IMAGE
            elif self.container_exists:
                output = json.dumps(self.container_state if '{{json .State}}' in args else self.labels)
            else:
                code = 1
        elif args[:2] == ['docker', 'create']:
            self.create_args = args
            key, value = args[args.index('--label') + 1].split('=', 1)
            self.labels[key] = value
            self.container_exists = True
            output = CID
        elif args[:2] == ['docker', 'rm']:
            self.assertIn(CID, args)
            self.container_exists = False
        elif args[:2] == ['docker', 'ps']:
            output = CID if self.container_exists else ''
        elif 'LoadState' in args:
            output = 'not-found'
        return subprocess.CompletedProcess(args, code, output, '')

    def apply(self):
        # Avoid reserving a real machine port in unit tests.
        with patch.object(p.socket, 'socket'):
            self.trial.apply('jkcoxson-mac')

    def test_uses_new_empty_mount_pinned_image_and_direct_provider_after_bootstrap(self):
        self.apply()
        self.assertIn(IMAGE, self.create_args)
        self.assertIn('--pull=never', self.create_args)
        self.assertIn('ALTKEEPER_ANISETTE_URL=' + p.URL, self.create_args)
        mounts = [s for s in self.create_args if s.startswith('type=bind,')]
        self.assertEqual(mounts, ['type=bind,source=' + str(self.trial.home / 'bootstrap') + ',target=/data'])
        self.assertNotIn('/srv/altkeeper', ' '.join(self.create_args))
        self.assertFalse(self.container_exists)
        self.assertEqual(self.bridge.fetch_anisette.call_count, 1)
        target = self.trial.home / 'provider-state.plist'
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(plistlib.loads(target.read_bytes())['adi_pb'], b'new-test-provisioning')
        unit = self.trial.unit.read_text()
        self.assertIn('/opt/altserver-keeper-v3/bridge.py', unit)
        self.assertIn('--client-info-url ' + p.URL + '/v3/client_info', unit)
        self.assertIn('--fresh-state-file /run/altserver-identity-trial/provider-state.plist', unit)
        self.assertEqual(self.trial.at(p.common.BASE / 'anisette-state.plist').read_bytes(), self.original)
        self.trial.rollback()
        self.assertFalse(self.trial.home.exists())
        self.assertEqual(self.trial.permanent_dropin.read_text(), self.permanent)

    def test_provisioning_failure_cleans_only_own_container_without_switching(self):
        self.bridge.fetch_anisette.side_effect = ValueError('provider failure')
        with self.assertRaises(ValueError):
            self.apply()
        self.assertFalse(self.container_exists)
        self.assertFalse(self.trial.home.exists())
        self.assertNotIn(['systemctl', 'restart', p.common.ALT], self.commands)
        removed = [cmd[-1] for cmd in self.commands if cmd[:2] == ['docker', 'rm']]
        self.assertEqual(removed, [CID])
        self.assertEqual(self.bridge.fetch_anisette.call_count, 1)

    def test_startup_reset_then_success_uses_same_empty_state_container(self):
        attempts = iter((ConnectionResetError(), BrokenPipeError(), None))
        def fetch(port):
            error = next(attempts)
            if error is not None:
                raise error
            return self.generate_state(port)
        self.bridge.fetch_anisette.side_effect = fetch
        self.apply()
        self.assertEqual(self.bridge.fetch_anisette.call_count, 3)
        self.assertEqual(sum(cmd[:2] == ['docker', 'create'] for cmd in self.commands), 1)
        self.assertFalse(self.container_exists)
        self.assertTrue(self.trial.dropin.exists())

    def test_persistent_reset_stops_after_bounded_attempts_and_rolls_back(self):
        self.bridge.fetch_anisette.side_effect = ConnectionResetError('private response')
        with self.assertRaisesRegex(RuntimeError, 'ConnectionResetError; running=True'):
            self.apply()
        self.assertEqual(self.bridge.fetch_anisette.call_count, p.BOOTSTRAP_ATTEMPTS)
        self.assertFalse(self.container_exists)
        self.assertFalse(self.trial.home.exists())
        self.assertNotIn(['systemctl', 'restart', p.common.ALT], self.commands)

    def test_container_exit_reports_only_safe_status_and_does_not_retry(self):
        def exited(port):
            self.container_state.update(Running=False, ExitCode=137, OOMKilled=True)
            raise ConnectionResetError('private response')
        self.bridge.fetch_anisette.side_effect = exited
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(RuntimeError) as caught:
            self.apply()
        self.assertIn('running=False, exit_code=137, oom_killed=True', str(caught.exception))
        self.assertNotIn('PRIVATE-ERROR', output.getvalue() + str(caught.exception))
        self.assertNotIn('private response', output.getvalue() + str(caught.exception))
        self.assertEqual(self.bridge.fetch_anisette.call_count, 1)
        self.assertFalse(self.container_exists)
        self.assertNotIn(['systemctl', 'restart', p.common.ALT], self.commands)

    def test_fresh_header_failure_does_not_switch_altserver(self):
        self.trial.check.side_effect = [None, RuntimeError('fresh path failed')]
        with self.assertRaisesRegex(RuntimeError, 'fresh path'):
            self.apply()
        self.assertFalse(self.trial.home.exists())
        self.assertNotIn(['systemctl', 'restart', p.common.ALT], self.commands)

    def test_create_timeout_recovers_only_labeled_container(self):
        def timeout_after_create(args, **kwargs):
            result = self.run_command(args, **kwargs)
            if args[:2] == ['docker', 'create']:
                raise subprocess.TimeoutExpired(args, 45)
            return result
        self.trial.runner = timeout_after_create
        with self.assertRaises(subprocess.TimeoutExpired):
            self.apply()
        self.assertFalse(self.container_exists)
        self.assertFalse(self.trial.home.exists())
        filters = [cmd for cmd in self.commands if cmd[:2] == ['docker', 'ps']]
        self.assertTrue(any('--filter' in cmd and any(x.startswith('label=' + p.LABEL) for x in cmd)
                            for cmd in filters))

    def test_client_info_rollback_refuses_provider_manifest(self):
        self.apply()
        other = p.common.Trial(root=self.root, runner=self.run_command)
        with self.assertRaisesRegex(RuntimeError, 'Different trial type'):
            other.rollback()
        self.assertTrue(self.trial.dropin.exists())

    def test_changed_container_ownership_is_never_removed(self):
        self.apply()
        self.trial.update_manifest(container_id=CID)
        self.container_exists = True
        self.labels = {p.LABEL: 'different-owner'}
        before = len(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
            self.trial.cleanup()
        self.assertFalse(any(cmd[:2] in (['docker', 'stop'], ['docker', 'rm'])
                             for cmd in self.commands[before:]))

    def test_non_mac_metadata_refused_before_runtime_or_container_creation(self):
        self.bridge.fetch_provider_identity.return_value['client_info'] = '<Windows>'
        with self.assertRaisesRegex(RuntimeError, 'no longer advertises'):
            self.apply()
        self.assertFalse(self.trial.home.exists())
        self.assertIsNone(self.create_args)


if __name__ == '__main__':
    unittest.main()
