"""Offline checks for temporary switching, rollback, and provider separation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


t = module('identity_trial', 'anisette-identity-trial.py')
b = module('baseline_bridge', 'keeper_v3_anisette_bridge.py')


class IdentityResponseTests(unittest.TestCase):
    def test_only_response_client_info_changes_and_provider_identity_stays_separate(self):
        provider = {'client_info': '<original provider>', 'user_agent': 'original-provider-UA'}
        original = {'X-MMe-Client-Info': provider['client_info'],
                    'X-Apple-I-MD': 'test-otp', 'X-Apple-I-MD-M': 'test-machine',
                    'X-Apple-I-Client-Time': '2026-10-25T01:00:00Z'}
        for profile in t.PROFILES:
            server = b.ThreadingHTTPServer(('127.0.0.1', 0), t.handler_class(b, profile))
            server.provider_identity = provider
            server.fresh_state_file = Path('/isolated/state')
            server.fresh_lock = threading.Lock()
            server.headers_url = 'https://provider.test/v3/get_headers'
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.object(b, 'fetch_fresh_anisette', return_value=dict(original)) as fetch:
                    with urlopen('http://127.0.0.1:' + str(server.server_port)) as response:
                        actual = json.load(response)
                    self.assertEqual(actual, dict(original, **{'X-MMe-Client-Info': t.PROFILES[profile]}))
                    self.assertEqual(fetch.call_args.args,
                                     (Path('/isolated/state'), server.headers_url, provider))
                    self.assertEqual(provider['user_agent'], 'original-provider-UA')
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'run').mkdir()
        self.commands = []
        self.checks = []
        self.trial = t.Trial(root=self.root, runner=self.run_command,
                             check=lambda profile=None: self.checks.append(profile),
                             pause=lambda _: None)
        self.endpoint = patch.object(self.trial, 'endpoint')
        self.mock_endpoint = self.endpoint.start()
        self.addCleanup(self.endpoint.stop)
        base = self.trial.at(t.BASE)
        base.mkdir(parents=True)
        for name in ('APPLIED', 'bridge.py', 'anisette-state.plist'):
            (base / name).write_text('untouched-' + name)
        self.permanent = ('[Service]\nExecStart=\nExecStart=/usr/bin/env '
                          'ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971 '
                          '"ALTSERVER_GSA_USER_AGENT=original agent" '
                          '/opt/altserver-keeper-v3/AltServer-aarch64\n')
        self.trial.write(self.trial.permanent_dropin, self.permanent)

    def run_command(self, args, **kwargs):
        self.commands.append(args)
        output = 'not-found\n' if 'LoadState' in args else ''
        return subprocess.CompletedProcess(args, 0, output, '')

    def test_switch_then_rollback_leaves_permanent_files_and_adi_untouched(self):
        self.trial.apply('windows')
        self.assertEqual(self.checks, [None, 'windows'])
        self.assertIn('http://127.0.0.1:16972', self.trial.dropin.read_text())
        self.assertIn('original agent', self.trial.dropin.read_text())
        self.mock_endpoint.assert_any_call(16971)
        self.mock_endpoint.assert_any_call(16972)
        self.trial.rollback()
        self.mock_endpoint.assert_called_with(16971)
        self.assertFalse(self.trial.dropin.exists())
        self.assertFalse(self.trial.unit.exists())
        self.assertFalse(self.trial.home.exists())
        self.assertEqual(self.trial.permanent_dropin.read_text(), self.permanent)
        self.assertEqual(self.trial.at(t.BASE / 'anisette-state.plist').read_text(),
                         'untouched-anisette-state.plist')
        self.assertFalse(any('enable' in cmd or 'docker' in cmd for cmd in self.commands))

    def test_provider_failure_does_not_switch_or_restart_altserver(self):
        def fail(profile=None):
            if profile:
                raise ValueError('upstream failure')
        self.trial.check = fail
        with self.assertRaises(ValueError):
            self.trial.apply('windows')
        self.assertFalse(self.trial.dropin.exists())
        self.assertFalse(self.trial.home.exists())
        self.assertNotIn(['systemctl', 'restart', t.ALT], self.commands)

    def test_bad_endpoint_after_switch_automatically_restores_original(self):
        def endpoint(port):
            if port == 16972:
                raise RuntimeError('wrong endpoint')
        self.mock_endpoint.side_effect = endpoint
        with self.assertRaisesRegex(RuntimeError, 'wrong endpoint'):
            self.trial.apply('android')
        self.assertEqual(self.commands.count(['systemctl', 'restart', t.ALT]), 2)
        self.assertFalse(self.trial.dropin.exists())
        self.mock_endpoint.assert_called_with(16971)

    def test_refuses_existing_trial_and_edited_rollback_file(self):
        self.trial.apply('windows')
        with self.assertRaisesRegex(RuntimeError, 'already exist'):
            self.trial.apply('android')
        self.trial.dropin.write_text('operator edit')
        with self.assertRaisesRegex(RuntimeError, 'edited'):
            self.trial.rollback()
        self.assertEqual(self.trial.dropin.read_text(), 'operator edit')

    def test_reboot_cleared_trial_is_noop_and_unexpected_base_is_rejected(self):
        self.trial.rollback()
        self.assertEqual(self.commands, [])
        self.trial.permanent_dropin.write_text('[Service]\nExecStart=/other/server\n')
        with self.assertRaisesRegex(RuntimeError, 'Unexpected persistent'):
            self.trial.apply('windows')
        self.assertFalse(self.trial.home.exists())


if __name__ == '__main__':
    unittest.main()
