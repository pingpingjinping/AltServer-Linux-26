"""Mock system services to verify header-mode recovery without touching a Pi."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
work = pathlib.Path(os.environ['ALTSERVER_TRIAL_DIR'])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (work/'calls').open('a') as stream:
    stream.write(json.dumps([name, *args])+'\n')
fresh = (work/'fresh-dropin.conf').exists()
failure = os.environ.get('MOCK_FAILURE', '')
if name == 'sudo':
    os.execvp(args[0], args)
elif name == 'systemctl':
    if args[0] == 'restart':
        assert args == ['restart', 'anisette-keeper-v3-bridge.service']
        if fresh and failure == 'restart': sys.exit(1)
    else: assert args == ['daemon-reload']
elif name == 'curl':
    if not any('/healthz' in arg for arg in args) and fresh and failure == 'provider':
        sys.exit(22)
elif name == 'sleep': pass
else: raise AssertionError(name)
'''


class HeaderModeTrialTests(unittest.TestCase):
    def run_case(self, failure=''):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            tools = work/'bin'
            tools.mkdir()
            dispatch = tools/'dispatch'
            dispatch.write_text(MOCK)
            dispatch.chmod(0o755)
            for name in ['sudo', 'systemctl', 'curl', 'sleep']:
                (tools/name).symlink_to(dispatch)
            scripts = work/'source/scripts'
            scripts.mkdir(parents=True)
            shutil.copy(ROOT/'scripts/keeper_v3_anisette_bridge.py', scripts)
            script = scripts/'keeper-v3-anisette-trial.sh'
            script.write_text((ROOT/'scripts/keeper-v3-anisette-trial.sh').read_text().replace(
                'FRESH_DROPIN=/run/systemd/system/anisette-keeper-v3-bridge.service.d/90-fresh-headers.conf',
                'FRESH_DROPIN='+str(work/'fresh-dropin.conf')))
            (work/'V3_BRIDGE_APPLIED').touch()
            state = work/'keeper-v3-only-state/state/anisette_state'
            state.parent.mkdir(parents=True)
            content = plistlib.dumps({'keychain_identifier': bytes(range(16)), 'adi_pb': b'private-adi'})
            state.write_bytes(content)
            if failure == 'state': state.write_bytes(b'invalid')
            original = state.read_bytes()
            env = dict(os.environ, PATH=str(tools)+':'+os.environ['PATH'],
                       ALTSERVER_TRIAL_DIR=folder, MOCK_FAILURE=failure)
            result = subprocess.run(['bash', str(script), 'fresh-headers'],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertNotIn('private-adi', result.stdout+result.stderr)
            if not failure:
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertTrue((work/'fresh-dropin.conf').exists())
                snapshot = work/'v3-fresh-state.plist'
                self.assertEqual(snapshot.read_bytes(), content)
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                result = subprocess.run(['bash', str(script), 'cached-headers'],
                                        env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertFalse(snapshot.exists())
            else:
                self.assertNotEqual(result.returncode, 0)
            self.assertFalse((work/'fresh-dropin.conf').exists())
            self.assertEqual(state.read_bytes(), original)
            self.assertTrue((work/'V3_BRIDGE_APPLIED').exists())
            calls = [json.loads(line) for line in (work/'calls').read_text().splitlines()]
            self.assertFalse(any('altserver.service' in arg or '/srv/altkeeper' in arg
                                 for call in calls for arg in call))

    def test_switch_and_restore(self):
        self.run_case()

    def test_failed_fresh_restart_restores_cached_mode(self):
        self.run_case('restart')

    def test_failed_fresh_generation_restores_cached_mode(self):
        self.run_case('provider')

    def test_invalid_state_never_changes_service_mode(self):
        self.run_case('state')


if __name__ == '__main__':
    unittest.main()
