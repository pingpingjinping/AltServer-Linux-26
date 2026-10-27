"""Exercise promotion, transient-unit recovery, and rollback without system changes."""
import importlib.util
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('persist', ROOT / 'scripts/keeper-v3-persist.py')
persist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(persist)


class PersistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.calls, self.probes = [], []
        self.units = {persist.ALT: True, persist.OLD: True, persist.UNIT: False}
        self.enabled = {persist.ALT: 'disabled', persist.UNIT: 'disabled'}
        self.old_available = True
        self.failure = ''
        self.work = root / 'home/pi/altserver-keeper-auth-20261024'
        self.work.mkdir(parents=True)
        user = SimpleNamespace(pw_name='pi', pw_uid=os.getuid(), pw_gid=os.getgid())
        self.deploy = persist.Deployment(self.work, ROOT / 'scripts/keeper_v3_anisette_bridge.py',
                                         root=root, runner=self.run_command,
                                         check=self.probe, pause=lambda _: None, user=user)
        for marker in ('READY', 'APPLIED', 'V3_BRIDGE_APPLIED'):
            (self.work / marker).touch()
        self.binary = self.work / 'AltServer/build/AltServer-aarch64'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b'validated-binary-fixture')
        self.binary.chmod(0o755)
        (self.work / 'SHA256SUMS').write_text(persist.digest(self.binary) + '  AltServer-aarch64\n')
        self.state = plistlib.dumps({'keychain_identifier': bytes(range(16)), 'adi_pb': b'private-state'})
        (self.work / 'v3-fresh-state.plist').write_bytes(self.state)
        persist.write(self.deploy.runtime, f'[Service]\nExecStart={self.binary} http://127.0.0.1:16971\n')
        self.original_override = self.deploy.runtime.read_bytes()
        fresh = self.deploy.at('/run/systemd/system') / (persist.OLD + '.d/90-fresh-headers.conf')
        persist.write(fresh, '[Service]\nEnvironment="ALTSERVER_ANISETTE_FRESH_STATE=' + str(self.work / 'v3-fresh-state.plist') + '"\n')
        persist.write(self.deploy.at('/proc/sys/kernel/random/boot_id'), 'first-boot\n')
        self.current_pid()

    def current_pid(self):
        exe = self.deploy.at('/proc/101/exe')
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.unlink(missing_ok=True)
        exe.symlink_to(self.deploy.dest / 'AltServer-aarch64' if self.deploy.dropin.exists() else self.binary)
        (exe.parent / 'environ').write_bytes(b'USBMUXD_SOCKET_ADDRESS=127.0.0.1:27015\0'
                                            b'ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971\0')

    def run_command(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[0], 'systemctl')
        action, *rest = args[1:]
        rc, stdout = 0, ''
        if action == 'show':
            unit, _, prop, _ = rest
            if prop == 'UnitFileState': stdout = self.enabled[unit]
            elif prop == 'LoadState': stdout = 'not-found' if unit == persist.UNIT else 'loaded'
            elif prop == 'MainPID': stdout = '101'
            else: self.fail(prop)
        elif action == 'is-active':
            rc = 0 if self.units[rest[-1]] else 3
        elif action == 'cat':
            stdout = '[Service]\nExecStart=/usr/bin/python3 old-bridge.py\n'
            if rest[0] == persist.OLD:
                stdout += 'Environment="ALTSERVER_ANISETTE_FRESH_STATE=' + str(self.work / 'v3-fresh-state.plist') + '"\n'
        elif action == 'stop':
            self.units[rest[0]] = False
            if rest[0] == persist.OLD: self.old_available = False  # transient GC
        elif action == 'start':
            unit = rest[0]
            restored = (self.deploy.at('/run/systemd/system') / persist.OLD).exists()
            if unit == persist.OLD and not self.old_available and not restored:
                rc = 5
            elif unit == persist.UNIT and self.failure == 'start':
                rc = 1
            else:
                self.units[unit] = True
                if unit == persist.ALT: self.current_pid()
        elif action in ('enable', 'disable'):
            for unit in rest:
                if unit == '--now': continue
                self.enabled[unit] = 'enabled' if action == 'enable' else 'disabled'
                if '--now' in rest: self.units[unit] = False
        elif action != 'daemon-reload':
            self.fail(args)
        return subprocess.CompletedProcess(args, rc, stdout, '')

    def probe(self, path):
        self.probes.append(path)
        if self.failure == 'provider' and self.units[persist.UNIT] and path == '/':
            raise OSError('private provider error')

    def assert_trial_restored(self):
        self.assertTrue(self.units[persist.ALT])
        self.assertTrue(self.units[persist.OLD])
        self.assertFalse(self.units[persist.UNIT])
        self.assertEqual(self.enabled[persist.ALT], 'disabled')
        self.assertFalse(self.deploy.unit.exists())
        self.assertFalse(self.deploy.dropin.exists())
        self.assertFalse(self.deploy.marker.exists())
        self.assertEqual(self.deploy.runtime.read_bytes(), self.original_override)
        self.assertEqual((self.work / 'v3-fresh-state.plist').read_bytes(), self.state)

    def test_promotion_and_same_boot_rollback_after_transient_collection(self):
        self.deploy.apply()
        self.assertEqual(self.enabled[persist.ALT], 'enabled')
        self.assertEqual(self.enabled[persist.UNIT], 'enabled')
        self.assertFalse(self.units[persist.OLD])
        self.assertTrue(self.deploy.marker.exists())
        self.assertEqual(persist.digest(self.deploy.dest / 'AltServer-aarch64'), persist.digest(self.binary))
        snapshot = self.deploy.dest / 'anisette-state.plist'
        self.assertEqual(snapshot.read_bytes(), self.state)
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        self.assertIn('--fresh-state-file', self.deploy.unit.read_text())
        self.assertNotIn('14951', self.deploy.unit.read_text())
        command = self.deploy.unit.read_text().split('ExecStart=')[1].split('\n')[0]
        self.assertNotIn(str(self.work), command)
        self.deploy.rollback()
        self.assert_trial_restored()
        self.assertTrue((self.deploy.at('/run/systemd/system') / persist.OLD).exists())
        self.assertTrue(self.deploy.manifest.exists())

    def test_new_service_failure_restores_working_trial(self):
        self.failure = 'start'
        with self.assertRaises(RuntimeError): self.deploy.apply()
        self.assert_trial_restored()

    def test_provider_failure_restores_working_trial(self):
        self.failure = 'provider'
        with self.assertRaises(OSError): self.deploy.apply()
        self.assert_trial_restored()

    def test_invalid_state_changes_no_services(self):
        (self.work / 'v3-fresh-state.plist').write_bytes(plistlib.dumps({'adi_pb': b'state'}))
        with self.assertRaises(RuntimeError): self.deploy.apply()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.deploy.dest.exists())

    def test_rollback_after_reboot_restores_disabled_original_boot_config(self):
        self.deploy.apply()
        persist.write(self.deploy.at('/proc/sys/kernel/random/boot_id'), 'second-boot\n')
        self.deploy.runtime.unlink()
        self.deploy.rollback()
        self.assertFalse(self.units[persist.ALT])
        self.assertFalse(self.units[persist.UNIT])
        self.assertEqual(self.enabled[persist.ALT], 'disabled')

    def test_edited_persistent_unit_is_not_deleted_by_rollback(self):
        self.deploy.apply()
        self.deploy.unit.write_text('operator edit\n')
        before = len(self.calls)
        with self.assertRaises(RuntimeError): self.deploy.rollback()
        self.assertEqual(len(self.calls), before)
        self.assertEqual(self.deploy.unit.read_text(), 'operator edit\n')


if __name__ == '__main__':
    unittest.main()
