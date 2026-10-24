#!/usr/bin/env python3
"""Promote WalnutPi's working fresh-header trial without rebuilding or Apple login."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen

ALT = 'altserver.service'
OLD = 'anisette-keeper-v3-bridge.service'
UNIT = 'anisette-keeper-v3.service'
UA = 'AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.new')
    with temporary.open('w') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(content)
    temporary.replace(path)


def probe(path):
    with urlopen('http://127.0.0.1:16971' + path, timeout=100 if path == '/' else 2) as response:
        data = json.load(response)
    if path == '/':
        fields = ('X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-MMe-Client-Info',
                  'X-Apple-I-Client-Time', 'X-Mme-Device-Id', 'X-Apple-I-MD-LU')
        if not all(isinstance(data.get(key), str) and data[key] for key in fields):
            raise RuntimeError('Anisette response validation failed (values redacted).')


class Deployment:
    def __init__(self, work, source, root=Path('/'), runner=subprocess.run,
                 check=probe, pause=time.sleep, user=None):
        self.root, self.work, self.source = root, work, source
        self.runner, self.check, self.pause = runner, check, pause
        self.user = user or pwd.getpwnam('pi')
        self.dest = self.at('/opt/altserver-keeper-v3')
        self.backup = self.dest / 'backup'
        self.manifest = self.backup / 'deployment.json'
        self.marker = self.dest / 'APPLIED'
        self.unit = self.at('/etc/systemd/system') / UNIT
        # Same basename: /etc takes precedence over the existing /run trial file.
        self.dropin = self.at('/etc/systemd/system/altserver.service.d/90-keeper-auth-trial.conf')
        self.runtime = self.at('/run/systemd/system/altserver.service.d/90-keeper-auth-trial.conf')

    def at(self, path):
        return self.root / path.lstrip('/')

    def call(self, *args, required=True):
        result = self.runner(list(args), text=True, capture_output=True, timeout=40)
        if required and result.returncode:
            raise RuntimeError('Command failed: ' + ' '.join(args[:3]))
        return result

    def value(self, unit, prop):
        return self.call('systemctl', 'show', unit, '-p', prop, '--value').stdout.strip()

    def active(self, unit):
        return self.call('systemctl', 'is-active', '--quiet', unit, required=False).returncode == 0

    def save(self, data):
        write(self.manifest, json.dumps(data, indent=2) + '\n', 0o600)

    def boot_id(self):
        return self.at('/proc/sys/kernel/random/boot_id').read_text().strip()

    def preflight(self):
        if any(p.exists() or p.is_symlink() for p in (self.dest, self.unit, self.dropin)):
            raise RuntimeError('Persistent deployment paths already exist; refusing to overwrite them.')
        for name in ('READY', 'APPLIED', 'V3_BRIDGE_APPLIED'):
            if not (self.work / name).is_file():
                raise RuntimeError('The existing trial is not recorded as applied.')
        binary = self.work / 'AltServer/build/AltServer-aarch64'
        sums = (self.work / 'SHA256SUMS').read_text().split()
        if len(sums) != 2 or sums[1].lstrip('*') != 'AltServer-aarch64' or digest(binary) != sums[0]:
            raise RuntimeError('Trial binary checksum mismatch.')
        raw = (self.work / 'v3-fresh-state.plist').read_bytes()
        state = plistlib.loads(raw)
        if (not isinstance(state.get('keychain_identifier'), bytes)
                or len(state['keychain_identifier']) != 16
                or not isinstance(state.get('adi_pb'), bytes) or not state['adi_pb']):
            raise RuntimeError('Invalid isolated trial state (values redacted).')
        if not self.source.is_file():
            raise RuntimeError('Missing bridge source beside this installer.')
        if not self.active(ALT) or not self.active(OLD):
            raise RuntimeError('Both existing trial services must be running.')
        runtime = self.runtime.read_text()
        if str(binary) not in runtime or 'http://127.0.0.1:16971' not in runtime:
            raise RuntimeError('Unexpected active trial override.')
        fresh = self.at('/run/systemd/system') / (OLD + '.d/90-fresh-headers.conf')
        if 'ALTSERVER_ANISETTE_FRESH_STATE=' + str(self.work / 'v3-fresh-state.plist') not in fresh.read_text():
            raise RuntimeError('The trial must be in fresh-header mode.')
        if self.value(UNIT, 'LoadState') != 'not-found':
            raise RuntimeError('The persistent bridge unit name is already in use.')
        enabled = self.value(ALT, 'UnitFileState')
        if enabled not in ('enabled', 'disabled'):
            raise RuntimeError('Unexpected AltServer enable state: ' + enabled)
        if self.value('netmuxd.service', 'LoadState') != 'loaded':
            raise RuntimeError('The existing netmuxd service is unavailable.')
        self.check('/')  # No login or phone request; discard the private data.
        return binary, raw, enabled

    def contents(self):
        unit = f'''[Unit]
Description=Anisette v3 fresh-header adapter for AltServer
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User={self.user.pw_name}
Group={self.user.pw_gid}
ExecStart=/usr/bin/python3 -u {self.dest}/bridge.py --port 16971 --fresh-state-file {self.dest}/anisette-state.plist
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
'''
        override = f'''[Unit]
Wants=network-online.target netmuxd.service {UNIT}
After=network-online.target netmuxd.service {UNIT}

[Service]
ExecStart=
ExecStart=/usr/bin/env "USBMUXD_SOCKET_ADDRESS=127.0.0.1:27015" "ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971" "ALTSERVER_GSA_USER_AGENT={UA}" "{self.dest}/AltServer-aarch64"
'''
        return {self.unit: unit, self.dropin: override}

    def apply(self):
        binary, raw, enabled = self.preflight()
        self.dest.mkdir(mode=0o755, parents=True)
        self.dest.chmod(0o755)
        self.backup.mkdir(mode=0o700)
        files = self.contents()
        data = dict(phase='installing', boot_id=self.boot_id(), enabled=enabled,
                    files={str(p): hashlib.sha256(s.encode()).hexdigest() for p, s in files.items()})
        # Save the effective old bridge, including its fresh-state environment.
        write(self.backup / 'trial-bridge.service', self.call('systemctl', 'cat', OLD, '--no-pager').stdout, 0o600)
        write(self.backup / 'altserver-before.service', self.call('systemctl', 'cat', ALT, '--no-pager').stdout, 0o600)
        shutil.copy2(self.runtime, self.backup / 'trial-altserver.conf')
        self.save(data)
        try:
            shutil.copyfile(binary, self.dest / 'AltServer-aarch64')
            (self.dest / 'AltServer-aarch64').chmod(0o755)
            if digest(self.dest / 'AltServer-aarch64') != digest(binary):
                raise RuntimeError('Copied binary checksum mismatch.')
            shutil.copyfile(self.source, self.dest / 'bridge.py')
            (self.dest / 'bridge.py').chmod(0o644)
            state = self.dest / 'anisette-state.plist'
            state.write_bytes(raw)
            state.chmod(0o600)
            os.chown(state, self.user.pw_uid, self.user.pw_gid)
            for path, content in files.items():
                write(path, content)
            self.call('systemctl', 'stop', ALT)
            self.call('systemctl', 'stop', OLD)
            self.call('systemctl', 'daemon-reload')
            self.call('systemctl', 'start', UNIT)
            for attempt in range(30):
                try:
                    self.check('/healthz')
                    break
                except Exception:
                    if attempt == 29:
                        raise RuntimeError('Persistent bridge did not become ready.') from None
                    self.pause(1)
            self.check('/')
            self.call('systemctl', 'start', ALT)
            self.pause(2)
            if not self.active(ALT) or not self.active(UNIT):
                raise RuntimeError('A persistent service did not stay active.')
            pid = self.value(ALT, 'MainPID')
            if not pid.isdecimal() or int(pid) == 0:
                raise RuntimeError('AltServer has no running process.')
            if self.at('/proc/' + pid + '/exe').resolve() != (self.dest / 'AltServer-aarch64').resolve():
                raise RuntimeError('The running binary does not match the promoted binary.')
            environ = self.at('/proc/' + pid + '/environ').read_bytes().split(b'\0')
            if (b'USBMUXD_SOCKET_ADDRESS=127.0.0.1:27015' not in environ
                    or b'ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971' not in environ):
                raise RuntimeError('AltServer is not using the expected endpoints.')
            self.call('systemctl', 'enable', UNIT, ALT)
            if any(self.value(unit, 'UnitFileState') != 'enabled' for unit in (UNIT, ALT)):
                raise RuntimeError('A persistent service was not enabled for boot.')
            data['phase'] = 'applied'
            self.save(data)
            write(self.marker, 'fresh-header deployment\n')
        except (Exception, KeyboardInterrupt):
            print('Promotion failed; restoring the previous trial...', flush=True)
            self.rollback()
            raise
        print('Persistent AltServer and fresh-header bridge are active and enabled for boot.')
        print('No build, Docker changes, Apple ID login or phone refresh was performed.')
        print('Rollback: sudo python3 ' + str(Path(__file__).resolve()) + ' rollback')

    def rollback(self):
        data = json.loads(self.manifest.read_text())
        if data['phase'] == 'rolled-back':
            print('Persistent deployment is already rolled back.')
            return
        expected = {str(self.unit), str(self.dropin)}
        if set(data['files']) != expected:
            raise RuntimeError('Unexpected rollback manifest paths.')
        for path, checksum in data['files'].items():
            p = Path(path)
            if p.is_symlink() or (p.exists() and digest(p) != checksum):
                raise RuntimeError('A deployed unit was edited; refusing to overwrite it during rollback.')
        self.call('systemctl', 'stop', ALT)
        self.call('systemctl', 'disable', '--now', UNIT, required=False)
        for path in data['files']:
            Path(path).unlink(missing_ok=True)
        self.call('systemctl', 'daemon-reload')
        self.call('systemctl', 'enable' if data['enabled'] == 'enabled' else 'disable', ALT)
        same_boot = data['boot_id'] == self.boot_id()
        if same_boot:
            # A stopped transient unit may have been garbage-collected by systemd.
            if self.call('systemctl', 'start', OLD, required=False).returncode:
                runtime_unit = self.at('/run/systemd/system') / OLD
                if runtime_unit.exists():
                    raise RuntimeError('Unexpected runtime bridge unit; inspect it before restoring.')
                write(runtime_unit, (self.backup / 'trial-bridge.service').read_text())
                self.call('systemctl', 'daemon-reload')
                self.call('systemctl', 'start', OLD)
            self.call('systemctl', 'start', ALT)
        elif data['enabled'] == 'enabled':
            self.call('systemctl', 'start', ALT)
        self.marker.unlink(missing_ok=True)
        data['phase'] = 'rolled-back'
        self.save(data)
        print('Previous trial restored.' if same_boot else 'Previous boot configuration restored.')
        print('Backup and isolated state retained at ' + str(self.dest))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('apply', 'rollback', 'status'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo python3; the bridge itself will run as pi.')
    if platform.machine() != 'aarch64':
        parser.error('This deployment is for the existing ARM64 WalnutPi trial.')
    deploy = Deployment(Path('/home/pi/altserver-keeper-auth-20261024'),
                        Path(__file__).resolve().with_name('keeper_v3_anisette_bridge.py'))
    try:
        if args.command == 'apply':
            print('Checking the existing trial and isolated Anisette data...', flush=True)
            deploy.apply()
        elif args.command == 'rollback':
            deploy.rollback()
        else:
            result = deploy.call('systemctl', '--no-pager', '--full', 'status', ALT, UNIT, required=False)
            print(result.stdout)
    except Exception as exc:
        # Provider errors can contain request details. Log only our own safe messages.
        print('ERROR: ' + (str(exc) if type(exc) is RuntimeError else type(exc).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
