#!/usr/bin/env python3
"""Temporary Client-Info-only comparison; never provisions or edits ADI state."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from urllib.request import urlopen

PROFILES = {
    'windows': '<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>',
    'android': '<Pixel 8><Android; 14; UQ1A.240205.004><com.apple.AuthKit/1 (com.apple.android.music/4.9.6)>',
}
BASE = Path('/opt/altserver-keeper-v3')
ALT = 'altserver.service'
UNIT = 'anisette-identity-trial.service'
BASE_UNIT = 'anisette-keeper-v3.service'
SOURCE_URL = 'https://ani3.stikstore.app/v3/client_info'


def handler_class(bridge, profile):
    class IdentityHandler(bridge.Handler):
        def respond(self, status, data):
            if status == 200 and self.path == '/':
                data = dict(data)
                data['X-MMe-Client-Info'] = PROFILES[profile]
            return super().respond(status, data)
    return IdentityHandler


def serve(profile):
    spec = importlib.util.spec_from_file_location('deployed_bridge', BASE / 'bridge.py')
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    identity = bridge.fetch_provider_identity(SOURCE_URL)
    state = BASE / 'anisette-state.plist'
    bridge.read_fresh_state(state)
    server = bridge.ThreadingHTTPServer(('127.0.0.1', 16972), handler_class(bridge, profile))
    server.provider_identity = identity  # Keep the provider POST User-Agent unchanged.
    server.fresh_state_file = state     # Existing isolated identity, read-only.
    server.fresh_lock = threading.Lock()
    server.headers_url = SOURCE_URL.rsplit('/', 1)[0] + '/get_headers'
    print('Client-Info-only trial: ' + profile, flush=True)
    print('Response Client-Info: ' + PROFILES[profile], flush=True)
    print('Provider, ADI state and provider User-Agent unchanged; phone selects its own UA.', flush=True)
    server.serve_forever()


def probe(profile=None):
    path = '/' if profile else '/healthz'
    with urlopen('http://127.0.0.1:16972' + path, timeout=100 if profile else 2) as response:
        data = json.load(response)
    if profile:
        if data.get('X-MMe-Client-Info') != PROFILES[profile]:
            raise RuntimeError('Trial Client-Info mismatch.')
        for name in ('X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Apple-I-Client-Time'):
            if not isinstance(data.get(name), str) or not data[name]:
                raise RuntimeError('Trial Anisette validation failed (values redacted).')
    elif data.get('ready') is not True:
        raise RuntimeError('Trial is not ready.')


class Trial:
    def __init__(self, root=Path('/'), runner=subprocess.run, check=probe, pause=time.sleep):
        self.root, self.runner, self.check, self.pause = root, runner, check, pause
        self.home = self.at('/run/altserver-identity-trial')
        self.unit = self.at('/run/systemd/system/' + UNIT)
        self.dropin = self.at('/run/systemd/system/altserver.service.d/95-anisette-identity-trial.conf')
        self.permanent_dropin = self.at('/etc/systemd/system/altserver.service.d/90-keeper-auth-trial.conf')

    def at(self, path):
        return self.root / str(path).lstrip('/')

    def call(self, *args, required=True):
        result = self.runner(list(args), text=True, capture_output=True, timeout=45)
        if required and result.returncode:
            raise RuntimeError('Command failed: ' + ' '.join(args[:3]))
        return result

    def active(self, unit):
        return self.call('systemctl', 'is-active', '--quiet', unit, required=False).returncode == 0

    def endpoint(self, expected):
        pid = self.call('systemctl', 'show', ALT, '-p', 'MainPID', '--value').stdout.strip()
        if not pid.isdecimal() or int(pid) == 0:
            raise RuntimeError('AltServer has no process.')
        proc = self.at('/proc/' + pid)
        if (proc / 'exe').resolve() != self.at(BASE / 'AltServer-aarch64').resolve():
            raise RuntimeError('Unexpected AltServer executable; no automatic replacement.')
        env = (proc / 'environ').read_bytes().split(b'\0')
        wanted = ('ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:' + str(expected)).encode()
        if wanted not in env:
            raise RuntimeError('AltServer endpoint does not match the expected configuration.')

    @staticmethod
    def write(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.new')
        temporary.write_text(content)
        temporary.chmod(0o644)
        temporary.replace(path)

    def contents(self, profile, permanent):
        commands = [line for line in permanent.splitlines()
                    if line.startswith('ExecStart=') and line != 'ExecStart=']
        if len(commands) != 1 or commands[0].count('http://127.0.0.1:16971') != 1:
            raise RuntimeError('Unexpected persistent ExecStart; refusing to replace it.')
        if str(BASE / 'AltServer-aarch64') not in commands[0]:
            raise RuntimeError('Persistent ExecStart is not the known deployment.')
        command = commands[0].replace('http://127.0.0.1:16971', 'http://127.0.0.1:16972')
        unit = f'''[Unit]
Description=Temporary Anisette Client-Info-only trial
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=pi
ExecStart=/usr/bin/python3 -u /run/altserver-identity-trial/server.py serve {profile}
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
'''
        override = f'''[Unit]
Wants={UNIT}
After={UNIT}

[Service]
ExecStart=
{command}
'''
        return {self.unit: unit, self.dropin: override}

    def apply(self, profile):
        if any(p.exists() or p.is_symlink() for p in (self.home, self.unit, self.dropin)):
            raise RuntimeError('Trial paths already exist. Run status or rollback before another trial.')
        for path in (BASE / 'APPLIED', BASE / 'bridge.py', BASE / 'anisette-state.plist'):
            if not self.at(path).is_file():
                raise RuntimeError('The expected persistent fresh-header deployment is missing.')
        if not self.active(ALT) or not self.active(BASE_UNIT):
            raise RuntimeError('The persistent AltServer and bridge must both be active.')
        if self.call('systemctl', 'show', UNIT, '-p', 'LoadState', '--value').stdout.strip() != 'not-found':
            raise RuntimeError('Trial unit name is already in use.')
        self.endpoint(16971)
        files = self.contents(profile, self.permanent_dropin.read_text())
        self.home.mkdir(mode=0o755)
        self.home.chmod(0o755)
        try:
            shutil.copyfile(__file__, self.home / 'server.py')
            (self.home / 'server.py').chmod(0o644)
            manifest = {'profile': profile, 'files': {
                str(p): hashlib.sha256(s.encode()).hexdigest() for p, s in files.items()}}
            self.write(self.home / 'manifest.json', json.dumps(manifest))
            self.write(self.unit, files[self.unit])
            self.call('systemctl', 'daemon-reload')
            self.call('systemctl', 'start', UNIT)
            for attempt in range(25):
                if self.active(UNIT):
                    try:
                        self.check()
                        break
                    except Exception:
                        pass
                if attempt == 24:
                    raise RuntimeError('Trial bridge did not become ready.')
                self.pause(1)
            self.check(profile)  # Generate headers only; never perform Apple account login.
            self.write(self.dropin, files[self.dropin])
            self.call('systemctl', 'daemon-reload')
            self.call('systemctl', 'restart', ALT)
            self.pause(2)
            if not self.active(ALT) or not self.active(UNIT):
                raise RuntimeError('Trial services did not remain active.')
            self.endpoint(16972)
        except (Exception, KeyboardInterrupt):
            print('Trial setup failed; restoring the persistent configuration...', flush=True)
            if (self.home / 'manifest.json').exists():
                self.rollback()
            else:
                shutil.rmtree(self.home)
            raise
        print('Client-Info-only trial active: ' + profile)
        print('Provider/ADI state/provider UA unchanged. Phone refresh is still unverified.')
        print('Temporary until reboot. Rollback: sudo python3 ' + str(Path(__file__).resolve()) + ' rollback')

    def rollback(self):
        manifest_path = self.home / 'manifest.json'
        if not manifest_path.exists():
            if any(p.exists() or p.is_symlink() for p in (self.home, self.unit, self.dropin)):
                raise RuntimeError('Unmanaged trial paths found; refusing to remove them.')
            print('No temporary identity trial is installed (or it was cleared by reboot).')
            return
        data = json.loads(manifest_path.read_text())
        if set(data['files']) != {str(self.unit), str(self.dropin)}:
            raise RuntimeError('Unexpected trial manifest paths.')
        for path, checksum in data['files'].items():
            p = Path(path)
            if p.is_symlink() or (p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() != checksum):
                raise RuntimeError('Trial unit was edited; refusing to overwrite it.')
        switched = self.dropin.exists()
        self.dropin.unlink(missing_ok=True)
        self.call('systemctl', 'daemon-reload')
        if switched:
            self.call('systemctl', 'restart', ALT)
            self.pause(2)
            self.endpoint(16971)
        self.call('systemctl', 'stop', UNIT, required=False)
        self.unit.unlink(missing_ok=True)
        self.call('systemctl', 'daemon-reload')
        self.call('systemctl', 'reset-failed', UNIT, required=False)
        shutil.rmtree(self.home)
        print('Original persistent Anisette endpoint restored. Keeper and ADI state were not changed.')

    def status(self):
        manifest = self.home / 'manifest.json'
        if not manifest.exists():
            print('No temporary identity trial is installed.')
            return
        data = json.loads(manifest.read_text())
        print('Profile: ' + data['profile'])
        print('Trial bridge active: ' + str(self.active(UNIT)))
        print('AltServer active: ' + str(self.active(ALT)))
        if self.dropin.exists():
            self.endpoint(16972)
            print('AltServer endpoint: 16972 (temporary trial)')
        else:
            print('Trial override absent; setup or rollback may be incomplete.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'status', 'rollback', 'serve'))
    parser.add_argument('profile', choices=tuple(PROFILES), nargs='?', default='windows')
    args = parser.parse_args()
    if args.action == 'serve':
        serve(args.profile)
        return
    if os.geteuid() != 0:
        parser.error('Use sudo for apply/status/rollback.')
    trial = Trial()
    try:
        if args.action == 'apply':
            trial.apply(args.profile)
        else:
            getattr(trial, args.action)()
    except Exception as error:
        # Provider responses/state are never included in this controller's errors.
        print('Identity trial failed: ' + type(error).__name__, flush=True)
        if isinstance(error, RuntimeError):
            print(str(error), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
