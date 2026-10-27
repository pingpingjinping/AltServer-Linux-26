#!/usr/bin/env python3
"""Opt-in fresh Mac identity + bounded provider retry trial, with rollback."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sys
from urllib.request import Request, urlopen

URL = 'https://mac-ani.jkcoxson.com'
SCRIPTS = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


common = module('modern_trial_control', SCRIPTS / 'anisette-identity-trial.py')
bridge = module('modern_trial_bridge', SCRIPTS / 'keeper_v3_anisette_bridge.py')


class ModernMacTrial(common.Trial):
    kind = 'modern-mac'

    def __init__(self, *args, owner=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.owner = owner
        self.controller_path = Path(__file__).resolve()
        self.identity = None
        self.check = self.probe

    def contents(self, profile, permanent):
        advertised = bridge.network_operation('provider metadata', bridge.fetch_provider_identity,
                                              URL + '/v3/client_info')
        self.identity = bridge.current_mac_identity(advertised)
        if any(char in self.identity['user_agent'] for char in ('"', '\\', '%')):
            raise ValueError('Provider User-Agent cannot be represented safely in a systemd command')
        files = super().contents(profile, permanent)
        lines = files[self.unit].splitlines()
        for index, line in enumerate(lines):
            if line.startswith('Description='):
                lines[index] = 'Description=Temporary fresh modern-Mac Anisette trial'
            elif line.startswith('ExecStart='):
                lines[index] = ('ExecStart=/usr/bin/python3 -u /run/altserver-identity-trial/bridge.py'
                                ' --port 16972 --current-mac'
                                ' --fresh-state-file /run/altserver-identity-trial/modern-state.plist'
                                ' --client-info-url ' + URL + '/v3/client_info')
        files[self.unit] = '\n'.join(lines) + '\n'
        # This environment controls Pi-side authentication only, not Classic's UA.
        pattern = r'"ALTSERVER_GSA_USER_AGENT=[^"\r\n]*"'
        override, count = re.subn(pattern,
                                 '"ALTSERVER_GSA_USER_AGENT=' + self.identity['user_agent'] + '"',
                                 files[self.dropin])
        if count != 1:
            raise RuntimeError('Expected one quoted persistent authentication User-Agent.')
        files[self.dropin] = override
        return files

    def prepare(self, profile):
        # Run the reviewed script copy; leave the deployed bridge and ADI intact.
        shutil.copyfile(SCRIPTS / 'keeper_v3_anisette_bridge.py', self.home / 'bridge.py')
        (self.home / 'bridge.py').chmod(0o644)
        state = self.home / 'modern-state.plist'
        print('Provisioning a NEW machine identity as the selected current Mac (no Apple ID)...', flush=True)
        bridge.provision_current_mac_state(state, URL, self.identity)
        bridge.validate_current_mac_state(state, URL, self.identity)
        user = self.owner or pwd.getpwnam('pi')
        os.chown(state, user.pw_uid, user.pw_gid)
        state.chmod(0o600)

    def probe(self, profile=None):
        if not profile:
            return common.probe()
        with urlopen('http://127.0.0.1:16972/', timeout=25) as response:
            data = json.load(response)
        if data.get('X-MMe-Client-Info') != self.identity['client_info']:
            raise RuntimeError('Trial returned a different Mac profile.')
        for key in ('X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Apple-I-MD-LU',
                    'X-Mme-Device-Id', 'X-Apple-I-Client-Time'):
            if not isinstance(data.get(key), str) or not data[key]:
                raise RuntimeError('Fresh Mac response is incomplete (private values redacted).')
        print('Fresh Mac identity and provider headers verified; Classic still chooses its own UA.', flush=True)


def diagnose():
    """Public metadata/URL-bag GETs only: no state, services or provisioning."""
    advertised = bridge.network_operation('provider metadata', bridge.fetch_provider_identity,
                                          URL + '/v3/client_info')
    identity = bridge.current_mac_identity(advertised)
    print('Provider metadata: OK', flush=True)
    request = Request('https://gsa.apple.com/grandslam/GsService2/lookup', headers={
        'X-Mme-Client-Info': identity['client_info'], 'User-Agent': identity['user_agent'],
        'Content-Type': 'text/x-xml-plist', 'Accept': 'text/x-xml-plist',
        'X-Apple-App-Info': 'com.apple.gs.xcode.auth', 'X-Xcode-Version': '14.2 (14C18)'})
    def lookup():
        with urlopen(request, timeout=20) as response:
            data = bridge.plistlib.loads(bridge.read_response(
                response, 1024 * 1024, bridge.time.monotonic() + 20))
        if not isinstance(data, dict) or not isinstance(data.get('urls'), dict):
            raise ValueError('Invalid Apple URL bag')
    bridge.network_operation('Apple URL lookup', lookup)
    print('Apple URL lookup: OK', flush=True)
    print('Read-only diagnosis finished; no identity or service was changed.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'status', 'rollback', 'diagnose'))
    args = parser.parse_args()
    if args.action != 'diagnose' and os.geteuid() != 0:
        parser.error('Use sudo.')
    trial = ModernMacTrial()
    try:
        if args.action == 'diagnose':
            diagnose()
        elif args.action == 'apply':
            trial.apply('modern-mac')
        else:
            getattr(trial, args.action)()
    except Exception as error:
        # Fixed phase and typed details only; opaque response text stays private.
        print('Modern Mac trial failed: ' + type(error).__name__, flush=True)
        print(bridge.network_error_summary(error), flush=True)
        if isinstance(error, RuntimeError):
            # Controller RuntimeErrors contain only our own fixed preflight messages.
            print(str(error), flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
