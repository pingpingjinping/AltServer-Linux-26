#!/usr/bin/env python3
"""Compare a new macOS provider with new state; preserve the deployed identity."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import sys
import uuid
from urllib.request import urlopen

URL = 'https://mac-ani.jkcoxson.com'
BOOTSTRAP_PORT = 14952
SOURCE_CONTAINER = 'anisette-keeper-v3-backend'
LABEL = 'org.altserver.provider-trial'
BOOTSTRAP_ATTEMPTS = 20


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = load_module('identity_trial_control', Path(__file__).with_name('anisette-identity-trial.py'))


class ProviderTrial(common.Trial):
    kind = 'provider'

    def __init__(self, *args, bridge=None, owner=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.controller_path = Path(__file__).resolve()
        self.bridge = bridge
        self.owner = owner
        self.identity = None
        self.created = None
        self.check = self.probe

    def contents(self, profile, permanent):
        self.identity = self.bridge.fetch_provider_identity(URL + '/v3/client_info')
        if not any(word in self.identity['client_info'] for word in ('Mac', 'macOS')):
            raise RuntimeError('Provider no longer advertises a Mac identity; stop for review.')
        files = super().contents(profile, permanent)
        # Use the deployed bridge without any Client-Info-only wrapper.
        unit = files[self.unit].splitlines()
        for index, line in enumerate(unit):
            if line.startswith('Description='):
                unit[index] = 'Description=Temporary isolated macOS Anisette provider trial'
            elif line.startswith('ExecStart='):
                unit[index] = (
                    'ExecStart=/usr/bin/python3 -u /opt/altserver-keeper-v3/bridge.py'
                    ' --port 16972 --fresh-state-file /run/altserver-identity-trial/provider-state.plist'
                    ' --client-info-url ' + URL + '/v3/client_info')
        files[self.unit] = '\n'.join(unit) + '\n'
        return files

    def update_manifest(self, **updates):
        path = self.home / 'manifest.json'
        data = json.loads(path.read_text())
        data.update(updates)
        self.write(path, json.dumps(data))

    def bootstrap_status(self, cid):
        # Never dump container logs, environment, or Docker's free-text Error:
        # they may contain provisioning data. Only report typed lifecycle fields.
        result = self.call('docker', 'inspect', '--type', 'container', cid,
                           '--format', '{{json .State}}')
        state = json.loads(result.stdout)
        running, exit_code, oom = (state.get('Running'), state.get('ExitCode'),
                                   state.get('OOMKilled'))
        if type(running) is not bool or type(exit_code) is not int or type(oom) is not bool:
            raise RuntimeError('Cannot read bootstrap lifecycle status safely.')
        summary = f'running={running}, exit_code={exit_code}, oom_killed={oom}'
        return running, summary

    def wait_for_bootstrap(self, cid):
        for attempt in range(BOOTSTRAP_ATTEMPTS):
            running, summary = self.bootstrap_status(cid)
            if not running:
                raise RuntimeError('Bootstrap container exited: ' + summary)
            try:
                # Retry only transport startup failures, not a rejected or
                # malformed provider response. Each call asks only for Anisette.
                self.bridge.fetch_anisette(BOOTSTRAP_PORT)
                return
            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as error:
                running, summary = self.bootstrap_status(cid)
                if not running or attempt == BOOTSTRAP_ATTEMPTS - 1:
                    raise RuntimeError('Bootstrap RPC failed: ' + type(error).__name__
                                       + '; ' + summary) from None
                if attempt == 0:
                    print('Bootstrap RPC not ready (' + type(error).__name__
                          + '); retrying startup connection up to '
                          + str(BOOTSTRAP_ATTEMPTS) + ' attempts...', flush=True)
                self.pause(1)
            except Exception as error:
                _, summary = self.bootstrap_status(cid)
                print('Bootstrap request failed: ' + type(error).__name__
                      + '; ' + summary + ' (response and logs redacted)', flush=True)
                raise

    def prepare(self, profile):
        # Reuse the image of the stopped, isolated old backend, never a moving
        # latest tag or the insurance container. No image pull/build is done.
        result = self.call('docker', 'inspect', '--type', 'container', SOURCE_CONTAINER,
                           '--format', '{{.Image}}')
        image = result.stdout.strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise RuntimeError('The previous isolated backend image could not be identified.')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', BOOTSTRAP_PORT))
        storage = self.home / 'bootstrap'
        storage.mkdir(mode=0o700)  # Empty directory; never copy an existing state.
        token = uuid.uuid4().hex
        name = 'anisette-provider-trial-' + token[:12]
        self.update_manifest(provider=URL, bootstrap_image=image, owner_token=token,
                             container_name=name)
        print('Provisioning NEW isolated state with ' + URL + ' ...', flush=True)
        print('No Apple ID, pairing record or existing ADI state is supplied.', flush=True)
        result = self.call(
            'docker', 'create', '--pull=never', '--restart=no',
            '--name', name,
            '--label', LABEL + '=' + token,
            '--network', 'bridge', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '-p', '127.0.0.1:' + str(BOOTSTRAP_PORT) + ':49500',
            '--mount', 'type=bind,source=' + str(storage) + ',target=/data',
            '-e', 'ALTKEEPER_ANISETTE_URL=' + URL,
            '--entrypoint', '/usr/local/bin/altkeeper', image,
            'altserver', '--port', '49500', '--dir', '/data')
        cid = result.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            raise RuntimeError('Unexpected bootstrap container identifier.')
        self.created = (cid, token)
        self.update_manifest(container_id=cid)
        self.call('docker', 'start', cid)
        self.wait_for_bootstrap(cid)
        source = storage / 'state/anisette_state'
        self.bridge.read_fresh_state(source)
        target = self.home / 'provider-state.plist'
        shutil.copyfile(source, target)
        target.chmod(0o600)
        user = self.owner or pwd.getpwnam('pi')
        os.chown(target, user.pw_uid, user.pw_gid)
        self.cleanup()  # Stop and remove only this helper's disposable bootstrap.
        print('New provider state created; checking the direct fresh-header path...', flush=True)

    def cleanup(self):
        data = json.loads((self.home / 'manifest.json').read_text())
        cid = data.get('container_id')
        token = data.get('owner_token')
        if not cid and self.created:
            cid, token = self.created
        if not cid and data.get('container_name'):
            name = data['container_name']
            if (not re.fullmatch(r'[0-9a-f]{32}', token or '')
                    or name != 'anisette-provider-trial-' + token[:12]):
                raise RuntimeError('Unexpected bootstrap recovery metadata.')
            # Also recover a create operation that completed in Docker but
            # timed out before the client received/persisted its container ID.
            result = self.call('docker', 'ps', '-aq', '--no-trunc',
                               '--filter', 'name=^/' + name + '$',
                               '--filter', 'label=' + LABEL + '=' + token)
            matches = result.stdout.split()
            if len(matches) > 1:
                raise RuntimeError('Ambiguous bootstrap recovery result.')
            cid = matches[0] if matches else None
        if not cid:
            return
        if not re.fullmatch(r'[0-9a-f]{64}', cid) or not re.fullmatch(r'[0-9a-f]{32}', token or ''):
            raise RuntimeError('Unexpected bootstrap ownership metadata.')
        result = self.call('docker', 'inspect', '--type', 'container', cid,
                           '--format', '{{json .Config.Labels}}', required=False)
        if result.returncode:
            # A failed inspect can mean Docker is unavailable, not just removal.
            listing = self.call('docker', 'ps', '-aq', '--no-trunc')
            if cid in listing.stdout.split():
                raise RuntimeError('Cannot verify bootstrap container ownership.')
        else:
            labels = json.loads(result.stdout)
            if labels.get(LABEL) != token:
                raise RuntimeError('Bootstrap ownership mismatch; refusing to stop it.')
            self.call('docker', 'stop', '--time', '5', cid)
            self.call('docker', 'rm', cid)
        self.created = None
        self.update_manifest(container_id=None)

    def probe(self, profile=None):
        if not profile:
            return common.probe()
        with urlopen('http://127.0.0.1:16972/', timeout=100) as response:
            data = json.load(response)
        if data.get('X-MMe-Client-Info') != self.identity['client_info']:
            raise RuntimeError('Fresh trial does not match the new provider Client-Info.')
        for key in ('X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Apple-I-MD-LU',
                    'X-Mme-Device-Id', 'X-Apple-I-Client-Time'):
            if not isinstance(data.get(key), str) or not data[key]:
                raise RuntimeError('New provider response is incomplete (values redacted).')
        print('Provider Client-Info: ' + data['X-MMe-Client-Info'], flush=True)
        print('Fresh Anisette response validated; private fields discarded.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'status', 'rollback'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Use sudo.')
    try:
        bridge = None
        if args.action == 'apply':
            bridge = load_module('deployed_bridge', common.BASE / 'bridge.py')
        trial = ProviderTrial(bridge=bridge)
        if args.action == 'apply':
            trial.apply('jkcoxson-mac')
        else:
            getattr(trial, args.action)()
    except Exception as error:
        print('Provider trial failed: ' + type(error).__name__, flush=True)
        if isinstance(error, RuntimeError):
            print(str(error), flush=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
