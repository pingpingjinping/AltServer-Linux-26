#!/usr/bin/env python3
"""Opt-in loopback adapter for an ALREADY provisioned, isolated v3 identity.

Never provisions, writes state, manages services or calls an Apple account API.
No AltKeeper RPC or default state path is used.
"""
import argparse
import base64
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import plistlib
import ssl
import threading
import uuid
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import keeper_v3_anisette_bridge as bridge


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def exchange(request):
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    with opener.open(request, timeout=20) as response:
        return json.loads(bridge.read_response(response))


class IsolatedProvider:
    def __init__(self, state_file, provider, identity_source='provider'):
        bridge.https_origin(provider)
        self.state_file = Path(state_file)
        self.provider = provider.rstrip('/')
        self.identity_source = identity_source
        self.lock = threading.Lock()

    def headers(self, sim=None):
        with self.lock:
            # Bounded read, never write or implicitly re-provision a rejected identity.
            with self.state_file.open('rb') as stream:
                raw = stream.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('Oversized isolated state')
            state = plistlib.loads(raw)
            identifier, adi = state.get('keychain_identifier'), state.get('adi_pb')
            if not isinstance(identifier, bytes) or len(identifier) != 16 or not isinstance(adi, bytes) or not adi:
                raise ValueError('Unprovisioned isolated state')
            identity = {'client_info': state.get('provisioned_client_info'),
                        'user_agent': state.get('provisioned_user_agent')}
            if state.get('provider_url', '').rstrip('/') != self.provider:
                raise ValueError('Isolated state provider mismatch')
            for value in identity.values():
                if (not isinstance(value, str) or not 0 < len(value) <= 2048
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                    raise ValueError('Missing provisioning identity metadata')
            advertised = exchange(Request(self.provider + '/v3/client_info'))
            if self.identity_source == 'provider' and any(advertised.get(k) != v for k, v in identity.items()):
                raise ValueError('Provider identity changed; separately provision a compatible identity')
            body = {'identifier': base64.b64encode(identifier).decode('ascii'),
                    'adi_pb': base64.b64encode(adi).decode('ascii')}
            device = str(uuid.UUID(bytes=identifier))
            local_user = hashlib.sha256(identifier).hexdigest()
            if sim is not None:
                if not isinstance(sim, str) or not 0 < len(sim) <= 65536:
                    raise ValueError('Invalid resync data')
                # Official RemoteAnisetteDataFetcher: sim + device_id + md_lu.
                body.update(sim=sim, device_id=device, md_lu=local_user)
            result = exchange(Request(self.provider + '/v3/get_headers',
                data=json.dumps(body).encode(), headers={'Content-Type': 'application/json',
                'User-Agent': identity['user_agent']}, method='POST'))
            response = {'identifier': 'AnisetteDataResponse', 'anisetteData': {
                'machineID': result.get('X-Apple-I-MD-M'),
                'oneTimePassword': result.get('X-Apple-I-MD'),
                'routingInfo': result.get('X-Apple-I-MD-RINFO'),
                'localUserID': local_user, 'deviceUniqueIdentifier': device,
                'deviceSerialNumber': '2', 'deviceDescription': identity['client_info'],
                'date': dt.datetime.now(dt.timezone.utc).isoformat(),
                'locale': 'en_US', 'timeZone': 'GMT'}}
            headers = bridge.convert_response(response)
            headers.update(authenticationUserAgent=identity['user_agent'],
                           provisionedClientInfo=identity['client_info'],
                           provisionedUserAgent=identity['user_agent'])
            return headers


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        if (self.command, self.path) not in (('GET', '/'), ('POST', '/resync')):
            return self.respond(404, {'error': 'Not found'})
        try:
            sim = None
            if self.command == 'POST':
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 128 * 1024:
                    return self.respond(400, {'error': 'Invalid request size'})
                sim = json.loads(self.rfile.read(length))['sim']
                if not isinstance(sim, str) or not 0 < len(sim) <= 65536:
                    return self.respond(400, {'error': 'Invalid resync data'})
            data = self.server.provider.headers(sim)
            return self.respond(200, data)
        except Exception:
            # Exception messages, state paths, provider bodies and sim are private.
            return self.respond(502, {'error': 'Isolated Anisette provider failed'})

    def respond(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, help='Explicit isolated state; no default')
    parser.add_argument('--provider', required=True, help='HTTPS v3 provider that provisioned this state')
    parser.add_argument('--port', type=int, default=16971)
    parser.add_argument('--identity-source', choices=('provider', 'provisioned'), default='provider',
                        help='provisioned uses the recorded pair; never overwrites the identity')
    args = parser.parse_args()
    provider = IsolatedProvider(args.state, args.provider, args.identity_source)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.provider = provider
    print('Isolated official-auth adapter ready on loopback (values redacted)', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
