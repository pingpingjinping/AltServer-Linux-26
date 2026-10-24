#!/usr/bin/env python3
"""Loopback-only AltKeeper Anisette RPC -> AltServer v1 JSON adapter.

This sends only AnisetteDataRequest; it has no account, signing or phone APIs.
The backend's state belongs to a separate, disposable container.
"""
import argparse
import base64
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pathlib
import plistlib
import socket
import struct
import threading
import uuid
from urllib.request import Request, urlopen


def fetch_provider_identity(url):
    if not url.startswith('https://'):
        raise ValueError('Provider metadata requires HTTPS')
    request = Request(url, headers={'User-Agent': 'AltServer-Anisette-Bridge/1.0'})
    with urlopen(request, timeout=15) as response:
        payload = response.read(65537)
    if len(payload) > 65536:
        raise ValueError('Provider metadata is too large')
    data = json.loads(payload)
    for field in ('client_info', 'user_agent'):
        value = data.get(field)
        if not isinstance(value, str) or not value or '\n' in value or '\r' in value:
            raise ValueError('Invalid provider identity metadata')
    return {k: data[k] for k in ('client_info', 'user_agent')}

FIELDS = {
    'machineID': 'X-Apple-I-MD-M',
    'oneTimePassword': 'X-Apple-I-MD',
    'localUserID': 'X-Apple-I-MD-LU',
    'routingInfo': 'X-Apple-I-MD-RINFO',
    'deviceUniqueIdentifier': 'X-Mme-Device-Id',
    'deviceSerialNumber': 'X-Apple-I-SRL-NO',
    'deviceDescription': 'X-MMe-Client-Info',
    'locale': 'X-Apple-Locale',
    'timeZone': 'X-Apple-I-TimeZone',
}


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ValueError('Incomplete backend response')
        data.extend(chunk)
    return bytes(data)


def convert_response(response):
    if response.get('identifier') != 'AnisetteDataResponse':
        raise ValueError('Backend did not return AnisetteDataResponse')
    data = response.get('anisetteData')
    if not isinstance(data, dict):
        raise ValueError('Missing Anisette data object')
    result = {}
    for source, target in FIELDS.items():
        value = data.get(source)
        if source == 'routingInfo' and type(value) is int:
            value = str(value)
        if not isinstance(value, str) or not value:
            raise ValueError('Missing Anisette field: ' + source)
        result[target] = value
    value = data.get('date')
    if not isinstance(value, str):
        raise ValueError('Missing Anisette date')
    try:
        stamp = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError()
        stamp = stamp.astimezone(dt.timezone.utc)
    except ValueError:
        raise ValueError('Invalid Anisette date') from None
    if abs((dt.datetime.now(dt.timezone.utc) - stamp).total_seconds()) > 120:
        raise ValueError('Stale Anisette response')
    result['X-Apple-I-Client-Time'] = stamp.strftime('%Y-%m-%dT%H:%M:%SZ')
    return result


def fetch_anisette(port):
    request = json.dumps({'version': 1, 'identifier': 'AnisetteDataRequest'}).encode()
    with socket.create_connection(('127.0.0.1', port), timeout=90) as sock:
        sock.sendall(struct.pack('<I', len(request)) + request)
        size, = struct.unpack('<I', receive_exact(sock, 4))
        if not 0 < size <= 1024 * 1024:
            raise ValueError('Invalid backend frame size')
        response = json.loads(receive_exact(sock, size))
    return convert_response(response)


def read_fresh_state(path):
    # A private snapshot of the isolated trial's state, never the insurance state.
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('Anisette state is too large')
    state = plistlib.loads(raw)
    identifier, adi_pb = state.get('keychain_identifier'), state.get('adi_pb')
    if not isinstance(identifier, bytes) or len(identifier) != 16:
        raise ValueError('Invalid Anisette state identifier')
    if not isinstance(adi_pb, bytes) or not adi_pb:
        raise ValueError('Anisette state is not provisioned')
    return identifier, adi_pb


def fetch_fresh_anisette(state_path, headers_url, identity):
    if not headers_url.startswith('https://'):
        raise ValueError('Anisette headers require HTTPS')
    identifier, adi_pb = read_fresh_state(state_path)
    request = Request(headers_url, data=json.dumps({
        'identifier': base64.b64encode(identifier).decode('ascii'),
        'adi_pb': base64.b64encode(adi_pb).decode('ascii'),
    }).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    # Call the same provider with the same identity on every request. Bypass only
    # Keeper's RPC cache; the remote provider can still choose to reuse an OTP.
    with urlopen(request, timeout=90) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError('Anisette headers response is too large')
    headers = json.loads(raw)
    response = {'identifier': 'AnisetteDataResponse', 'anisetteData': {
        'machineID': headers.get('X-Apple-I-MD-M'),
        'oneTimePassword': headers.get('X-Apple-I-MD'),
        'routingInfo': headers.get('X-Apple-I-MD-RINFO'),
        'localUserID': hashlib.sha256(identifier).hexdigest(),
        'deviceUniqueIdentifier': str(uuid.UUID(bytes=identifier)),
        'deviceSerialNumber': '2',
        'deviceDescription': identity['client_info'],
        'date': dt.datetime.now(dt.timezone.utc).isoformat(),
        'locale': 'en_US', 'timeZone': 'GMT',
    }}
    return convert_response(response)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/healthz':
            return self.respond(200, {'ready': True})
        if self.path != '/':
            return self.respond(404, {'error': 'Not found'})
        try:
            state_path = getattr(self.server, 'fresh_state_file', None)
            if state_path:
                with self.server.fresh_lock:
                    data = fetch_fresh_anisette(
                        state_path, self.server.headers_url, self.server.provider_identity)
            else:
                data = fetch_anisette(self.server.backend_port)
            # Keeper's fork hardcodes its own client description. The actual
            # provider can advertise a different identity; forward that identity.
            identity = getattr(self.server, 'provider_identity', None)
            if identity:
                data['X-MMe-Client-Info'] = identity['client_info']
        except Exception as exc:
            # Do not print exceptions or response objects containing backend data.
            print('Anisette backend request failed: ' + type(exc).__name__, flush=True)
            return self.respond(502, {'error': 'Anisette backend request failed'})
        print('Anisette v3 response validated (values redacted)', flush=True)
        self.respond(200, data)

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
    parser.add_argument('--port', type=int, default=16971)
    parser.add_argument('--backend-port', type=int, default=14951)
    parser.add_argument('--client-info-url', default='https://ani3.stikstore.app/v3/client_info')
    parser.add_argument('--fresh-state-file', default=os.environ.get('ALTSERVER_ANISETTE_FRESH_STATE'))
    args = parser.parse_args()
    identity = fetch_provider_identity(args.client_info_url)
    if args.fresh_state_file:
        read_fresh_state(args.fresh_state_file)
    # These are public provider metadata, never OTPs or account information.
    print('Provider client_info: ' + identity['client_info'], flush=True)
    print('Provider user_agent: ' + identity['user_agent'], flush=True)
    print('The phone still chooses its own authentication User-Agent.', flush=True)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.backend_port = args.backend_port
    server.provider_identity = identity
    server.fresh_state_file = args.fresh_state_file
    server.fresh_lock = threading.Lock()
    server.headers_url = args.client_info_url.rsplit('/', 1)[0] + '/get_headers'
    print('Header mode: ' + ('direct provider (Keeper cache bypassed)' if args.fresh_state_file
                             else 'Keeper RPC (backend cache applies)'), flush=True)
    print('Anisette bridge listening on localhost (no account or phone access)', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
