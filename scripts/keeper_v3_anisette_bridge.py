#!/usr/bin/env python3
"""Loopback-only AltKeeper Anisette RPC -> AltServer v1 JSON adapter.

Normal operation only fetches Anisette, with no account, signing or phone APIs.
The opt-in modern-Mac trial can provision a NEW isolated machine identity.
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
import re
import secrets
import socket
import ssl
import struct
import threading
import time
import uuid
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

CURRENT_MAC_CLIENT_INFO = '<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>'
CURRENT_MAC_USER_AGENT = 'AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)'
HEADER_ATTEMPTS = 3
HEADER_IO_TIMEOUT = 5
HEADER_RETRY_WINDOW = 20
MAX_RESPONSE = 65536


def https_origin(url):
    parts = urlsplit(url)
    if (parts.scheme != 'https' or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment
            or parts.port not in (None, 443)):
        raise ValueError('Expected an HTTPS provider URL without credentials or query')
    return parts


def current_mac_identity(advertised):
    match = re.search(r'<(?:macOS|Mac OS X);(\d+)(?:\.(\d+))?', advertised['client_info'])
    if not match:
        raise ValueError('Modern Mac trial requires a macOS ADI provider')
    version = (int(match[1]), int(match[2] or 0))
    if version < (10, 13):
        return {'client_info': CURRENT_MAC_CLIENT_INFO, 'user_agent': CURRENT_MAC_USER_AGENT}
    return dict(advertised)


def read_response(response, limit=MAX_RESPONSE, deadline=None):
    """Bound response size and check the retry window between body reads."""
    result = bytearray()
    read = getattr(response, 'read1', response.read)
    while len(result) <= limit:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('Anisette response exceeded its request window')
        chunk = read(min(8192, limit + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
    raise ValueError('Provider response is too large')


def request_headers(request):
    """Retry only provider HTTP 5xx, never Apple login or provisioning requests."""
    deadline = time.monotonic() + HEADER_RETRY_WINDOW
    for attempt in range(HEADER_ATTEMPTS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Anisette retry window expired')
        try:
            with urlopen(request, timeout=min(HEADER_IO_TIMEOUT, remaining)) as response:
                return read_response(response, deadline=deadline)
        except HTTPError as error:
            if not 500 <= error.code <= 599 or attempt == HEADER_ATTEMPTS - 1:
                raise
            error.close()
            if deadline - time.monotonic() <= 1:
                raise TimeoutError('Anisette retry window expired') from None
            # Public status only; provider bodies and all identity fields stay private.
            print('Anisette provider HTTP ' + str(error.code) + '; retrying header request', flush=True)
            time.sleep(1)


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


def validate_current_mac_state(path, provider, identity):
    read_fresh_state(path)
    state = plistlib.loads(pathlib.Path(path).read_bytes())
    if (state.get('provider_url') != provider
            or state.get('provisioned_client_info') != identity['client_info']
            or state.get('provisioned_user_agent') != identity['user_agent']):
        raise ValueError('State was not provisioned with this provider and Mac profile')


class ProvisioningSocket:
    """Small RFC 6455 client for the v3 provisioning JSON exchange (TLS only)."""
    MAX_MESSAGE = 1024 * 1024

    def __init__(self, provider, deadline):
        parts = https_origin(provider)
        self.deadline, self.buffer, self.sock = deadline, bytearray(), None
        raw = socket.create_connection((parts.hostname, 443), timeout=self.remaining())
        try:
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=parts.hostname)
            key = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
            path = parts.path.rstrip('/') + '/v3/provisioning_session'
            request = (f'GET {path} HTTP/1.1\r\nHost: {parts.hostname}\r\n'
                       'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                       f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
            self.sock.sendall(request.encode('ascii'))
            while b'\r\n\r\n' not in self.buffer:
                self.sock.settimeout(self.remaining())
                chunk = self.sock.recv(4096)
                if not chunk or len(self.buffer) + len(chunk) > 16384:
                    raise ValueError('Invalid provisioning WebSocket handshake')
                self.buffer.extend(chunk)
            head, tail = bytes(self.buffer).split(b'\r\n\r\n', 1)
            self.buffer = bytearray(tail)
            lines = head.decode('ascii').split('\r\n')
            fields = dict(line.split(':', 1) for line in lines[1:])
            fields = {k.lower(): v.strip().lower() if k.lower() in ('upgrade', 'connection') else v.strip()
                      for k, v in fields.items()}
            expected = base64.b64encode(hashlib.sha1(
                (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()).decode('ascii')
            if (len(lines[0].split()) < 2 or lines[0].split()[1] != '101'
                    or fields.get('sec-websocket-accept') != expected
                    or fields.get('upgrade') != 'websocket'
                    or 'upgrade' not in [token.strip() for token in fields.get('connection', '').split(',')]):
                raise ValueError('Provisioning WebSocket handshake was rejected')
        except BaseException:
            (self.sock or raw).close()
            raise

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('Provisioning deadline expired')
        return min(20, left)

    def exact(self, count):
        while len(self.buffer) < count:
            self.sock.settimeout(self.remaining())
            chunk = self.sock.recv(min(65536, count - len(self.buffer)))
            if not chunk:
                raise ValueError('Provisioning socket closed before completion')
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def send_frame(self, opcode, payload):
        if len(payload) > self.MAX_MESSAGE:
            raise ValueError('Provisioning message is too large')
        length = len(payload)
        header = bytes((0x80 | opcode, 0x80 | (length if length < 126 else 126 if length < 65536 else 127)))
        if length >= 126:
            header += struct.pack('>H' if length < 65536 else '>Q', length)
        mask = secrets.token_bytes(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.settimeout(self.remaining())
        self.sock.sendall(header + mask + masked)

    def send_json(self, data):
        self.send_frame(1, json.dumps(data).encode('utf8'))

    def receive_json(self):
        message, fragmented = bytearray(), False
        for _ in range(128):
            first, second = self.exact(2)
            fin, opcode, size = bool(first & 0x80), first & 15, second & 127
            if first & 0x70 or second & 0x80:
                raise ValueError('Unsupported provisioning WebSocket frame')
            if size == 126:
                size, = struct.unpack('>H', self.exact(2))
            elif size == 127:
                size, = struct.unpack('>Q', self.exact(8))
            if size > self.MAX_MESSAGE or (opcode >= 8 and (not fin or size > 125)):
                raise ValueError('Invalid provisioning WebSocket frame size')
            payload = self.exact(size)
            if opcode == 8:
                raise ValueError('Provisioning socket closed before completion')
            if opcode in (9, 10):
                if opcode == 9:
                    self.send_frame(10, payload)
                continue
            if opcode not in (0, 1) or (opcode == 0) != fragmented:
                raise ValueError('Unexpected provisioning WebSocket message')
            message.extend(payload)
            if len(message) > self.MAX_MESSAGE:
                raise ValueError('Provisioning message is too large')
            if fin:
                data = json.loads(message)
                if not isinstance(data, dict):
                    raise ValueError('Invalid provisioning message')
                return data
            fragmented = True
        raise ValueError('Too many provisioning frames')

    def close(self):
        self.sock.close()


def provision_current_mac_state(path, provider, identity):
    """Provision only machine identity, never an Apple account or phone profile.

    Protocol: SideInstaller v1.6.1 / isideload remote-v3. Existing states are
    never loaded or overwritten. All Apple requests use the same client and UA.
    """
    https_origin(provider)
    target = pathlib.Path(path)
    if target.exists() or target.is_symlink():
        raise ValueError('Refusing to replace an existing identity')
    if current_mac_identity(identity) != identity:
        raise ValueError('Provisioning requires an already selected current Mac profile')
    deadline = time.monotonic() + 120
    identifier = secrets.token_bytes(16)
    headers = {'X-Mme-Client-Info': identity['client_info'],
               'User-Agent': identity['user_agent'],
               'X-Apple-I-MD-LU': hashlib.sha256(identifier).hexdigest(),
               'X-Mme-Device-Id': str(uuid.UUID(bytes=identifier)),
               'Content-Type': 'text/x-xml-plist', 'Accept': 'text/x-xml-plist',
               'X-Apple-App-Info': 'com.apple.gs.xcode.auth', 'X-Xcode-Version': '14.2 (14C18)'}

    def apple(url, body=None):
        parts = https_origin(url)
        if not parts.hostname.endswith('.apple.com'):
            raise ValueError('Provisioning URL bag points outside Apple')
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('Provisioning deadline expired')
        data = None if body is None else plistlib.dumps(body, fmt=plistlib.FMT_XML)
        req = Request(url, data=data, headers=headers, method='GET' if data is None else 'POST')
        with urlopen(req, timeout=min(20, left)) as response:
            result = plistlib.loads(read_response(response, 1024 * 1024, deadline))
        if not isinstance(result, dict):
            raise ValueError('Invalid Apple provisioning response')
        return result

    bag = apple('https://gsa.apple.com/grandslam/GsService2/lookup').get('urls', {})
    endpoints = [bag.get(key) for key in ('midStartProvisioning', 'midFinishProvisioning')]
    if not all(isinstance(url, str) and url for url in endpoints):
        raise ValueError('Apple URL bag lacks provisioning endpoints')
    ws = ProvisioningSocket(provider, deadline)
    stage = 0
    try:
        for _ in range(8):
            payload = ws.receive_json()
            result = payload.get('result')
            if result == 'GiveIdentifier' and stage == 0:
                ws.send_json({'identifier': base64.b64encode(identifier).decode('ascii')})
            elif result in ('GiveStartProvisioningData', 'GiveEndProvisioningData') and stage in (1, 2):
                if result != ('GiveStartProvisioningData' if stage == 1 else 'GiveEndProvisioningData'):
                    raise ValueError('Unexpected provisioning sequence')
                request = {} if stage == 1 else {'cpim': payload['cpim']}
                result = apple(endpoints[stage - 1], {'Header': {}, 'Request': request}).get('Response')
                if not isinstance(result, dict) or result.get('Status', {}).get('ec', 0):
                    raise ValueError('Apple rejected machine provisioning')
                fields = ('spim',) if stage == 1 else ('ptm', 'tk')
                if not all(isinstance(result.get(field), str) and result[field] for field in fields):
                    raise ValueError('Incomplete Apple machine provisioning response')
                ws.send_json({field: result[field] for field in fields})
            elif result == 'ProvisioningSuccess' and stage == 3:
                adi = base64.b64decode(payload['adi_pb'], validate=True)
                if not adi or len(adi) > 1024 * 1024:
                    raise ValueError('Invalid new machine provisioning data')
                state = {'keychain_identifier': identifier, 'adi_pb': adi, 'provider_url': provider,
                         'provisioned_client_info': identity['client_info'],
                         'provisioned_user_agent': identity['user_agent']}
                # Exclusive private creation; never clobber an existing ADI state.
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(fd, 'wb') as output:
                        plistlib.dump(state, output, fmt=plistlib.FMT_BINARY)
                        output.flush()
                        os.fsync(output.fileno())
                except BaseException:
                    target.unlink(missing_ok=True)
                    raise
                return
            else:
                raise ValueError('Unexpected or rejected machine provisioning step')
            stage += 1
        raise ValueError('Machine provisioning did not complete')
    finally:
        ws.close()


def fetch_fresh_anisette(state_path, headers_url, identity):
    if not headers_url.startswith('https://'):
        raise ValueError('Anisette headers require HTTPS')
    identifier, adi_pb = read_fresh_state(state_path)
    request = Request(headers_url, data=json.dumps({
        'identifier': base64.b64encode(identifier).decode('ascii'),
        'adi_pb': base64.b64encode(adi_pb).decode('ascii'),
    }).encode(), headers={
        'Content-Type': 'application/json',
        # This provider rejects Python's default UA with HTTP 403. Use its
        # advertised public UA for the provider request, as for provisioning.
        'User-Agent': identity['user_agent'],
    }, method='POST')
    # Call the same provider with the same identity on every request. Bypass only
    # Keeper's RPC cache; the remote provider can still choose to reuse an OTP.
    raw = request_headers(request)
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
        except HTTPError as exc:
            # Status codes are safe diagnostics; never log the body or request.
            print('Anisette backend request failed: HTTPError (upstream HTTP '
                  + str(exc.code) + ')', flush=True)
            exc.close()
            return self.respond(502, {'error': 'Anisette backend request failed'})
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
    parser.add_argument('--current-mac', action='store_true',
                        help='Require a new identity provisioned with the matching Mac profile')
    args = parser.parse_args()
    identity = fetch_provider_identity(args.client_info_url)
    if args.current_mac:
        identity = current_mac_identity(identity)
        if not args.fresh_state_file:
            parser.error('--current-mac requires --fresh-state-file')
        validate_current_mac_state(args.fresh_state_file,
                                   args.client_info_url.rsplit('/v3/', 1)[0], identity)
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

