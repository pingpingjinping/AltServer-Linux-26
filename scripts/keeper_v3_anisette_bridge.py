#!/usr/bin/env python3
"""Loopback-only AltKeeper Anisette RPC -> AltServer v1 JSON adapter.

This sends only AnisetteDataRequest; it has no account, signing or phone APIs.
The backend's state belongs to a separate, disposable container.
"""
import argparse
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import struct

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


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/healthz':
            return self.respond(200, {'ready': True})
        if self.path != '/':
            return self.respond(404, {'error': 'Not found'})
        try:
            data = fetch_anisette(self.server.backend_port)
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
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.backend_port = args.backend_port
    print('Anisette bridge listening on localhost (no account or phone access)', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
