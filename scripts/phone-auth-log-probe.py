#!/usr/bin/env python3
"""Read phone syslog directly, without usbmux device-event subscriptions.

netmuxd v0.1.4 leaves Listen unimplemented, while idevicesyslog waits for an
attachment event before connecting. This probe uses the device list directly.
It changes no service configuration, certificates, apps or profiles.
"""
import argparse
import ctypes as c
import ctypes.util
import os
import sys
import time


def configure(lib):
    signatures = {
        'idevice_new_with_options': [c.POINTER(c.c_void_p), c.c_char_p, c.c_int],
        'idevice_free': [c.c_void_p],
        'syslog_relay_client_start_service': [c.c_void_p, c.POINTER(c.c_void_p), c.c_char_p],
        'syslog_relay_client_free': [c.c_void_p],
        'syslog_relay_receive_with_timeout': [c.c_void_p, c.c_void_p, c.c_uint32,
                                            c.POINTER(c.c_uint32), c.c_uint],
    }
    for name, args in signatures.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, c.c_int


def probe(lib, udid, seconds, clock=time.monotonic):
    device, client = c.c_void_p(), c.c_void_p()
    received_bytes = matching_lines = 0
    pending = b''
    try:
        result = lib.idevice_new_with_options(c.byref(device), udid.encode(), 2)
        print('Device connection result: ' + str(result), flush=True)
        if result != 0:
            return 1
        result = lib.syslog_relay_client_start_service(
            device, c.byref(client), b'AltStoreLogProbe')
        print('Syslog service result: ' + str(result), flush=True)
        if result != 0:
            return 1
        print('Connected. Read-only capture for ' + str(seconds)
              + ' seconds; showing lines containing AltStore.', flush=True)
        deadline = clock() + seconds
        buffer = c.create_string_buffer(16384)
        while clock() < deadline:
            count = c.c_uint32()
            result = lib.syslog_relay_receive_with_timeout(
                client, buffer, len(buffer), c.byref(count), 1000)
            if count.value:
                if received_bytes == 0:
                    print('Phone system log stream is receiving data.', flush=True)
                received_bytes += count.value
                pending += buffer.raw[:count.value].replace(b'\0', b'\n')
                lines = pending.split(b'\n')
                pending = lines.pop()
                for line in lines:
                    if b'altstore' in line.lower():
                        matching_lines += 1
                        print(line.decode('utf-8', errors='replace'), flush=True)
                if len(pending) > 262144:
                    pending = b''
            if result not in (0, -4, -5):
                print('Syslog receive result: ' + str(result), flush=True)
                return 1
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        if client.value:
            lib.syslog_relay_client_free(client)
        if device.value:
            lib.idevice_free(device)
        print('Received bytes: ' + str(received_bytes)
              + '; AltStore lines: ' + str(matching_lines), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--seconds', type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error('--seconds must be between 1 and 300')
    os.environ['USBMUXD_SOCKET_ADDRESS'] = '127.0.0.1:27015'
    name = ctypes.util.find_library('imobiledevice-1.0')
    if not name:
        sys.exit('libimobiledevice shared library was not found.')
    try:
        lib = c.CDLL(name)
        configure(lib)
    except (OSError, AttributeError) as error:
        sys.exit('Cannot load required libimobiledevice functions: ' + type(error).__name__)
    return probe(lib, args.udid, args.seconds)


if __name__ == '__main__':
    sys.exit(main())
