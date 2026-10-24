import contextlib
import ctypes as c
import importlib.util
import io
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'probe', Path(__file__).resolve().parents[1] / 'scripts/phone-auth-log-probe.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeLibrary:
    def __init__(self, service_result=0, receive_result=0):
        self.service_result = service_result
        self.receive_result = receive_result
        self.freed = []
        self.chunks = [b'OtherProcess: ignored\nAltSto', b're: auth 503\nAltStore: received\0']

    def idevice_new_with_options(self, target, udid, options):
        assert options == 2 and udid == b'test-device'
        c.cast(target, c.POINTER(c.c_void_p))[0] = 1
        return 0

    def syslog_relay_client_start_service(self, device, target, label):
        assert device.value == 1 and label == b'AltStoreLogProbe'
        if self.service_result == 0:
            c.cast(target, c.POINTER(c.c_void_p))[0] = 2
        return self.service_result

    def syslog_relay_receive_with_timeout(self, client, buffer, size, received, timeout):
        assert client.value == 2 and timeout == 1000
        data = self.chunks.pop(0) if self.chunks else b''
        assert len(data) <= size
        c.memmove(buffer, data, len(data))
        c.cast(received, c.POINTER(c.c_uint32))[0] = len(data)
        return self.receive_result

    def syslog_relay_client_free(self, client):
        self.freed.append('client')

    def idevice_free(self, device):
        self.freed.append('device')


class PhoneLogProbeTests(unittest.TestCase):
    def run_probe(self, lib):
        output = io.StringIO()
        ticks = iter(range(20))
        with contextlib.redirect_stdout(output):
            result = module.probe(lib, 'test-device', 3, clock=lambda: next(ticks))
        return result, output.getvalue()

    def test_direct_connection_fragmented_lines_and_filtering(self):
        lib = FakeLibrary()
        result, output = self.run_probe(lib)
        self.assertEqual(result, 0)
        self.assertIn('AltStore: auth 503', output)
        self.assertIn('AltStore lines: 2', output)
        self.assertNotIn('OtherProcess', output)
        self.assertEqual(lib.freed, ['client', 'device'])

    def test_service_failure_reports_code_and_cleans_device(self):
        lib = FakeLibrary(service_result=-3)
        result, output = self.run_probe(lib)
        self.assertEqual(result, 1)
        self.assertIn('Syslog service result: -3', output)
        self.assertEqual(lib.freed, ['device'])

    def test_receive_failure_reports_code_and_cleans_both_handles(self):
        lib = FakeLibrary(receive_result=-2)
        result, output = self.run_probe(lib)
        self.assertEqual(result, 1)
        self.assertIn('Syslog receive result: -2', output)
        self.assertEqual(lib.freed, ['client', 'device'])


if __name__ == '__main__':
    unittest.main()
