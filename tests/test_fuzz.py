"""Детерминированный фаззинг без сторонних библиотек: разбор HTTP-ответа, адреса и пакета.

Число прогонов и зерно задаются переменными SEALSNAP_FUZZ_ITERATIONS и SEALSNAP_FUZZ_SEED.
Свойство везде одно: недоверенный вход даёт либо допустимый результат, либо SnapshotError.
"""
import os
from pathlib import Path
import random
import socketserver
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from sealsnap.network import Fetcher, PinnedConnection, SnapshotError, target
from sealsnap.bundle import save, verify, digest, encoded

ITERATIONS = max(1, int(os.environ.get('SEALSNAP_FUZZ_ITERATIONS') or 150))
SEED = int(os.environ.get('SEALSNAP_FUZZ_SEED') or 20261101)


def mutate(rng, data, tokens, rounds=4):
    data = bytearray(data)
    for _ in range(rng.randint(1, rounds)):
        op = rng.randrange(6)
        i = rng.randint(0, len(data))
        j = rng.randint(i, min(len(data), i + 16))
        if op == 0 and data:
            k = rng.randrange(len(data))
            data[k] ^= 1 << rng.randrange(8)
        elif op == 1:
            data[i:i] = rng.choice(tokens)
        elif op == 2:
            data[i:j] = rng.choice(tokens)
        elif op == 3:
            del data[i:j]
        elif op == 4:
            data[i:i] = data[i:j] * rng.randint(1, 3)
        else:
            del data[i:]
    return bytes(data)


HTTP_SEEDS = [
    b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello',
    b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n',
    b'HTTP/1.1 302 Found\r\nLocation: http://fuzz.example/next\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
    b'HTTP/1.1 302 Found\r\nLocation: http://[::1\r\nContent-Length: 0\r\n\r\n',
]
HTTP_TOKENS = [
    b'\r\n', b'\n', b'\r', b':', b' ', b'\t', b'\x00', b'\xff', b'HTTP/1.1 ', b'HTTP/1.0 ', b'HTTP/0.9 ',
    b'100 Continue\r\n\r\n', b'103 Early Hints\r\n\r\n', b'Content-Length: ', b'Content-Length: -1',
    b'Content-Length: 99999999999', b'Content-Length: 5 ', b'Transfer-Encoding: chunked',
    b'Transfer-Encoding: gzip, chunked', b'Content-Encoding: identity', b'Content-Disposition: inline',
    b'Location: ', b'Location: http://[::1', b'Location: http://[', b'Location: http://127.0.0.1/',
    b'Location: //fuzz.example/x', b'Location: http://a..b/', b'Location: http://xn--/',
    b'Location: \xff\xfe', b'Location: http://fuzz.example:80/', b'Content-Type: ', b'0\r\n\r\n',
    b'ffffffff\r\n', b'+5\r\n', b'0x5\r\n', b'5_0\r\n', b'5;ext=1\r\n', b'301', b'302', b'307',
    b'999', b'6_00', b'0200', b'X' * 70000,
]


class RawHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.5)
        data = b''
        try:
            while b'\r\n\r\n' not in data and len(data) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        try:
            self.request.sendall(self.server.payload)
        except OSError:
            pass


class RawServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    payload = b''


class HTTPFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = RawServer(('127.0.0.1', 0), RawHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': 0.05},
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_response_parsing(self):
        port = self.server.server_address[1]

        class LoopbackConnection(PinnedConnection):
            def connect(self):
                self.ip, self.port = '127.0.0.1', port
                super().connect()
        rng = random.Random(SEED)
        failures = []
        with patch('sealsnap.network.PinnedConnection', LoopbackConnection), \
                patch('sealsnap.network.resolve', lambda t: '93.184.216.34'):
            for _ in range(ITERATIONS):
                payload = mutate(rng, rng.choice(HTTP_SEEDS), HTTP_TOKENS)
                self.server.payload = payload
                try:
                    r = Fetcher().fetch('http://fuzz.example/')
                except SnapshotError:
                    continue
                except Exception as e:
                    failures.append((type(e).__name__, str(e)[:80], payload[:200]))
                    continue
                if not 200 <= r.status <= 599 or len(r.body) > Fetcher.MAX_BODY:
                    failures.append(('BAD_RESULT', r.status, payload[:200]))
        self.assertEqual(failures, [], 'seed %d' % SEED)


URL_SEEDS = ['http://example.com/', 'https://example.com/a?b=c', 'http://пример.рф/путь?q=ы',
             'HTTP://Example.COM./%7e', 'https://a-b.example.org:443/x/../y']
URL_TOKENS = ['://', '@', ':', '[', ']', '%', '%00', '%2e', '..', '.', '//', '#', '?', 'xn--', 'ß',
              'ﬀ', '。', '．', '​', ':80', ':443', ':0', ':65536', 'user:pass@',
              'ⓔ', '١', '\ud800', 'a' * 70, '-', '_', '*', '\x7f', ' ', 'https', 'ftp']


class URLFuzz(unittest.TestCase):
    def test_target_normalization(self):
        rng = random.Random(SEED + 1)
        failures = []
        for _ in range(ITERATIONS * 4):
            raw = rng.choice(URL_SEEDS)
            for _ in range(rng.randint(1, 3)):
                i = rng.randint(0, len(raw))
                raw = raw[:i] + rng.choice(URL_TOKENS) + raw[i + rng.randint(0, 3):]
            try:
                t = target(raw)
            except SnapshotError:
                continue
            except Exception as e:
                failures.append((type(e).__name__, raw))
                continue
            try:
                again = target(t.url)
            except Exception as e:
                failures.append(('NOT_IDEMPOTENT_' + type(e).__name__, raw))
                continue
            if (again != t or t.port not in (80, 443) or urlsplit(t.url).hostname != t.host
                    or not t.host.isascii()):
                failures.append(('INCONSISTENT', raw))
        self.assertEqual(failures, [], 'seed %d' % SEED)


MANIFEST_TOKENS = [b'{', b'}', b'[', b']', b'"', b':', b',', b'null', b'true', b'1e999', b'NaN',
                   b'Infinity', b'-0', b'1.0', b'"\\ud800"', b'\\u0000', b'"files"', b'"format"',
                   b'"sealsnap-1"', b'"size"', b'"sha256"', b'\xef\xbb\xbf', b'\xff', b'9' * 5000,
                   b'[' * 3000, b'{"a":' * 3000]


class PackageFuzz(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='_proba_sealsnap_fuzz_')
        self.addCleanup(temp.cleanup)
        files = {'source.html.txt': b'<h1>fuzz</h1>', 'rendered.html.txt': b'<h1>fuzz</h1>',
                 'screenshot.png': b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' + struct.pack('>II', 1280, 900),
                 'metadata.json': b'{}'}
        self.folder = Path(save(temp.name, files)['path'])
        self.original = {p.name: p.read_bytes() for p in self.folder.iterdir()}

    def restore(self):
        for name, data in self.original.items():
            (self.folder / name).write_bytes(data)

    def check(self, failures, case, expected=None):
        try:
            result = verify(self.folder, expected)
        except SnapshotError:
            return None
        except Exception as e:
            failures.append((type(e).__name__, case))
            return None
        if result.get('ok') is not True:
            failures.append(('NOT_OK_RESULT', case))
        return result

    def test_crafted_manifest(self):
        rng = random.Random(SEED + 2)
        failures = []
        for _ in range(ITERATIONS):
            data = mutate(rng, self.original['manifest.json'], MANIFEST_TOKENS)[:16384]
            (self.folder / 'manifest.json').write_bytes(data)
            self.check(failures, data[:120])
        self.restore()
        self.assertEqual(failures, [], 'seed %d' % SEED)

    def test_crafted_png_with_matching_manifest(self):
        rng = random.Random(SEED + 3)
        failures = []
        png_tokens = [b'\x00', b'\xff\xff\xff\xff', b'IHDR', b'\x89PNG', struct.pack('>II', 1441, 6001),
                      struct.pack('>II', 0, 0), struct.pack('>II', 1440, 6000)]
        for _ in range(ITERATIONS):
            png = mutate(rng, self.original['screenshot.png'], png_tokens)
            (self.folder / 'screenshot.png').write_bytes(png)
            files = {n: self.original[n] for n in ('source.html.txt', 'rendered.html.txt', 'metadata.json')}
            files['screenshot.png'] = png
            manifest = {'format': 'sealsnap-1', 'files': {
                k: {'size': len(v), 'sha256': digest(v)} for k, v in files.items()}}
            (self.folder / 'manifest.json').write_bytes(encoded(manifest))
            if self.check(failures, png[:40]) is not None:
                w, h = struct.unpack('>II', png[16:24])
                if (png[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
                        or not (1 <= w <= 1440 and 1 <= h <= 6000)):
                    failures.append(('ACCEPTED_BAD_PNG', png[:40]))
        self.restore()
        self.assertEqual(failures, [], 'seed %d' % SEED)

    def test_expected_fingerprint(self):
        rng = random.Random(SEED + 4)
        failures = []
        real = digest(self.original['manifest.json'])
        alphabet = '0123456789abcdefABCDEF١０ g\n'
        for _ in range(ITERATIONS):
            choice = rng.randrange(3)
            if choice == 0:
                expected = ''.join(rng.choice(alphabet) for _ in range(rng.choice((63, 64, 65))))
            elif choice == 1:
                expected = real.upper()
            else:
                k = rng.randrange(64)
                expected = real[:k] + rng.choice(alphabet) + real[k + 1:]
            result = self.check(failures, expected, expected)
            if result is not None and expected.lower() != real:
                failures.append(('ACCEPTED_WRONG_FINGERPRINT', expected))
        self.assertEqual(failures, [], 'seed %d' % SEED)


if __name__ == '__main__':
    unittest.main()
