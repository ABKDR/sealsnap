"""Синтетический HTTP-стенд. Только тест подменяет транспорт к своему loopback-серверу."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest
from unittest.mock import patch
from sealsnap.network import Fetcher, PinnedConnection, SnapshotError, resolve


class Handler(BaseHTTPRequestHandler):
    hits = []
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.hits.append(self.path)
        if self.path in ('/redirect-private', '/redirect-ok', '/loop'):
            self.send_response(302)
            self.send_header('Location', {'/redirect-private':'http://127.0.0.1/private',
                '/redirect-ok':'http://fixture.example/final', '/loop':'http://fixture.example/loop'}[self.path])
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        body = b'<h1>fixture</h1>'
        if self.path == '/truncated': self.send_header('Content-Length',str(len(body)+100))
        if self.path in ('/full-cl','/ambiguous','/duplicate-cl'):
            self.send_header('Content-Length',str(len(body)))
        if self.path == '/duplicate-cl': self.send_header('Content-Length',str(len(body)))
        if self.path in ('/chunked','/ambiguous'):
            self.send_header('Transfer-Encoding','chunked')
        if self.path == '/unsupported-te': self.send_header('Transfer-Encoding','identity')
        if self.path == '/large':self.send_header('Content-Length',str(Fetcher.MAX_BODY+1))
        if self.path == '/download':self.send_header('Content-Disposition','attachment; filename=sample.exe')
        if self.path == '/compressed':self.send_header('Content-Encoding','gzip')
        self.end_headers()
        if self.path in ('/chunked','/ambiguous'):
            body = b'%x\r\n'%len(body) + body + b'\r\n0\r\n\r\n'
        self.wfile.write(body)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        Handler.hits=[]
        port=self.server.server_port
        class FixtureConnection(PinnedConnection):
            def connect(self):
                self.ip='127.0.0.1'; self.port=port
                super().connect()
        def fixture_resolve(t):
            return '93.184.216.34' if t.host=='fixture.example' else resolve(t)
        self.p1=patch('sealsnap.network.PinnedConnection',FixtureConnection)
        self.p2=patch('sealsnap.network.resolve',fixture_resolve)
        self.p1.start();self.p2.start()
        self.addCleanup(self.p1.stop);self.addCleanup(self.p2.stop)

    def test_normal_redirect_and_final_address(self):
        r=Fetcher().fetch('http://fixture.example/redirect-ok')
        self.assertEqual(r.body,b'<h1>fixture</h1>')
        self.assertEqual(r.url,'http://fixture.example/final')
        self.assertEqual(len(r.redirects),1)

    def test_redirect_to_private_never_connected(self):
        with self.assertRaisesRegex(SnapshotError,'NON_PUBLIC_ADDRESS'):
            Fetcher().fetch('http://fixture.example/redirect-private')
        self.assertEqual(Handler.hits,['/redirect-private'])

    def test_redirect_loop(self):
        with self.assertRaisesRegex(SnapshotError,'REDIRECT_LIMIT'):
            Fetcher().fetch('http://fixture.example/loop')
        self.assertEqual(len(Handler.hits),6)

    def test_download_and_limits(self):
        for path,reason in [('large','BODY_LIMIT'),('download','DOWNLOAD_BLOCKED'),
                            ('compressed','COMPRESSED_RESPONSE_BLOCKED')]:
            with self.subTest(path=path), self.assertRaisesRegex(SnapshotError,reason):
                Fetcher().fetch('http://fixture.example/'+path)

    def test_time_and_request_budget(self):
        f=Fetcher();f.deadline=time.monotonic()-1
        with self.assertRaisesRegex(SnapshotError,'NETWORK_BUDGET'):f.fetch('http://fixture.example')
        f=Fetcher();f.requests=50
        with self.assertRaisesRegex(SnapshotError,'NETWORK_BUDGET'):f.fetch('http://fixture.example')
        self.assertEqual(Handler.hits,[])

    def test_complete_body_and_red_incomplete_body(self):
        for path in ('/full-cl','/chunked'):
            self.assertEqual(Fetcher().fetch('http://fixture.example'+path).body,b'<h1>fixture</h1>')
        with self.assertRaisesRegex(SnapshotError,'BODY_INCOMPLETE'):
            Fetcher().fetch('http://fixture.example/truncated')

    def test_ambiguous_or_unsupported_framing(self):
        for path in ('/ambiguous','/duplicate-cl','/unsupported-te'):
            with self.subTest(path=path), self.assertRaisesRegex(SnapshotError,'HTTP_FRAMING'):
                Fetcher().fetch('http://fixture.example'+path)
