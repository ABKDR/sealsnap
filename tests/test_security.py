"""Красные входы существуют только в испытаниях; рабочий код намеренно не ослабляется."""
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch
from sealsnap.network import target, public_ipv4, resolve, Fetcher, SnapshotError, PinnedConnection
from sealsnap.bundle import save, verify, digest, encoded


class URLTests(unittest.TestCase):
    def test_public(self):
        self.assertEqual(target('https://example.com/путь').host, 'example.com')
        self.assertTrue(public_ipv4('93.184.216.34'))

    def test_rejected_urls(self):
        for u in ['file:///C:/secret', 'javascript:alert(1)', 'ftp://example.com',
                  'http://user:password@example.com', 'http://example.com:8080',
                  'http://example.com:0', 'https://example.com:0',
                  'http://example.com\\@127.0.0.1', 'http://example.com/\r\nx',
                  'http://[::1]', 'http://%31%32%37.0.0.1']:
            with self.subTest(url=u), self.assertRaises(SnapshotError):
                target(u)

    def test_nonpublic_addresses(self):
        for ip in ['127.0.0.1','10.0.0.1','172.16.2.3','192.168.1.1','169.254.169.254',
                   '100.64.0.1','0.0.0.0','224.0.0.1','255.255.255.255','192.0.2.1',
                   '198.51.100.1','203.0.113.1','198.18.0.1','::1','::ffff:127.0.0.1','192.0.0.9']:
            with self.subTest(ip=ip):
                self.assertFalse(public_ipv4(ip))

    def test_mixed_dns_is_rejected(self):
        records = [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))
                   for ip in ['93.184.216.34','127.0.0.1']]
        with patch('socket.getaddrinfo', return_value=records), self.assertRaisesRegex(SnapshotError,'NON_PUBLIC'):
            resolve(target('https://example.com'))

    def test_no_second_dns_on_connect(self):
        with patch('socket.socket') as mock, patch('socket.getaddrinfo', side_effect=AssertionError('DNS rebound')):
            mock.return_value.getpeername.return_value = ('93.184.216.34',80)
            c = PinnedConnection(target('http://example.com'), '93.184.216.34', 1)
            c.connect()
            mock.return_value.connect.assert_called_once_with(('93.184.216.34',80))
            c.close()


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='_proba_sealsnap_bundle_')
        self.addCleanup(self.temp.cleanup)
        # Header-only PNG is a fixture for package integrity, not a rendered capture.
        files = {'source.html.txt':b'<h1>test</h1>', 'rendered.html.txt':b'<h1>test</h1>',
                 'screenshot.png':b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'+struct.pack('>II',1,1),
                 'metadata.json':b'{}'}
        self.result = save(self.temp.name, files)
        self.folder = Path(self.result['path'])

    def test_original_and_red_changed(self):
        self.assertTrue(verify(self.folder, self.result['manifest_sha256'])['ok'])
        (self.folder/'source.html.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(SnapshotError,'FILE_DIGEST_MISMATCH:source'):
            verify(self.folder, self.result['manifest_sha256'])

    def test_wrong_external_digest(self):
        with self.assertRaisesRegex(SnapshotError,'MANIFEST_FINGERPRINT'):
            verify(self.folder,'0'*64)

    def test_creation_is_not_external_verification(self):
        self.assertFalse(self.result['external_fingerprint_checked'])
        self.assertTrue(verify(self.folder, self.result['manifest_sha256'])['external_fingerprint_checked'])

    def test_failed_exclusive_create_preserves_foreign_file(self):
        files = {name: (self.folder/name).read_bytes() for name in
                 ('source.html.txt','rendered.html.txt','screenshot.png','metadata.json')}
        original_open = Path.open
        injected = []
        def collide(path, mode='r', *args, **kwargs):
            if mode == 'xb' and path.name == 'source.html.txt':
                with original_open(path, 'wb') as f:
                    f.write(b'OTHER_WRITER')
                injected.append(path)
            return original_open(path, mode, *args, **kwargs)
        with patch.object(Path, 'open', collide), self.assertRaises(FileExistsError):
            save(self.temp.name, files)
        self.assertEqual(len(injected), 1)
        self.assertTrue(injected[0].is_file(), 'cleanup deleted a file it did not create')
        self.assertEqual(injected[0].read_bytes(), b'OTHER_WRITER')

    def test_rewritten_manifest_vs_external_receipt(self):
        data=b'changed';(self.folder/'source.html.txt').write_bytes(data)
        m=json.loads((self.folder/'manifest.json').read_bytes())
        m['files']['source.html.txt']={'size':len(data),'sha256':digest(data)}
        (self.folder/'manifest.json').write_bytes(encoded(m))
        self.assertTrue(verify(self.folder)['ok'])  # Unanchored integrity is not authenticity.
        with self.assertRaisesRegex(SnapshotError,'MANIFEST_FINGERPRINT'):
            verify(self.folder,self.result['manifest_sha256'])

    def test_missing_and_extra(self):
        (self.folder/'extra.txt').write_bytes(b'x')
        with self.assertRaisesRegex(SnapshotError,'PACKAGE_FILE_SET'):verify(self.folder)
        (self.folder/'extra.txt').unlink()
        (self.folder/'source.html.txt').unlink()
        with self.assertRaisesRegex(SnapshotError,'PACKAGE_FILE_SET'):verify(self.folder)

    def test_path_traversal_manifest(self):
        m=json.loads((self.folder/'manifest.json').read_bytes())
        m['files']['../outside'] = m['files'].pop('source.html.txt')
        (self.folder/'manifest.json').write_bytes(encoded(m))
        with self.assertRaisesRegex(SnapshotError,'MANIFEST_SCHEMA'):verify(self.folder)

    def test_duplicate_json_key(self):
        p=self.folder/'manifest.json';p.write_bytes(b'{"format":"x","format":"y","files":{}}')
        with self.assertRaisesRegex(SnapshotError,'DUPLICATE'):verify(self.folder)

    def test_hardlink(self):
        p=self.folder/'source.html.txt'
        (Path(self.temp.name)/'second-link').hardlink_to(p)
        with self.assertRaisesRegex(SnapshotError,'UNSAFE_FILE'):verify(self.folder)


if __name__ == '__main__':
    unittest.main()
