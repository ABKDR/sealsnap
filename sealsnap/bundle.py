"""Фиксированные имена и строгий манифест; никогда не открывает HTML в браузере."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import uuid
from .network import SnapshotError

FILES = {'source.html.txt': 2 * 1024 * 1024, 'rendered.html.txt': 8 * 1024 * 1024,
         'screenshot.png': 32 * 1024 * 1024, 'metadata.json': 1024 * 1024}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise SnapshotError('DUPLICATE_JSON_KEY')
        d[k] = v
    return d


def regular(path):
    s = path.lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or
            getattr(s, 'st_file_attributes', 0) & 0x400):
        raise SnapshotError('UNSAFE_FILE')
    return s


def no_links(path):
    p = Path(os.path.abspath(path))
    for component in [p, *p.parents]:
        if component.exists() or component.is_symlink():
            s = component.lstat()
            if stat.S_ISLNK(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
                raise SnapshotError('UNSAFE_PATH')
    return p


def bounded_read(path, limit):
    before = regular(path)
    if before.st_size > limit:
        raise SnapshotError('FILE_LIMIT')
    with path.open('rb') as f:
        opened = os.fstat(f.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise SnapshotError('FILE_CHANGED')
        raw = f.read(limit + 1)
        after = os.fstat(f.fileno())
    if len(raw) > limit or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise SnapshotError('FILE_CHANGED')
    regular(path)
    return raw


def verify(directory, expected=None):
    folder = no_links(directory)
    if not folder.is_dir() or {x.name for x in folder.iterdir()} != set(FILES) | {'manifest.json'}:
        raise SnapshotError('PACKAGE_FILE_SET')
    raw = bounded_read(folder / 'manifest.json', 16384)
    fingerprint = digest(raw)
    if expected is not None:
        if not re.fullmatch('[0-9a-fA-F]{64}', expected) or fingerprint != expected.lower():
            raise SnapshotError('MANIFEST_FINGERPRINT_MISMATCH')
    try:
        m = json.loads(raw, object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(SnapshotError('INVALID_JSON')))
    except (ValueError, UnicodeError, RecursionError):
        # Deep nesting fits into the size limit and exhausts the parser's recursion.
        raise SnapshotError('INVALID_JSON') from None
    if (type(m) is not dict or set(m) != {'format', 'files'} or m['format'] != 'sealsnap-1'
            or type(m['files']) is not dict or set(m['files']) != set(FILES)):
        raise SnapshotError('MANIFEST_SCHEMA')
    for name, limit in FILES.items():
        item = m['files'][name]
        if (type(item) is not dict or set(item) != {'size', 'sha256'} or
                type(item['size']) is not int or not 0 <= item['size'] <= limit or
                type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise SnapshotError('MANIFEST_SCHEMA')
        data = bounded_read(folder / name, limit)
        if len(data) != item['size'] or digest(data) != item['sha256']:
            raise SnapshotError('FILE_DIGEST_MISMATCH:' + name)
        if name == 'screenshot.png':
            if len(data) < 24 or data[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR':
                raise SnapshotError('PNG_HEADER')
            w, h = struct.unpack('>II', data[16:24])
            if not (1 <= w <= 1440 and 1 <= h <= 6000):
                raise SnapshotError('PNG_DIMENSIONS')
    return dict(ok=True, path=str(folder), manifest_sha256=fingerprint,
                external_fingerprint_checked=expected is not None,
                assurance='Files match the manifest; this does not certify the author or the time.')


def save(directory, files):
    if set(files) != set(FILES) or any(type(v) is not bytes or len(v) > FILES[k] for k, v in files.items()):
        raise SnapshotError('OUTPUT_LIMIT')
    parent = no_links(directory)
    parent.mkdir(parents=True, exist_ok=True)
    no_links(parent)
    folder = parent / ('snapshot-' + uuid.uuid4().hex)
    folder.mkdir()
    created = []
    def write_owned(name, data):
        path = folder / name
        with path.open('xb') as f:
            identity = os.fstat(f.fileno())
            created.append((path, identity.st_dev, identity.st_ino))
            f.write(data)
    try:
        for name, data in files.items():
            write_owned(name, data)
        manifest = {'format': 'sealsnap-1', 'files': {
            k: {'size': len(v), 'sha256': digest(v)} for k, v in files.items()}}
        write_owned('manifest.json', encoded(manifest))
        result = verify(folder, digest(encoded(manifest)))
        # This is a self-check, not comparison with a previously known receipt.
        result['external_fingerprint_checked'] = False
        return result
    except BaseException:
        # A competing file is left intact, even if that leaves an incomplete folder.
        for path, device, inode in created:
            try:
                current = regular(path)
                if (current.st_dev, current.st_ino) == (device, inode):
                    path.unlink()
            except (OSError, SnapshotError):
                pass
        try:
            folder.rmdir()  # Only succeeds when empty; never recursive.
        except OSError:
            pass
        raise
