"""HTTP GET через проверенный IPv4: без прокси, cookies и повторного DNS при connect."""
from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import ssl
import time
import certifi
from urllib.parse import urljoin, urlsplit, urlunsplit, quote
from . import __version__


class SnapshotError(Exception):
    """Ожидаемый отказ; сообщение не содержит тела ответа или секретных заголовков."""


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    port: int
    tls: bool
    path: str


def target(url):
    if type(url) is not str or not 1 <= len(url) <= 4096:
        raise SnapshotError('URL_LENGTH')
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or '\\' in url:
        raise SnapshotError('URL_CHARACTERS')
    try:
        u = urlsplit(url)
        if u.scheme not in ('http', 'https') or u.username is not None or u.password is not None:
            raise ValueError()
        host = (u.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
        if (not host or len(host) > 253 or ':' in host or '%' in host or
                not re.fullmatch(r'[a-z0-9.-]+', host) or
                any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in host.split('.'))):
            raise ValueError()
        port = (443 if u.scheme == 'https' else 80) if u.port is None else u.port
        if port != (443 if u.scheme == 'https' else 80):
            raise ValueError()
        path = quote(u.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = quote(u.query, safe="/%?:@!$&'()*+,;=-._~")
        normalized = urlunsplit((u.scheme, host, path, query, ''))
    except (ValueError, UnicodeError):
        raise SnapshotError('URL_NOT_PUBLIC_HTTP') from None
    return Target(normalized, host, port, u.scheme == 'https', path + ('?' + query if query else ''))


def public_ipv4(value):
    try:
        a = ipaddress.ip_address(value)
        return (type(a) is ipaddress.IPv4Address and a.is_global and
                not (a.is_multicast or a.is_reserved or a.is_unspecified or a.is_loopback)
                and a not in ipaddress.ip_network('192.0.0.0/24'))
    except ValueError:
        return False


def resolve(t):
    try:
        records = socket.getaddrinfo(t.host, t.port, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        raise SnapshotError('DNS_FAILED') from None
    addresses = sorted({x[4][0] for x in records})
    if not addresses or any(not public_ipv4(a) for a in addresses):
        raise SnapshotError('NON_PUBLIC_ADDRESS')
    return addresses[0]


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, t, ip, timeout):
        super().__init__(t.host, t.port, timeout=timeout)
        self.target, self.ip = t, ip

    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect((self.ip, self.port))
            if raw.getpeername()[0] != self.ip:
                raise SnapshotError('PEER_CHANGED')
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=certifi.where())
            self.sock = context.wrap_socket(raw, server_hostname=self.target.host) if self.target.tls else raw
        except BaseException:
            raw.close()
            raise


@dataclass
class Response:
    url: str
    status: int
    content_type: str
    body: bytes
    redirects: list
    ip: str


class Fetcher:
    MAX_BODY = 2 * 1024 * 1024
    MAX_TOTAL = 16 * 1024 * 1024
    MAX_REQUESTS = 50

    def __init__(self):
        self.deadline = time.monotonic() + 35
        self.bytes = 0
        self.requests = 0
        self.events = []

    def fetch(self, url):
        redirects = []
        for step in range(6):
            t = target(url)
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.requests >= self.MAX_REQUESTS:
                raise SnapshotError('NETWORK_BUDGET')
            ip = resolve(t)
            self.requests += 1
            conn = PinnedConnection(t, ip, min(8, remaining))
            try:
                conn.request('GET', t.path, headers={
                    'Host': t.host, 'User-Agent': f'SealSnap/{__version__} (passive capture)',
                    'Accept': '*/*', 'Accept-Encoding': 'identity', 'Connection': 'close'})
                resp = conn.getresponse()
                headers = resp.getheaders()
                if sum(len(k) + len(v) for k, v in headers) > 32768:
                    raise SnapshotError('HEADERS_LIMIT')
                self.events.append(dict(url=t.url, ip=ip, status=resp.status))
                if resp.status in (301, 302, 303, 307, 308):
                    locations = [v for k, v in headers if k.lower() == 'location']
                    if step == 5 or len(locations) != 1:
                        raise SnapshotError('REDIRECT_LIMIT_OR_LOCATION')
                    try:
                        joined = urljoin(t.url, locations[0])
                    except ValueError:
                        raise SnapshotError('URL_NOT_PUBLIC_HTTP') from None
                    next_url = target(joined).url
                    redirects.append(dict(source=t.url, destination=next_url, status=resp.status))
                    url = next_url
                    continue
                # http.client returns 101-199 and 600-999 as final statuses; this guard is live.
                if not 200 <= resp.status <= 599:
                    raise SnapshotError('HTTP_STATUS')
                if 'attachment' in (resp.getheader('Content-Disposition') or '').lower():
                    raise SnapshotError('DOWNLOAD_BLOCKED')
                if (resp.getheader('Content-Encoding') or 'identity').lower() != 'identity':
                    raise SnapshotError('COMPRESSED_RESPONSE_BLOCKED')
                lengths = [v for k, v in headers if k.lower() == 'content-length']
                encodings = [v.strip().lower() for k, v in headers if k.lower() == 'transfer-encoding']
                if len(lengths) > 1 or (encodings and (lengths or encodings != ['chunked'])):
                    raise SnapshotError('HTTP_FRAMING')
                length = lengths[0] if lengths else None
                if length is not None and (not re.fullmatch(r'[0-9]{1,10}', length)
                                           or int(length) > self.MAX_BODY):
                    raise SnapshotError('BODY_LIMIT')
                body = bytearray()
                while True:
                    if time.monotonic() > self.deadline:
                        raise SnapshotError('NETWORK_BUDGET')
                    chunk = resp.read(min(65536, self.MAX_BODY - len(body) + 1))
                    if not chunk:
                        break
                    body.extend(chunk)
                    self.bytes += len(chunk)
                    if len(body) > self.MAX_BODY or self.bytes > self.MAX_TOTAL:
                        raise SnapshotError('BODY_LIMIT')
                if length is not None and len(body) != int(length):
                    raise SnapshotError('BODY_INCOMPLETE')
                ctype = resp.getheader('Content-Type') or 'application/octet-stream'
                if len(ctype) > 512:
                    raise SnapshotError('CONTENT_TYPE_LIMIT')
                return Response(t.url, resp.status, ctype, bytes(body), redirects, ip)
            except (OSError, http.client.HTTPException) as e:
                raise SnapshotError('NETWORK_' + type(e).__name__) from None
            finally:
                conn.close()
        raise SnapshotError('REDIRECT_LIMIT')
