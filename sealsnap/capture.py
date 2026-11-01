"""Пассивная отрисовка: никакой прямой сети браузера, только ограниченный GET-брокер."""
from datetime import datetime, timezone
import socketserver
import threading
from .network import Fetcher, SnapshotError
from .bundle import encoded, save

CSP = ("sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; "
       "object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; "
       "img-src http: https: data:; style-src http: https: 'unsafe-inline'; "
       "font-src http: https: data:")
PAGE_TYPES = {'text/html', 'application/xhtml+xml', 'text/plain'}
RESOURCE_TYPES = {'stylesheet', 'image', 'font'}
MIMES = {'text/css', 'image/png', 'image/jpeg', 'image/gif', 'image/webp',
         'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon',
         'font/woff', 'font/woff2', 'application/font-woff', 'font/ttf', 'font/otf'}


class DenyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        except OSError:
            pass


def capture(url, output):
    # Import only inside the owned worker, after its parent attaches the Windows Job.
    from playwright.sync_api import sync_playwright
    started = datetime.now(timezone.utc).isoformat()
    fetcher = Fetcher()
    main = fetcher.fetch(url)
    if main.content_type.split(';')[0].strip().lower() not in PAGE_TYPES or not main.body:
        raise SnapshotError('MAIN_CONTENT_TYPE')
    blocked = []
    with socketserver.TCPServer(('127.0.0.1', 0), DenyHandler) as deny:
        thread = threading.Thread(target=deny.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(channel='msedge', headless=True, chromium_sandbox=True,
                    proxy={'server': f'http://127.0.0.1:{deny.server_address[1]}', 'bypass': '<-loopback>'},
                    args=['--disable-quic', '--disable-background-networking',
                          '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
                try:
                    ctx = browser.new_context(java_script_enabled=False, service_workers='block',
                        accept_downloads=False, offline=True, viewport={'width': 1280, 'height': 900},
                        permissions=[], ignore_https_errors=False)
                    ctx.route_web_socket('**/*', lambda ws: ws.close(code=1008, reason='Disabled'))
                    page = ctx.new_page()
                    ctx.on('page', lambda other: other.close() if other != page else None)
                    page.on('dialog', lambda dialog: dialog.dismiss())
                    page.on('download', lambda download: download.cancel())
                    first = True

                    def route_request(route):
                        nonlocal first
                        request = route.request
                        try:
                            if request.method != 'GET':
                                raise SnapshotError('METHOD_BLOCKED')
                            if first and request.is_navigation_request() and request.url == main.url:
                                first = False
                                response = main
                                headers = {'content-type': response.content_type,
                                    'content-security-policy': CSP, 'x-content-type-options': 'nosniff'}
                            else:
                                if request.resource_type not in RESOURCE_TYPES:
                                    raise SnapshotError('RESOURCE_TYPE_BLOCKED')
                                response = fetcher.fetch(request.url)
                                if response.content_type.split(';')[0].strip().lower() not in MIMES:
                                    raise SnapshotError('RESOURCE_MIME_BLOCKED')
                                headers = {'content-type': response.content_type,
                                           'access-control-allow-origin': '*',
                                           'x-content-type-options': 'nosniff'}
                            route.fulfill(status=response.status, headers=headers, body=response.body)
                        except SnapshotError as e:
                            if len(blocked) < 100:
                                blocked.append({'url': request.url[:4096], 'reason': str(e)})
                            route.abort('blockedbyclient')

                    ctx.route('**/*', route_request)
                    page.goto(main.url, wait_until='load', timeout=45000)
                    if first:
                        raise SnapshotError('MAIN_ROUTE_NOT_OBSERVED')
                    page.wait_for_timeout(250)
                    height = page.evaluate('Math.max(document.documentElement.scrollHeight, document.body ? document.body.scrollHeight : 0, 900)')
                    height = min(max(int(height), 900), 6000)
                    shot = page.screenshot(type='png', clip={'x': 0, 'y': 0, 'width': 1280, 'height': height}, timeout=8000)
                    rendered = page.content().encode('utf-8')
                    browser_version = browser.version
                    ctx.close()
                finally:
                    browser.close()
        finally:
            deny.shutdown()
            thread.join(timeout=2)
    metadata = dict(format='sealsnap-metadata-1', mode='passive-no-javascript',
        requested_url=url, final_url=main.url, http_status=main.status, peer_ipv4=main.ip,
        response_content_type=main.content_type, started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(), clock='unverified-local-system-clock',
        redirects=main.redirects, requests=fetcher.events, blocked=blocked,
        browser='Microsoft Edge ' + browser_version, chromium_sandbox=True,
        javascript=False, cookies_from_user=False, maximum_image_height=6000,
        completeness='Passive rendering; scripts, frames and forms disabled; image height capped at 6000px.')
    result = save(output, {'source.html.txt': main.body, 'rendered.html.txt': rendered,
                          'screenshot.png': shot, 'metadata.json': encoded(metadata)})
    result['mode'] = metadata['mode']
    result['blocked_resources'] = len(blocked)
    return result
