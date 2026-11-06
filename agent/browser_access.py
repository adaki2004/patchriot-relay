"""Generic browser access helpers. The agent navigates with Hermes browser tools;
this controller supplies scoped traffic, private form filling and a test wallet.
No website endpoints, JSON layouts or credentials are embedded in this module.
"""
import argparse
import asyncio
import base64
import json
import hmac
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

MAX_CONTROL = 32768


class StaticAssetCache:
    """Per-role cache for explicitly public, immutable browser assets only.

    APIs, documents, login responses and direct testing tools stay uncached.
    Entries never leave the disposable browser and never create evidence IDs.
    """
    def __init__(self, max_bytes=16 * 1024 * 1024, max_entries=128):
        self.entries = OrderedDict()
        self.bytes = 0
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self.hits = 0

    @staticmethod
    def allowed(method, kind, headers):
        control = headers.get('cache-control', '').lower()
        return (method == 'GET' and kind in ('script', 'stylesheet', 'image', 'font')
                and 'authorization' not in headers and 'range' not in headers
                and not any(v in control for v in ('no-cache', 'no-store', 'max-age=0'))
                and 'no-cache' not in headers.get('pragma', '').lower())

    def get(self, url, method, kind, headers):
        if not self.allowed(method, kind, headers): return None
        entry = self.entries.get(url)
        if not entry: return None
        if entry['until'] <= time.monotonic():
            self.bytes -= len(self.entries.pop(url)['body'])
            return None
        if any(headers.get(k, '') != v for k, v in entry['vary'].items()): return None
        self.entries.move_to_end(url)
        self.hits += 1
        return entry

    def put(self, url, method, kind, request_headers, status, headers, body):
        old = self.entries.pop(url, None)
        if old: self.bytes -= len(old['body'])
        if not self.allowed(method, kind, request_headers) or status != 200: return
        control = {p.strip().lower() for p in headers.get('cache-control', '').split(',')}
        if not {'public', 'immutable'} <= control or control & {'private', 'no-cache', 'no-store'}: return
        if 'set-cookie' in headers or len(body) > min(self.max_bytes, 2 * 1024 * 1024): return
        vary = {v.strip().lower() for v in headers.get('vary', '').split(',') if v.strip()}
        if '*' in vary: return
        ages = [v.split('=', 1)[1] for v in control if v.startswith('max-age=')]
        try:
            if len(ages) != 1: return
            age = max(0, int(headers.get('age', '0')))
            if 'date' in headers:
                age = max(age, time.time() - parsedate_to_datetime(headers['date']).timestamp())
            ttl = int(ages[0]) - age
            if ttl <= 0: return
        except (ValueError, TypeError, OverflowError):
            return
        while self.entries and (self.bytes + len(body) > self.max_bytes or len(self.entries) >= self.max_entries):
            self.bytes -= len(self.entries.popitem(last=False)[1]['body'])
        self.entries[url] = {'until':time.monotonic() + ttl, 'vary':{k:request_headers.get(k, '') for k in vary}, 'headers':headers, 'body':body}
        self.bytes += len(body)


def rpc(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=60) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        value = json.loads(error.read(MAX_CONTROL))
    if isinstance(value, dict) and value.get('error'):
        raise ValueError(value['error'])
    return value


def origin(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def configure_hermes_browser(scope):
    """Hermes cannot resolve DNS in a network-none container. Admit only the
    assignment's exact origin here; the Rust broker still checks public DNS on
    every actual request, including redirects and assets. No global private-URL
    setting, proxy or alternative browser backend is enabled.
    """
    from tools import browser_tool
    approved = scope['origins'][0]
    browser_tool._is_safe_url = lambda url: origin(url) == approved


class BrowserAccess:
    def __init__(self, scope, bridge, *, directory='/work', executable='/usr/bin/chromium'):
        self.scope, self.bridge = scope, bridge
        self.origin = scope['origins'][0]
        self.resources = set(scope.get('browser_login', {}).get('resource_origins', []))
        self.pending = {}
        self.requests = {}
        self.verified = False
        self.legacy_wallet = False
        self.unsupported_wallet_methods = set()
        self.credentials = None
        self.process = None
        self.control = None
        self.secret = secrets.token_urlsafe(32)
        self.port = None
        self.context = None
        self.errors = []
        self.inflight = 0
        self.http_slots = asyncio.Semaphore(4)
        self.http_exhausted = False
        self.assets = StaticAssetCache()
        self.wallet_account = None
        self.wallet_lock = asyncio.Lock()
        self.blocked_origins = set()
        self.directory, self.executable = Path(directory), executable

    async def call(self, path, data):
        return await asyncio.to_thread(rpc, self.bridge, '/patchriot/browser/' + path, data)

    async def start(self):
        from playwright.async_api import async_playwright
        self.playwright = await async_playwright().start()
        # Playwright otherwise disables Chromium's sandbox. The container is
        # unprivileged, has no direct egress and supplies the reviewed seccomp file.
        self.context = await self.playwright.chromium.launch_persistent_context(
            str(self.directory / 'browser-profile'), executable_path=self.executable, headless=True,
            chromium_sandbox=True, service_workers='block', accept_downloads=False,
            args=['--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
                  '--disable-background-networking', '--disable-component-update',
                  '--disable-sync', '--disable-extensions', '--disable-quic',
                  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],
        )
        await self.context.route('**/*', self.route)
        await self.context.route_web_socket('**/*', lambda socket: socket.close())
        await self.context.expose_binding('__patchriot_wallet_rpc', self.wallet)
        if self.scope.get('authentication') == 'wallet':
            await self.context.add_init_script(path=str(Path(__file__).with_name('browser_wallet.js')))
        self.control = await asyncio.start_server(self.handle_control, '127.0.0.1', 0, limit=MAX_CONTROL)
        self.port = self.control.sockets[0].getsockname()[1]
        ready = self.directory / 'browser-profile/DevToolsActivePort'
        for _ in range(100):
            if ready.exists(): break
            await asyncio.sleep(.05)
        lines = ready.read_text().splitlines()
        cdp = 'http://127.0.0.1:' + lines[0]
        path = self.directory / 'browser-access.json'
        path.write_text(json.dumps({'url':f'http://127.0.0.1:{self.port}', 'secret':self.secret, 'cdp':cdp}))
        path.chmod(0o600)
        return cdp

    async def route(self, route):
        request = route.request
        self.inflight += 1
        try:
            # Only approved public dependencies may load outside the app. They
            # cannot become pages/login targets or receive its session headers.
            external = origin(request.url) != self.origin
            resource = external and origin(request.url) in self.resources and request.method in ('GET','HEAD') and request.resource_type not in ('document','websocket')
            if external and not resource:
                if len(self.blocked_origins) < 12:
                    self.blocked_origins.add(origin(request.url))
                await route.abort('blockedbyclient')
                return
            headers = await request.all_headers()
            cached = self.assets.get(request.url, request.method, request.resource_type, headers)
            if cached:
                await route.fulfill(status=200, headers=cached['headers'], body=cached['body'])
                return
            login = not resource and request.method == 'POST' and not self.verified
            # A split JS bundle can queue hundreds of files. Bound bridge
            # callers so queued assets do not start their RPC timeout at once.
            async with self.http_slots:
                # Background polling must not exhaust the wire-message allowance
                # after the target allowance has already closed. Keep local
                # browser status and final report generation available.
                if self.http_exhausted:
                    await route.abort('blockedbyclient')
                    return
                reply = await self.call('http', {'method':request.method, 'url':request.url,
                    'headers':headers, 'data':request.post_data, 'authenticated':not resource, 'login':login})
            evidence = reply['evidence']
            if evidence.get('error'):
                self.errors = (self.errors + [evidence['error']])[-12:]
                await route.abort('failed')
                return
            if not resource and request.method == 'GET':
                # Keep only session headers for an explicit access comparison;
                # never dump this cache into an agent transcript or artifact.
                self.requests[request.url] = {k:v for k,v in headers.items() if k.lower() in ('authorization','cookie','accept')}
            response_headers = {}
            for key, value in reply['headers']:
                # Only Set-Cookie uses Playwright's newline representation.
                # Newlines in list headers (e.g. repeated Server-Timing from a
                # CDN) can stall Chromium before it commits the navigation.
                key = key.lower()
                separator = '\n' if key == 'set-cookie' else ', '
                response_headers[key] = response_headers[key] + separator + value if key in response_headers else value
            body = base64.b64decode(reply['body_base64'])
            self.assets.put(request.url, request.method, request.resource_type, headers, evidence['status'], response_headers, body)
            await route.fulfill(status=evidence['status'], headers=response_headers, body=body)
        except Exception as error:
            # Relay policy failures are short codes. Preserve them so an agent
            # can distinguish a spent request budget from a broken website;
            # never copy arbitrary exception text or headers into its context.
            code = str(error) if isinstance(error, ValueError) else ''
            if not re.fullmatch(r'[a-z][a-z0-9_]{1,79}', code):
                code = 'browser_request_failed'
            if code == 'target_request_budget_reached':
                self.http_exhausted = True
            self.errors = (self.errors + [code])[-12:]
            await route.abort('failed')
        finally:
            self.inflight -= 1

    async def wallet(self, source, request):
        frame = source['frame']
        if frame != source['page'].main_frame:
            raise ValueError('Wallet request outside approved page')
        if self.scope.get('authentication') != 'wallet':
            raise ValueError('Wallet login not selected')
        if request.get('method') == 'wallet_mode':
            # Discovery can run before navigation commits. This reveals only
            # a transport preference, never an address or signing permission.
            return {'legacy':self.legacy_wallet}
        if origin(frame.url) != self.origin:
            raise ValueError('Wallet request outside approved page')
        if request.get('method') == 'unsupported_method':
            name = request.get('name')
            if isinstance(name, str) and 0 < len(name) <= 80 and name.replace('_','').isascii() and name.replace('_','').isalnum() and len(self.unsupported_wallet_methods) < 12:
                self.unsupported_wallet_methods.add(name)
            return {'recorded':True}
        if request.get('method') == 'eth_accounts':
            return await self.account()
        if request.get('method') != 'personal_sign':
            raise ValueError('Unsupported wallet method')
        params = request.get('params', [])
        if len(params) != 2 or not all(isinstance(p,str) for p in params):
            raise ValueError('Invalid signing parameters')
        account = (await self.account())['address']
        message, address = params
        if message.lower() == account.lower(): address, message = message, address
        if address.lower() != account.lower(): raise ValueError('Wrong signing account')
        if message.startswith('0x'):
            message = bytes.fromhex(message[2:]).decode('utf-8', errors='strict')
        if not 1 <= len(message.encode()) <= 4096: raise ValueError('Invalid login message size')
        if len(self.pending) >= 4: raise ValueError('Too many pending signatures')
        identifier = secrets.token_hex(12)
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = {'message':message,'address':account,'origin':self.origin,
            'page_url':frame.url,'frame':frame,'future':future}
        try:
            return await asyncio.wait_for(future, timeout=180)
        finally:
            self.pending.pop(identifier, None)

    async def account(self):
        # The disposable address is fixed for this role. Repeated connection
        # requests need no relay lookup; every signature still goes to it.
        async with self.wallet_lock:
            if self.wallet_account is None:
                self.wallet_account = await self.call('wallet', {'origin':self.origin,'method':'eth_accounts'})
            return self.wallet_account.copy()

    def page(self):
        pages = [p for p in self.context.pages if origin(p.url) == self.origin]
        if not pages: raise ValueError('Open the approved website with the browser first')
        return pages[-1]

    async def visible_controls(self):
        """Playwright traverses open shadow roots, unlike document.querySelector.
        Return labels and screen positions, never input values or page storage.
        Navigation/clicks still use the existing Hermes browser tools.
        """
        try:
            return await asyncio.wait_for(self.page().locator('button, a, input[type=checkbox], [role=button], [role=checkbox]').evaluate_all('''elements => elements.flatMap(e => {
                const labels = Array.from(e.labels || []);
                const control = e.matches('input[type=checkbox]') ? labels.find(l => {const r=l.getBoundingClientRect();return r.width>2&&r.height>2;}) || e : e;
                const r = control.getBoundingClientRect(), style = getComputedStyle(control);
                if (!r.width || !r.height || r.bottom <= 0 || r.top >= innerHeight || r.right <= 0 || r.left >= innerWidth || style.visibility === 'hidden' || style.display === 'none') return [];
                const label = (e.innerText || e.getAttribute('aria-label') || labels.map(l => l.innerText).join(' ') || '').trim().slice(0,180);
                if (!label) return [];
                return [{label, role:e.getAttribute('role') || e.tagName.toLowerCase(), disabled:!!e.disabled || e.getAttribute('aria-disabled') === 'true', x:Math.round(r.x+r.width/2), y:Math.round(r.y+r.height/2)}];
            }).slice(-50)'''), timeout=2)
        except Exception:
            return []

    async def operation(self, value):
        command = value.get('command')
        if command == 'wait':
            # Waiting uses no inference and lets the bounded asset queue drain.
            # Repeated model calls while a JS bundle loads share the bridge and
            # can otherwise postpone the very UI the agent is inspecting.
            deadline = asyncio.get_running_loop().time() + 120
            try:
                await self.page().wait_for_load_state('load', timeout=120000)
            except Exception:
                pass
            # Lazy imports can start after the load event. Do not busy-loop
            # through model calls while those requests are still in progress.
            while self.inflight and not self.pending and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(.25)
            return await self.operation({'command':'status'})
        if command == 'status':
            # Verification is set only by the broker's explicit check below.
            # Do not queue an inspection behind every asset still loading.
            return {'verified':self.verified, 'pages':[p.url.split('?')[0].split('#')[0] for p in self.context.pages if origin(p.url) == self.origin],
                'wallet_transport':'legacy' if self.legacy_wallet else 'eip6963',
                'unsupported_wallet_methods':sorted(self.unsupported_wallet_methods),
                'pending_signatures':[{'id':key, **{k:v for k,v in item.items() if k in ('message','address','origin')}} for key,item in self.pending.items()],
                'request_errors':self.errors[-5:], 'pending_requests':self.inflight,
                'request_budget_exhausted':self.http_exhausted, 'static_asset_cache_hits':self.assets.hits,
                'blocked_origins':sorted(self.blocked_origins), 'visible_controls':await self.visible_controls()}
        if command == 'legacy':
            if self.scope.get('authentication') != 'wallet' or self.verified or self.pending:
                raise ValueError('Legacy retry requires an unverified wallet connection with no pending signature')
            if self.legacy_wallet: return {'wallet_transport':'legacy','already_selected':True}
            page = self.page()
            self.legacy_wallet = True
            try:
                await page.reload(wait_until='domcontentloaded', timeout=30000)
            except Exception:
                return {'wallet_transport':'legacy','navigation_pending':True}
            return {'wallet_transport':'legacy'}
        if command == 'fill':
            page = self.page()
            if not self.credentials: self.credentials = await self.call('credentials', {})
            for kind in ('username','password'):
                selector = value.get(kind)
                if selector:
                    if not isinstance(selector,str) or len(selector) > 512: raise ValueError('Invalid field selector')
                    await page.locator(selector).fill(self.credentials[kind], timeout=5000)
            return {'filled':True}
        if command == 'begin':
            self.page()
            return await self.call('begin', {})
        if command in ('approve','reject'):
            pending = self.pending.get(value.get('id'))
            if not pending or pending['future'].done(): raise ValueError('Signature no longer pending')
            if command == 'reject':
                pending['future'].set_exception(ValueError('Login signature rejected'))
                return {'rejected':True}
            if pending['frame'].is_detached() or pending['frame'].url != pending['page_url']:
                raise ValueError('Page changed before signature approval')
            signed = await self.call('wallet', {'method':'personal_sign','origin':pending['origin'],
                'address':pending['address'],'message':pending['message'],'approved':True})
            pending['future'].set_result(signed)
            return {'signed':True}
        if command == 'check':
            url = value.get('url','')
            if origin(url) != self.origin: raise ValueError('Check must use the approved origin')
            headers = self.requests.get(url, {}).copy()
            cookies = await self.context.cookies([url])
            if cookies: headers['cookie'] = '; '.join(c['name'] + '=' + c['value'] for c in cookies)
            result = await self.call('check', {'url':url,'headers':headers,'json_pointer':value.get('json_pointer')})
            self.verified = result['verified']
            return result
        raise ValueError('Unknown browser access operation')

    async def handle_control(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            lines = head.decode('ascii').split('\r\n')
            if lines[0] != 'POST / HTTP/1.1': raise ValueError('Invalid control method')
            pairs = [line.split(':',1) for line in lines[1:] if line]
            headers = {key.lower():value.strip() for key,value in pairs}
            if len(headers) != len(pairs) or not hmac.compare_digest(headers.get('authorization',''), 'Bearer ' + self.secret): raise ValueError('Invalid control token')
            length = int(headers.get('content-length','0'))
            if not 0 < length <= MAX_CONTROL: raise ValueError('Invalid control size')
            data = await asyncio.wait_for(reader.readexactly(length),5)
            result = await self.operation(json.loads(data))
            status = 200
        except Exception as error:
            # Errors contain no request bodies, passwords, cookies or signatures.
            result, status = {'error':str(error)[:200] if isinstance(error,ValueError) else 'Browser operation failed'}, 400
        body = json.dumps(result).encode()
        writer.write(f'HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
        await writer.drain()
        writer.close()

    async def close(self):
        for pending in self.pending.values():
            if not pending['future'].done(): pending['future'].cancel()
        self.credentials = None
        self.requests.clear()
        if self.control: self.control.close(); await self.control.wait_closed()
        if self.context: await self.context.close()
        if hasattr(self,'playwright'): await self.playwright.stop()


def cli():
    parser = argparse.ArgumentParser(description='Private account filling and login proof for the approved browser')
    parser.add_argument('command',choices=['status','wait','begin','fill','approve','reject','check','legacy'])
    parser.add_argument('--username', help='CSS selector for username/email input; never enter credentials here')
    parser.add_argument('--password', help='CSS selector for password input; never enter credentials here')
    parser.add_argument('--id', help='Pending signature ID, after reviewing its exact message')
    parser.add_argument('--url', help='Actual protected GET resource or account API observed in the browser')
    parser.add_argument('--json-pointer', help='JSON pointer to supplied username or test wallet address in an account response')
    args = vars(parser.parse_args())
    settings = json.loads(Path('/work/browser-access.json').read_text())
    req = urllib.request.Request(settings['url']+'/',data=json.dumps(args).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+settings['secret']})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=150 if args['command']=='wait' else 60) as response: print(response.read().decode())
    except urllib.error.HTTPError as error:
        print(error.read(MAX_CONTROL).decode()); sys.exit(1)


if __name__ == '__main__': cli()


class BrowserRunner:
    """Own the browser event loop while Hermes runs its synchronous agent loop."""
    def __init__(self, scope, bridge):
        import threading
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name='patchriot-browser', daemon=True)
        self.thread.start()
        self.browser = BrowserAccess(scope, bridge)
        try:
            self.cdp = asyncio.run_coroutine_threadsafe(self.browser.start(), self.loop).result(timeout=60)
            configure_hermes_browser(scope)
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            asyncio.run_coroutine_threadsafe(self.browser.close(), self.loop).result(timeout=15)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=5)
