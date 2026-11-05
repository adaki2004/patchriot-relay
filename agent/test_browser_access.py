"""Owned browser fixtures, no external targets or model calls.

Opt in with PATCHRIOT_BROWSER_FIXTURE=1 inside the isolated browser image.
PATCHRIOT_BROWSER_EXECUTABLE may select an installed Chromium for local fixtures.
"""
import asyncio
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from browser_access import BrowserAccess, configure_hermes_browser

ORIGIN = 'https://owned.example'
ADDRESS = '0x1111111111111111111111111111111111111111'

PASSWORD_PAGE = '''<!doctype html><html><body>
<a href="/sign-in">Member sign in</a>
<form><label>Email<input id="user" type="email"></label><label>Password<input id="pass" type="password"></label><button>Enter</button></form>
<p id="account"></p><script>
document.querySelector('form').onsubmit = async event => {
 event.preventDefault();
 const r = await fetch('/unusual-session-path', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({member:document.querySelector('#user').value,code:document.querySelector('#pass').value})});
 if (r.ok) document.querySelector('#account').textContent = (await (await fetch('/account-data')).json()).email;
};
</script></body></html>'''


def wallet_page(layout):
    submit = "{challengeId:c.id,address:a,signature:s,chainId:1}" if layout == 'challenge' else "{nonce:c.nonce,signature:s}"
    challenge = '/auth/start' if layout == 'challenge' else '/wallet/challenge'
    verify = '/auth/finish' if layout == 'challenge' else '/wallet/verify'
    return f'''<!doctype html><html><body><button id="connect">Connect wallet</button><p id="account"></p><script>
let provider;
window.addEventListener('eip6963:announceProvider', e => provider=e.detail.provider);
window.dispatchEvent(new Event('eip6963:requestProvider'));
document.querySelector('#connect').onclick = async () => {{
 const [a] = await provider.request({{method:'eth_requestAccounts'}});
 const c = await (await fetch('{challenge}',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{address:a}})}})).json();
 const bytes = Array.from(new TextEncoder().encode(c.message)).map(n=>n.toString(16).padStart(2,'0')).join('');
 const s = await provider.request({{method:'personal_sign',params:['0x'+bytes,a]}});
 await fetch('{verify}',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({submit})}});
 document.querySelector('#account').textContent = (await (await fetch('/account-data')).json()).address;
}};
</script></body></html>'''


class FixtureBrowser(BrowserAccess):
    def __init__(self, mode, directory, executable, layout='challenge'):
        super().__init__({'origins':[ORIGIN],'authentication':mode,'browser_login':{}},'unused',directory=directory,executable=executable)
        self.mode, self.layout = mode, layout
        self.calls = []
        self.signed = []
        self.seq = 0

    async def call(self, path, data):
        if path == 'credentials': return {'username':'fixture@example.com','password':'synthetic-password'}
        if path == 'begin': return {'login_submissions':8}
        if path == 'status': return {'verified':self.verified}
        if path == 'wallet':
            if data['method'] == 'eth_accounts': return {'address':ADDRESS}
            assert data['approved'] and data['origin'] == ORIGIN
            self.signed.append(data['message'])
            return {'signature':'fixture-signature'}
        if path == 'check':
            # Real protected-control validation lives in Rust and has independent
            # TCP/crypto tests. This fixture checks the controller's session handoff.
            assert data['url'] == ORIGIN + '/account-data'
            assert 'session=owned-fixture' in data['headers']['cookie']
            return {'verified':True,'authenticated_evidence_id':8,'anonymous_evidence_id':9}
        assert path == 'http'
        if origin_of(data['url']) in self.resources:
            assert not data['authenticated'] and not data['login']
            self.calls.append(data)
            return {'evidence':{'id':100,'status':200,'error':None}, 'headers':[['content-type','application/javascript'],['access-control-allow-origin',ORIGIN]], 'body_base64':base64.b64encode(b'window.dependencyLoaded=true').decode()}
        assert origin_of(data['url']) == ORIGIN
        self.calls.append(data)
        self.seq += 1
        route = urlsplit(data['url']).path
        status, headers = 200, [['content-type','application/json']]
        if route in ('/','/sign-in'):
            body = PASSWORD_PAGE if self.mode == 'session' else wallet_page(self.layout)
            headers = [['content-type','text/html']]
        elif route == '/unusual-session-path':
            assert json.loads(data['data']) == {'member':'fixture@example.com','code':'synthetic-password'}
            body = '{}'; headers.append(['set-cookie','session=owned-fixture; Secure; HttpOnly; Path=/'])
        elif route in ('/auth/start','/wallet/challenge'):
            assert json.loads(data['data']) == {'address':ADDRESS}
            body = json.dumps({'id':'abc-123','nonce':'newNonce123','message':'Welcome to our owned fixture. Log in: token-123.'})
        elif route in ('/auth/finish','/wallet/verify'):
            payload = json.loads(data['data'])
            expected = {'challengeId':'abc-123','address':ADDRESS,'signature':'fixture-signature','chainId':1} if self.layout == 'challenge' else {'nonce':'newNonce123','signature':'fixture-signature'}
            assert payload == expected
            body = '{}'; headers.append(['set-cookie','session=owned-fixture; Secure; HttpOnly; Path=/'])
        elif route == '/account-data':
            if 'session=owned-fixture' in data['headers'].get('cookie',''):
                body = json.dumps({'email':'fixture@example.com','address':ADDRESS})
            else: status, body = 401, '{}'
        elif route == '/repeated-headers':
            body = '<!doctype html><title>Loaded</title><p>Repeated headers work</p>'
            headers = [['content-type','text/html'], ['server-timing','edge;dur=10'],
                ['server-timing','origin;dur=20'], ['x-content-type-options','nosniff'],
                ['content-security-policy',"default-src 'none'"],
                ['set-cookie','first=one; Secure; HttpOnly; Path=/'],
                ['set-cookie','second=two; Secure; HttpOnly; Path=/']]
        else: status, body = 404, '{}'
        return {'evidence':{'id':self.seq,'status':status,'error':None},'headers':headers,'body_base64':base64.b64encode(body.encode()).decode()}


def origin_of(url):
    p=urlsplit(url)
    return p.scheme+'://'+p.netloc


@unittest.skipUnless(os.environ.get('PATCHRIOT_BROWSER_FIXTURE') == '1','requires explicit owned-browser fixture opt-in')
class BrowserFixtures(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.browser=None

    async def asyncTearDown(self):
        if self.browser: await self.browser.close()
        self.directory.cleanup()

    async def start(self, mode, layout='challenge'):
        self.browser=FixtureBrowser(mode,self.directory.name,os.environ.get('PATCHRIOT_BROWSER_EXECUTABLE','/usr/bin/chromium'),layout)
        self.cdp = await self.browser.start()
        page=self.browser.context.pages[0]
        await page.goto(ORIGIN)
        return page

    async def test_password_login_runs_the_sites_javascript_and_keeps_its_cookie(self):
        page=await self.start('session')
        await self.browser.operation({'command':'begin'})
        result=await self.browser.operation({'command':'fill','username':'#user','password':'#pass'})
        self.assertEqual(result,{'filled':True})
        self.assertNotIn('synthetic-password',json.dumps(result))
        await page.get_by_role('button',name='Enter').click()
        await page.wait_for_function("document.querySelector('#account').textContent.includes('@')")
        result=await self.browser.operation({'command':'check','url':ORIGIN+'/account-data'})
        self.assertTrue(result['verified'])
        self.assertTrue(self.browser.verified)

    async def wallet_login(self, layout):
        page=await self.start('wallet',layout)
        await self.browser.operation({'command':'begin'})
        await page.get_by_role('button',name='Connect wallet').click()
        for _ in range(100):
            if self.browser.pending: break
            await asyncio.sleep(.05)
        status=await self.browser.operation({'command':'status'})
        request=status['pending_signatures'][0]
        self.assertEqual(request['origin'],ORIGIN)
        self.assertFalse(self.browser.signed)
        await self.browser.operation({'command':'approve','id':request['id']})
        await page.wait_for_function("document.querySelector('#account').textContent.startsWith('0x')")
        self.assertEqual(self.browser.signed,[request['message']])
        result=await self.browser.operation({'command':'check','url':ORIGIN+'/account-data','json_pointer':'/address'})
        self.assertTrue(result['verified'])
        # Transaction and typed-data methods never reach the signing broker.
        for method in ['eth_sendTransaction','eth_sign','eth_signTypedData_v4','wallet_sendCalls']:
            error=await page.evaluate("async method=>{try{await ethereum.request({method,params:[]});return null;}catch(e){return e.code}}",method)
            self.assertEqual(error,4200)

    async def test_wallet_uses_frontend_challenge_id_payload_without_an_adapter(self):
        await self.wallet_login('challenge')

    async def test_wallet_uses_frontend_nonce_payload_without_an_adapter(self):
        await self.wallet_login('nonce')

    async def test_external_and_localhost_fetches_never_reach_the_network_broker(self):
        page=await self.start('session')
        before=len(self.browser.calls)
        for url in ['https://outside.example/','http://127.0.0.1:1/','http://169.254.169.254/']:
            failed=await page.evaluate("async url=>{try{await fetch(url);return false;}catch{return true;}}",url)
            self.assertTrue(failed)
        self.assertEqual(len(self.browser.calls),before)
        self.assertIn('https://outside.example', self.browser.blocked_origins)
        self.assertEqual(self.browser.inflight, 0)
        with self.assertRaises(ValueError):
            await self.browser.operation({'command':'check','url':'https://outside.example/private'})

    async def test_status_finds_shadow_wallet_controls_without_echoing_input_values(self):
        page=await self.start('session')
        await page.evaluate('''() => {
            const host=document.createElement('div'); document.body.append(host);
            host.attachShadow({mode:'open'}).innerHTML='<button>Fixture injected wallet</button><input type="password" value="never-echo-this">';
        }''')
        status=await self.browser.operation({'command':'status'})
        control=next(c for c in status['visible_controls'] if c['label']=='Fixture injected wallet')
        self.assertGreater(control['x'],0)
        self.assertGreater(control['y'],0)
        self.assertNotIn('never-echo-this',json.dumps(status))
        self.assertEqual(status['pending_requests'],0)

    async def test_checkbox_control_uses_its_visible_label_and_status_does_not_wait_for_http(self):
        page=await self.start('session')
        await page.evaluate('''() => {
            const container=document.createElement('div');document.body.append(container);
            container.innerHTML='<input id="terms" type="checkbox" style="position:absolute;width:1px;height:1px;clip:rect(0,0,0,0)"><label for="terms" style="display:block;width:250px;height:40px">Accept fixture terms</label>';
        }''')
        async def blocked(path,data):
            raise AssertionError('Status must not use the busy HTTP bridge')
        self.browser.call=blocked
        status=await self.browser.operation({'command':'status'})
        control=next(c for c in status['visible_controls'] if c['label']=='Accept fixture terms')
        await page.mouse.click(control['x'],control['y'])
        self.assertTrue(await page.locator('#terms').is_checked())

    async def test_approved_public_resources_load_but_cannot_become_login_pages(self):
        page=await self.start('session')
        self.browser.resources.add('https://cdn.example.com')
        await page.add_script_tag(url='https://cdn.example.com/app.js')
        self.assertTrue(await page.evaluate('window.dependencyLoaded'))
        before=len(self.browser.calls)
        with self.assertRaises(Exception):
            await page.goto('https://cdn.example.com/login')
        self.assertEqual(len(self.browser.calls),before)
        with self.assertRaises(ValueError):
            await self.browser.operation({'command':'check','url':'https://cdn.example.com/login'})

    async def test_legacy_wallet_retry_uses_injected_rpc_without_impersonating_a_wallet_brand(self):
        page=await self.start('wallet')
        await self.browser.operation({'command':'legacy'})
        await page.evaluate("window.announcements=0; window.addEventListener('eip6963:announceProvider',()=>window.announcements++); window.dispatchEvent(new Event('eip6963:requestProvider'))")
        await asyncio.sleep(.1)
        self.assertEqual(await page.evaluate('window.announcements'),0)
        result=await page.evaluate("async()=>{const accounts=await ethereum.send('eth_requestAccounts',[]);return {accounts,address:ethereum.selectedAddress,chain:ethereum.chainId,metamask:!!ethereum.isMetaMask}}")
        self.assertEqual(result,{'accounts':[ADDRESS],'address':ADDRESS,'chain':'0x1','metamask':False})
        denied=await page.evaluate("()=>new Promise(resolve=>ethereum.sendAsync({id:1,method:'eth_sendTransaction',params:[]},error=>resolve(error.code)))")
        self.assertEqual(denied,4200)

    async def test_discovery_before_navigation_does_not_grant_wallet_access(self):
        page=await self.start('wallet')
        await page.goto('about:blank')
        mode=await page.evaluate("()=>window.__patchriot_wallet_rpc({method:'wallet_mode'})")
        self.assertEqual(mode,{'legacy':False})
        error=await page.evaluate("async()=>{try{await window.__patchriot_wallet_rpc({method:'eth_accounts'});return null;}catch(e){return e.message;}}")
        self.assertIn('outside approved page',error)

    async def test_wait_allows_a_late_script_to_finish_before_the_next_inspection(self):
        page=await self.start('session')
        original=self.browser.call
        entered, release=asyncio.Event(), asyncio.Event()
        async def delayed(path,data):
            if path=='http' and data['url']==ORIGIN+'/late.js':
                entered.set()
                await release.wait()
                return {'evidence':{'id':100,'status':200,'error':None},'headers':[['content-type','application/javascript']], 'body_base64':base64.b64encode(b'window.lateScriptLoaded=true').decode()}
            return await original(path,data)
        self.browser.call=delayed
        await page.evaluate("()=>{const script=document.createElement('script');script.src='/late.js';document.head.append(script)}")
        await asyncio.wait_for(entered.wait(),timeout=5)
        waiting=asyncio.create_task(self.browser.operation({'command':'wait'}))
        await asyncio.sleep(.1)
        self.assertFalse(waiting.done())
        release.set()
        status=await asyncio.wait_for(waiting,timeout=5)
        self.assertEqual(status['pending_requests'],0)
        self.assertTrue(await page.evaluate('window.lateScriptLoaded'))

    async def test_request_failure_keeps_policy_codes_but_not_arbitrary_error_text(self):
        page=await self.start('session')
        async def denied(path,data):
            if data['url'].endswith('/budget'):
                raise ValueError('target_request_budget_reached')
            raise ValueError('Authorization: Bearer private-value')
        self.browser.call=denied
        for path in ('/budget','/private-error'):
            await page.evaluate("async path=>{try{await fetch(path)}catch{}}",path)
        status=await self.browser.operation({'command':'status'})
        self.assertEqual(status['request_errors'],['target_request_budget_reached','browser_request_failed'])
        self.assertNotIn('private-value',json.dumps(status))

    async def test_repeated_response_headers_allow_navigation_and_keep_separate_cookies(self):
        page=await self.start('session')
        await page.goto(ORIGIN+'/repeated-headers', timeout=5000)
        self.assertEqual(await page.title(), 'Loaded')
        cookies={c['name']:c['value'] for c in await self.browser.context.cookies()}
        self.assertEqual(cookies, {'first':'one', 'second':'two'})
        blocked=await page.evaluate("async()=>{try{await fetch('/account-data');return false;}catch{return true;}}")
        self.assertTrue(blocked, 'The page CSP must still block fetch')

    async def test_hermes_browser_tool_attaches_to_the_scoped_context(self):
        # Exercise the actual pinned runtime tool, without asking any model.
        await self.start('session')
        previous = os.environ.get('BROWSER_CDP_URL')
        os.environ['BROWSER_CDP_URL'] = self.cdp
        try:
            configure_hermes_browser(self.browser.scope)
            from tools.browser_tool import browser_navigate, browser_snapshot
            task = 'patchriot-owned-browser-fixture'
            result = await asyncio.to_thread(browser_navigate, ORIGIN+'/sign-in', task_id=task)
            self.assertTrue(any(c['url'] == ORIGIN+'/sign-in' for c in self.browser.calls), result)
            snapshot = await asyncio.to_thread(browser_snapshot, task_id=task)
            self.assertIn('Enter', snapshot)
            count = len(self.browser.calls)
            rejected = await asyncio.to_thread(browser_navigate, 'https://outside.example/', task_id=task)
            self.assertEqual(len(self.browser.calls), count, rejected)
            self.assertEqual(self.browser.page().url, ORIGIN+'/sign-in')
        finally:
            from tools.browser_tool_lifecycle import cleanup_browser
            await asyncio.to_thread(cleanup_browser, task)
            if previous is None: os.environ.pop('BROWSER_CDP_URL', None)
            else: os.environ['BROWSER_CDP_URL'] = previous


if __name__=='__main__': unittest.main()
