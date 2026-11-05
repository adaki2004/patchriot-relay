// A disposable EIP-1193 provider. Signing is completed by the relay, never by
// page JavaScript. The page still owns its login requests and session storage.
(() => {
  if (window.top !== window) return;
  const listeners = new Map();
  let chain = '0x1';
  let accounts = [];
  const emit = (name, value) => (listeners.get(name) || []).forEach(fn => { try { fn(value); } catch {} });
  const provider = Object.freeze({
    isPatchriot: true,
    get chainId() { return chain; },
    get networkVersion() { return String(parseInt(chain, 16)); },
    get selectedAddress() { return accounts[0] || null; },
    isConnected: () => accounts.length > 0,
    on(name, fn) { if (typeof fn === 'function') listeners.set(name, [...(listeners.get(name) || []), fn]); return provider; },
    removeListener(name, fn) { listeners.set(name, (listeners.get(name) || []).filter(item => item !== fn)); return provider; },
    send(payload, callback) {
      if (typeof payload === 'string') return provider.request({method:payload, params:Array.isArray(callback) ? callback : []});
      const result = provider.request(payload).then(value => ({jsonrpc:'2.0', id:payload.id, result:value}));
      if (typeof callback === 'function') { result.then(value => callback(null,value), error => callback(error,null)); return; }
      return result;
    },
    sendAsync(payload, callback) { return provider.send(payload, callback); },
    async request({method, params = []} = {}) {
      if (method === 'eth_chainId') return chain;
      if (method === 'net_version') return String(parseInt(chain, 16));
      if (method === 'eth_accounts') return [...accounts];
      if (method === 'eth_requestAccounts') {
        const result = await window.__patchriot_wallet_rpc({method:'eth_accounts'});
        accounts = [result.address];
        emit('connect', {chainId:chain}); emit('accountsChanged', [...accounts]);
        return [...accounts];
      }
      if (method === 'wallet_switchEthereumChain') {
        const value = params?.[0]?.chainId;
        if (!/^0x[0-9a-f]{1,12}$/i.test(value || '') || parseInt(value, 16) === 0) throw Object.assign(new Error('Invalid test chain'), {code:4902});
        chain = value.toLowerCase(); emit('chainChanged', chain); return null;
      }
      if (method === 'wallet_requestPermissions' && Object.keys(params?.[0] || {}).join() === 'eth_accounts') {
        await provider.request({method:'eth_requestAccounts'});
        return [{parentCapability:'eth_accounts'}];
      }
      if (method === 'wallet_getPermissions') return accounts.length ? [{parentCapability:'eth_accounts'}] : [];
      if (method !== 'personal_sign') {
        window.__patchriot_wallet_rpc({method:'unsupported_method', name:method}).catch(() => {});
        throw Object.assign(new Error('This test wallet supports login messages only'), {code:4200});
      }
      if (!accounts.length) throw Object.assign(new Error('Connect the test wallet first'), {code:4100});
      const result = await window.__patchriot_wallet_rpc({method, params, chainId:chain});
      return result.signature;
    },
  });
  Object.defineProperty(window, 'ethereum', {value:provider, configurable:false, writable:false});
  const info = Object.freeze({
    uuid:'9cfae789-33fa-4e87-969c-a7cf02778a8e', name:'Patchriot Test Wallet', rdns:'tech.patchriot.testwallet',
    icon:'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="%2317202c"/><path d="M9 9h9a5 5 0 0 1 0 10h-4v5H9zm5 5v1h4v-1z" fill="white"/></svg>',
  });
  // Some older pickers suppress their generic injected option as soon as any
  // EIP-6963 provider appears, then ignore unfamiliar provider names. The agent
  // can retry the standard window.ethereum transport, without posing as a brand.
  const mode = window.__patchriot_wallet_rpc({method:'wallet_mode'});
  const announce = () => mode.then(value => {
    if (!value.legacy) window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {detail:Object.freeze({info,provider})}));
  }).catch(() => {});
  window.addEventListener('eip6963:requestProvider', announce);
  announce();
})();
