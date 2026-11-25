import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { main_handler } from '../index.js';

const sharedSecret = 'shared-secret-for-static-egress-gateway-test-123456';

function signedEvent(path, payload) {
  const body = JSON.stringify(payload);
  const timestamp = String(Date.now());
  const nonce = randomUUID();
  const signature = createHmac('sha256', sharedSecret).update(`${timestamp}.${nonce}.${body}`).digest('hex');
  return {
    httpMethod: 'POST',
    path,
    headers: {
      'x-oke-gateway-timestamp': timestamp,
      'x-oke-gateway-nonce': nonce,
      'x-oke-gateway-signature': signature
    },
    body
  };
}

test('health reports the public IPv4 observed by SCF', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  globalThis.fetch = async () => new Response(JSON.stringify({ ip: '203.0.113.25' }), { status: 200 });
  try {
    const result = await main_handler({ httpMethod: 'GET', path: '/health' });
    assert.equal(result.statusCode, 200);
    assert.equal(JSON.parse(result.body).observedOutboundIPv4, '203.0.113.25');
  } finally { globalThis.fetch = oldFetch; }
});

test('signed proxy request reaches only the allowed OkeConnect balance endpoint', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let requested;
  const originalInfo = console.info;
  let logged = '';
  console.info = value => { logged += String(value); };
  globalThis.fetch = async (url, options) => {
    requested = new URL(url);
    assert.equal(options.method, 'GET');
    return new Response(JSON.stringify({ status: true, data: { balance: 9000 } }), {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' }
    });
  };
  try {
    const event = signedEvent('/proxy', {
      endpoint: 'balance',
      baseUrl: 'https://h2h.okeconnect.com',
      credentials: { memberID: 'OKTEST01', pin: '1234', password: 'secret-pass' },
      params: {}
    });
    const result = await main_handler(event);
    assert.equal(result.statusCode, 200);
    assert.equal(requested.pathname, '/balance');
    assert.equal(requested.searchParams.get('memberID'), 'OKTEST01');
    assert.equal(requested.searchParams.get('pin'), '1234');
    assert.equal(result.headers['x-oke-static-egress'], 'tencent-scf');
    assert.ok(result.headers['x-oke-gateway-request-id']);
    assert.match(logged, /okeconnect_proxy_complete/);
    assert.doesNotMatch(logged, /secret-pass|OKTEST01|pin/);
  } finally { globalThis.fetch = oldFetch; console.info = originalInfo; }
});


test('BBS open-nominal qty is accepted and forwarded by the static egress gateway', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let requested;
  globalThis.fetch = async url => {
    requested = new URL(url);
    return new Response('accepted', { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  };
  try {
    const event = signedEvent('/proxy', {
      endpoint: 'trx',
      baseUrl: 'https://h2h.okeconnect.com',
      credentials: { memberID: 'OKTEST01', pin: '1234', password: 'secret-pass' },
      params: { product: 'BBSDN', dest: '081234567890', refID: 'OCREFBBS001', qty: 50000 }
    });
    const result = await main_handler(event);
    assert.equal(result.statusCode, 200);
    assert.equal(requested.pathname, '/trx');
    assert.equal(requested.searchParams.get('qty'), '50000');
  } finally { globalThis.fetch = oldFetch; }
});

test('gateway rejects missing, too-small, or non-BBS qty before calling OkeConnect', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let upstreamCalled = false;
  globalThis.fetch = async () => { upstreamCalled = true; throw new Error('must not reach provider'); };
  const base = {
    endpoint: 'trx', baseUrl: 'https://h2h.okeconnect.com',
    credentials: { memberID: 'OKTEST01', pin: '1234', password: 'secret-pass' }
  };
  try {
    const cases = [
      { product: 'BBSDN', dest: '081234567890', refID: 'OCREFBBS002' },
      { product: 'BBSDN', dest: '081234567890', refID: 'OCREFBBS003', qty: 9999 },
      { product: 'T5', dest: '081234567890', refID: 'OCREFT5001', qty: 50000 }
    ];
    for (const params of cases) {
      const result = await main_handler(signedEvent('/proxy', { ...base, params }));
      assert.equal(result.statusCode, 400);
    }
    assert.equal(upstreamCalled, false);
  } finally { globalThis.fetch = oldFetch; }
});

test('proxy rejects missing or invalid HMAC signature', async () => {
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  const result = await main_handler({ httpMethod: 'POST', path: '/proxy', headers: {}, body: '{}' });
  assert.equal(result.statusCode, 401);
});

test('proxy rejects unknown host even with valid HMAC signature', async () => {
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  const event = signedEvent('/proxy', {
    endpoint: 'balance', baseUrl: 'https://attacker.example',
    credentials: { memberID: 'OKTEST01', pin: '1234', password: 'secret-pass' }, params: {}
  });
  const result = await main_handler(event);
  assert.equal(result.statusCode, 400);
  assert.match(result.body, /Base URL OkeConnect/);
});


test('proxy rejection emits a safe request ID for diagnostics without logging credentials', async () => {
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  const oldWarn = console.warn;
  let logged = '';
  console.warn = value => { logged += String(value); };
  try {
    const result = await main_handler({ httpMethod: 'POST', path: '/proxy', headers: {}, body: '{}' });
    assert.equal(result.statusCode, 401);
    assert.ok(result.headers['x-oke-gateway-request-id']);
    assert.match(logged, /signature-rejected/);
    assert.doesNotMatch(logged, /secret-pass|memberID|password/);
  } finally { console.warn = oldWarn; }
});


test('health rejects an invalid IPv4 address from the echo provider', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ ip: '999.10.10.10' }), { status: 200 });
  try {
    const response = await main_handler({ httpMethod: 'GET', path: '/health' });
    assert.equal(response.statusCode, 502);
    assert.match(response.body, /Tidak dapat mendeteksi IPv4/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('signed price-feed proxy fetches only the official OkeConnect H2H table', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let requested;
  globalThis.fetch = async (url, options) => {
    requested = new URL(url);
    assert.equal(options.method, 'GET');
    return new Response('<table><tr><th>Kode</th><th>Nama</th><th>Harga</th><th>Status</th></tr><tr><td>A5</td><td>Axis 5.000</td><td>5852</td><td>OPEN</td></tr></table>', {
      status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'price-feed', source: 'h2h',
      url: 'https://okeconnect.com/harga-h2h/list?id=905ccd028329b0a'
    }));
    assert.equal(result.statusCode, 200);
    assert.equal(requested.hostname, 'okeconnect.com');
    assert.equal(requested.pathname, '/harga-h2h/list');
    assert.equal(result.headers['x-oke-feed-source'], 'h2h');
    assert.match(result.body, /Axis 5.000/);
  } finally { globalThis.fetch = oldFetch; }
});


test('official OkeConnect list compacts an oversized HTML response and preserves code/status rows', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  const giantAssets = 'x'.repeat(6 * 1024 * 1024);
  const html = `<html><head><style>${giantAssets}</style></head><body><nav>menu</nav><h2>Telkomsel</h2><table><tr><th>Kode</th><th>Keterangan</th><th>Harga</th><th>Status</th></tr><tr><td>T5</td><td>Telkomsel 5.000</td><td>Rp 5.205</td><td>open</td></tr></table><script>${giantAssets}</script></body></html>`;
  assert.ok(Buffer.byteLength(html, 'utf8') > 12 * 1024 * 1024);
  globalThis.fetch = async url => {
    assert.equal(new URL(url).pathname, '/harga/list');
    return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'price-feed', source: 'list',
      url: 'https://okeconnect.com/harga/list?id=905ccd028329b0a&produk=pulsa'
    }));
    assert.equal(result.statusCode, 200);
    assert.match(result.body, /<td>T5<\/td>/);
    assert.match(result.body, /<td>open<\/td>/);
    assert.match(result.body, /Telkomsel 5\.000<\/td>/);
    assert.doesNotMatch(result.body, /<script|<style|menu/);
    assert.ok(Buffer.byteLength(result.body, 'utf8') < 12 * 1024 * 1024);
    assert.equal(result.headers['x-oke-feed-source'], 'list');
  } finally { globalThis.fetch = oldFetch; }
});

test('signed price-feed proxy rejects filtered H2H feeds and non-OkeConnect hosts', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let upstreamCalled = false;
  globalThis.fetch = async () => { upstreamCalled = true; throw new Error('must not reach upstream'); };
  try {
    const filtered = await main_handler(signedEvent('/proxy', { endpoint: 'price-feed', source: 'h2h', url: 'https://okeconnect.com/harga-h2h/list?id=905ccd028329b0a&produk=pulsa' }));
    const evil = await main_handler(signedEvent('/proxy', { endpoint: 'price-feed', source: 'h2h', url: 'https://evil.example/harga-h2h/list?id=905ccd028329b0a' }));
    assert.equal(filtered.statusCode, 400);
    assert.equal(evil.statusCode, 400);
    assert.equal(upstreamCalled, false);
  } finally { globalThis.fetch = oldFetch; }
});


test('signed feed proxy rejects redirect that changes the OkeConnect partner id', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  globalThis.fetch = async () => new Response('', {
    status: 302,
    headers: { location: 'https://www.okeconnect.com/harga-h2h/list?id=999999999999999' }
  });
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'price-feed', source: 'h2h',
      url: 'https://okeconnect.com/harga-h2h/list?id=905ccd028329b0a'
    }));
    assert.equal(result.statusCode, 502);
    assert.match(result.body, /mengubah parameter ID/);
  } finally { globalThis.fetch = oldFetch; }
});

test('price-feed retries transient upstream failures but succeeds without changing the target', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let calls = 0;
  globalThis.fetch = async url => {
    calls += 1;
    assert.equal(new URL(url).pathname, '/harga/json');
    if (calls < 3) return new Response('temporarily unavailable', { status: 503 });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'price-feed', source: 'json',
      url: 'https://okeconnect.com/harga/json?id=905ccd028329b0a&produk=pulsa'
    }));
    assert.equal(result.statusCode, 200);
    assert.equal(calls, 3);
    assert.match(result.body, /"ok":true/);
  } finally { globalThis.fetch = oldFetch; }
});

test('transaction endpoint is not automatically retried after an upstream error', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    throw new Error('simulated network failure');
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'trx', baseUrl: 'https://h2h.okeconnect.com',
      credentials: { memberID: 'OKTEST01', pin: '1234', password: 'secret-pass' },
      params: { product: 'T5', dest: '081234567890', refID: 'OCREFSAFE001' }
    }));
    assert.equal(result.statusCode, 502);
    assert.equal(calls, 1);
  } finally { globalThis.fetch = oldFetch; }
});


test('signed H2H feed follows only safe aliases inside the H2H endpoint family', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let calls = 0;
  let finalRequest;
  globalThis.fetch = async url => {
    calls += 1;
    finalRequest = new URL(url);
    if (calls === 1) return new Response('', {status:302, headers:{location:'https://www.okeconnect.com/harga-h2h/list.php?id=905ccd028329b0a'}});
    return new Response('<table><tr><th>Kode</th><th>Nama</th><th>Harga</th><th>Status</th></tr><tr><td>BYRAXIS</td><td>AXIS BAYAR</td><td>5000</td><td>OPEN</td></tr></table>', {status:200,headers:{'content-type':'text/html; charset=utf-8'}});
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {endpoint:'price-feed',source:'h2h',url:'https://okeconnect.com/harga-h2h/list?id=905ccd028329b0a'}));
    assert.equal(result.statusCode,200);
    assert.equal(calls,2);
    assert.equal(finalRequest.pathname,'/harga-h2h/list.php');
    assert.match(result.body,/BYRAXIS/);
  } finally { globalThis.fetch = oldFetch; }
});

test('H2H feed redirect cannot switch to public price feed or login paths', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  globalThis.fetch = async () => new Response('', {status:302,headers:{location:'https://okeconnect.com/login?id=905ccd028329b0a'}});
  try {
    const result = await main_handler(signedEvent('/proxy', {endpoint:'price-feed',source:'h2h',url:'https://okeconnect.com/harga-h2h/list?id=905ccd028329b0a'}));
    assert.equal(result.statusCode,502);
    assert.match(result.body,/path \/login/);
  } finally { globalThis.fetch = oldFetch; }
});

test('signed Digiflazz Buyer pasca price list uses the fixed SCF gateway and only the official API host', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let requested;
  globalThis.fetch = async (url, options) => {
    requested = new URL(url);
    assert.equal(options.method, 'POST');
    assert.equal(JSON.parse(options.body).cmd, 'pasca');
    return new Response(JSON.stringify({ data: [{ buyer_sku_code: 'PLN01' }] }), {
      status: 200, headers: { 'content-type': 'application/json' }
    });
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'digiflazz', path: '/price-list', body: { cmd: 'pasca', username: 'buyer-demo', sign: 'a'.repeat(32) }
    }));
    assert.equal(result.statusCode, 200);
    assert.equal(requested.hostname, 'api.digiflazz.com');
    assert.equal(requested.pathname, '/v1/price-list');
    assert.equal(result.headers['x-digiflazz-static-egress'], 'tencent-scf');
  } finally { globalThis.fetch = oldFetch; }
});

test('Digiflazz pasca transaction enforces 4-5 character SKU and only allowed commands', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let upstreamCalled = false;
  globalThis.fetch = async (url, options) => {
    upstreamCalled = true;
    assert.equal(new URL(url).pathname, '/v1/transaction');
    return new Response(JSON.stringify({ data: { status: 'Sukses' } }), { status: 200 });
  };
  try {
    const good = await main_handler(signedEvent('/proxy', {
      endpoint: 'digiflazz', path: '/transaction', body: {
        commands: 'inq-pasca', username: 'buyer-demo', sign: 'a'.repeat(32),
        buyer_sku_code: 'PLN01', customer_no: '1234567890', ref_id: 'DFTEST123456', amount: 50000
      }
    }));
    assert.equal(good.statusCode, 200);
    upstreamCalled = false;
    const badSku = await main_handler(signedEvent('/proxy', {
      endpoint: 'digiflazz', path: '/transaction', body: {
        commands: 'inq-pasca', username: 'buyer-demo', sign: 'a'.repeat(32),
        buyer_sku_code: 'TOOLONG', customer_no: '1234567890', ref_id: 'DFTEST123457'
      }
    }));
    assert.equal(badSku.statusCode, 400);
    assert.equal(upstreamCalled, false);
    const badCommand = await main_handler(signedEvent('/proxy', {
      endpoint: 'digiflazz', path: '/transaction', body: {
        commands: 'topup', username: 'buyer-demo', sign: 'a'.repeat(32),
        buyer_sku_code: 'PLN01', customer_no: '1234567890', ref_id: 'DFTEST123458'
      }
    }));
    assert.equal(badCommand.statusCode, 400);
    assert.equal(upstreamCalled, false);
  } finally { globalThis.fetch = oldFetch; }
});

test('Digiflazz webhook ping route is the only non-transaction pass-through route', async () => {
  const oldFetch = globalThis.fetch;
  process.env.OKE_STATIC_EGRESS_SHARED_SECRET = sharedSecret;
  let requested;
  globalThis.fetch = async (url, options) => {
    requested = new URL(url);
    assert.equal(options.method, 'POST');
    assert.equal(options.body, undefined);
    return new Response(JSON.stringify({ hook_id: 'abc12345' }), { status: 200 });
  };
  try {
    const result = await main_handler(signedEvent('/proxy', {
      endpoint: 'digiflazz', path: '/report/hooks/abc12345/pings', body: {}
    }));
    assert.equal(result.statusCode, 200);
    assert.equal(requested.pathname, '/v1/report/hooks/abc12345/pings');
  } finally { globalThis.fetch = oldFetch; }
});
