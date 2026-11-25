import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';

const ALLOWED_BASE_HOSTS = new Set(['h2h.okeconnect.com', 'b2b.okeconnect.com']);
const DIGIFLAZZ_API_BASE = 'https://api.digiflazz.com/v1';
const NONCE_CACHE = new Map();
const MAX_BODY_BYTES = 16384;
const MAX_UPSTREAM_FEED_BYTES = 32 * 1024 * 1024;
const MAX_COMPACT_FEED_BYTES = 12 * 1024 * 1024;
const CLOCK_SKEW_MS = 90_000;

function validIPv4(value) {
  const parts = String(value || '').trim().split('.');
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function header(headers = {}, name) {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (key.toLowerCase() === target) return String(value || '');
  }
  return '';
}

function reply(statusCode, body, contentType = 'application/json; charset=utf-8', extra = {}) {
  return {
    statusCode,
    headers: {
      'content-type': contentType,
      'cache-control': 'no-store, no-cache, must-revalidate',
      'x-content-type-options': 'nosniff',
      ...extra
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  };
}

function eventBody(event) {
  const raw = String(event?.body || '');
  if (event?.isBase64Encoded) return Buffer.from(raw, 'base64').toString('utf8');
  return raw;
}

function eventMethod(event) {
  return String(event?.httpMethod || event?.requestContext?.http?.method || event?.method || 'GET').toUpperCase();
}

function eventPath(event) {
  return String(event?.path || event?.rawPath || event?.requestContext?.path || '/');
}

function validBaseUrl(raw) {
  try {
    const url = new URL(raw || 'https://h2h.okeconnect.com');
    return url.protocol === 'https:' && ALLOWED_BASE_HOSTS.has(url.hostname.toLowerCase())
      && url.pathname === '/' && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function rememberNonce(nonce, now) {
  for (const [key, expires] of NONCE_CACHE) if (expires < now) NONCE_CACHE.delete(key);
  if (NONCE_CACHE.has(nonce)) return false;
  NONCE_CACHE.set(nonce, now + CLOCK_SKEW_MS);
  if (NONCE_CACHE.size > 5000) {
    const first = NONCE_CACHE.keys().next().value;
    if (first) NONCE_CACHE.delete(first);
  }
  return true;
}

function verifyRequest(event, rawBody, secret) {
  const timestamp = header(event.headers, 'x-oke-gateway-timestamp');
  const nonce = header(event.headers, 'x-oke-gateway-nonce');
  const signature = header(event.headers, 'x-oke-gateway-signature');
  const numericTimestamp = Number(timestamp);
  const now = Date.now();
  if (!Number.isFinite(numericTimestamp) || Math.abs(now - numericTimestamp) > CLOCK_SKEW_MS) return false;
  if (!/^[A-Za-z0-9-]{16,100}$/.test(nonce) || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = createHmac('sha256', secret).update(`${timestamp}.${nonce}.${rawBody}`).digest();
  let supplied;
  try { supplied = Buffer.from(signature, 'hex'); } catch { return false; }
  if (supplied.length !== expected.length || !timingSafeEqual(expected, supplied)) return false;
  return rememberNonce(nonce, now);
}

async function health() {
  let ipv4 = '';
  try {
    const response = await fetch('https://api4.ipify.org?format=json', {
      headers: { accept: 'application/json', 'cache-control': 'no-cache' },
      signal: AbortSignal.timeout(7000)
    });
    if (response.ok) {
      const data = await response.json();
      ipv4 = String(data?.ip || '').trim();
    }
  } catch {
    try {
      const response = await fetch('https://checkip.amazonaws.com/', { signal: AbortSignal.timeout(7000) });
      if (response.ok) ipv4 = (await response.text()).trim();
    } catch {}
  }
  if (!validIPv4(ipv4)) {
    return reply(502, { ok: false, error: 'Tidak dapat mendeteksi IPv4 keluar dari fungsi SCF.' });
  }
  return reply(200, {
    ok: true,
    service: 'okeconnect-digiflazz-static-egress-gateway',
    observedOutboundIPv4: ipv4,
    checkedAt: new Date().toISOString(),
    fixedOutboundIpFeature: 'Enable Fixed public outbound IP in Tencent SCF Function Configuration → Network. This endpoint cannot inspect that console toggle.',
    note: 'The observed IP is static only when Tencent SCF Fixed public outbound IP is enabled and remains enabled.'
  });
}

const FEED_SOURCE_PATHS = Object.freeze({
  json: '/harga/json',
  list: '/harga/list',
  h2h: '/harga-h2h/list'
});
const ALLOWED_FEED_HOSTS = new Set(['okeconnect.com', 'www.okeconnect.com']);

function normalizeFeedPathname(pathname) {
  let decoded = String(pathname || '');
  try { decoded = decodeURIComponent(decoded); } catch { throw new Error('Path redirect feed mengandung encoding yang tidak valid.'); }
  return decoded.replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/';
}

function allowedFeedPath(source, pathname, isRedirect = false) {
  const expectedPath = FEED_SOURCE_PATHS[source];
  const path = normalizeFeedPathname(pathname);
  if (path === expectedPath) return true;
  if (!isRedirect) return false;
  // Some OkeConnect edge routes canonicalize a feed URL to its namespace root
  // or PHP-style route. Keep the redirect inside the SAME feed family: H2H can
  // never fall through to the public /harga feed (which is not seller status).
  const aliases = {
    json: new Set(['/harga', '/harga/json.php']),
    list: new Set(['/harga', '/harga/list.php']),
    h2h: new Set(['/harga-h2h', '/harga-h2h/list.php'])
  };
  return aliases[source]?.has(path) === true;
}

function validateOfficialFeedUrl(raw, source, isRedirect = false) {
  source = String(source || '').toLowerCase();
  const expectedPath = FEED_SOURCE_PATHS[source];
  if (!expectedPath) throw new Error('Sumber feed tidak diizinkan.');
  let url;
  try { url = new URL(String(raw || '')); } catch { throw new Error('URL feed tidak valid.'); }
  if (url.protocol !== 'https:' || !ALLOWED_FEED_HOSTS.has(url.hostname.toLowerCase())
      || !allowedFeedPath(source, url.pathname, isRedirect) || url.username || url.password || url.hash) {
    throw new Error('Feed hanya boleh memakai endpoint HTTPS resmi OkeConnect yang sesuai sumber.');
  }
  for (const key of url.searchParams.keys()) {
    if (!['id', 'produk'].includes(key)) throw new Error(`Parameter feed ${key} tidak diizinkan.`);
  }
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(url.searchParams.get('id') || '')) throw new Error('Parameter id feed tidak valid.');
  const products = url.searchParams.get('produk');
  if (products && !/^[A-Za-z0-9_,.-]{1,600}$/.test(products)) throw new Error('Parameter produk feed tidak valid.');
  // H2H status feed is intentionally unfiltered so every payment code can be verified.
  if (source === 'h2h' && products) throw new Error('Feed H2H wajib tidak menggunakan filter produk agar status semua kode dapat diverifikasi.');
  return url;
}

/**
 * OkeConnect's public HTML price page contains the same product tables plus
 * large layout assets/scripts. Keep only its headings and product tables before
 * returning the feed to EdgeOne. This preserves the official Code/Description/
 * Price/Status rows while avoiding the SCF response-size ceiling.
 */
function compactOkeHtmlPriceList(rawHtml) {
  const source = String(rawHtml || '')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ')
    .replace(/<(?:svg|noscript|iframe|video|audio)\b[^>]*>[\s\S]*?<\/(?:svg|noscript|iframe|video|audio)\s*>/gi, ' ')
    .replace(/<(?:header|footer|nav|aside)\b[^>]*>[\s\S]*?<\/(?:header|footer|nav|aside)\s*>/gi, ' ');
  const tables = [...source.matchAll(/<table\b[^>]*>[\s\S]*?<\/table\s*>/gi)];
  if (!tables.length) {
    return source.replace(/<head\b[^>]*>[\s\S]*?<\/head\s*>/gi, ' ')
      .replace(/<meta\b[^>]*>/gi, ' ').replace(/<link\b[^>]*>/gi, ' ');
  }
  const fragments = [];
  let cursor = 0;
  for (const match of tables) {
    const preceding = source.slice(cursor, match.index);
    const headings = [...preceding.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1\s*>/gi)];
    const headingText = headings.length
      ? headings[headings.length - 1][2].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()
      : '';
    const table = match[0].replace(/<(\/?)([a-z][a-z0-9:-]*)\b[^>]*>/gi, (tag, closing, name) => {
      const normalized = String(name).toLowerCase();
      if (['table', 'tr', 'th', 'td'].includes(normalized)) return `<${closing}${normalized}>`;
      return ' ';
    });
    if (headingText) fragments.push(`<h2>${headingText}</h2>`);
    fragments.push(table);
    cursor = match.index + match[0].length;
  }
  return `<!doctype html><html><body>${fragments.join('')}</body></html>`;
}

function retryDelayMs(response, attempt) {
  const retryAfter = Number(response?.headers?.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return Math.min(2000, Math.round(retryAfter * 1000));
  return Math.min(1600, 300 * (2 ** attempt));
}

async function fetchOfficialFeed(source, rawUrl, timeoutMs) {
  let current = validateOfficialFeedUrl(rawUrl, source);
  const originalId = current.searchParams.get('id');
  const originalProducts = current.searchParams.get('produk') || '';
  const expectedPath = FEED_SOURCE_PATHS[source];
  for (let hop = 0; hop <= 3; hop += 1) {
    let upstream;
    let lastError;
    // Price feeds are read-only GET requests, so bounded retries are safe.
    // Never apply this retry policy to balance/trx/status through the gateway.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        upstream = await fetch(current.toString(), {
          method: 'GET',
          headers: {
            accept: source === 'json' ? 'application/json' : 'text/html, application/json;q=0.9, */*;q=0.8',
            'cache-control': 'no-cache'
          },
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs)
        });
        if (![429, 500, 502, 503, 504].includes(upstream.status) || attempt === 2) break;
        await new Promise(resolve => setTimeout(resolve, retryDelayMs(upstream, attempt)));
      } catch (error) {
        lastError = error;
        if (attempt === 2) throw error;
        await new Promise(resolve => setTimeout(resolve, Math.min(1600, 300 * (2 ** attempt))));
      }
    }
    if (!upstream) throw lastError || new Error('Feed OkeConnect tidak memberikan respons.');
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      if (hop === 3) throw new Error('Feed OkeConnect terlalu banyak melakukan redirect.');
      const location = upstream.headers.get('location');
      if (!location) throw new Error(`Feed OkeConnect redirect HTTP ${upstream.status} tanpa Location.`);
      let next;
      try { next = new URL(location, current); } catch { throw new Error('Alamat redirect feed tidak valid.'); }
      if (!allowedFeedPath(source, next.pathname, true)) throw new Error(`Redirect feed OkeConnect mengarah ke path ${normalizeFeedPathname(next.pathname)} di luar kelompok endpoint ${source} yang diizinkan.`);
      current = validateOfficialFeedUrl(next.toString(), source, true);
      // A redirect may change the canonical host (www/non-www), but never
      // the partner ID or selected JSON product scope.
      if (current.searchParams.get('id') !== originalId
          || (current.searchParams.get('produk') || '') !== originalProducts) {
        throw new Error('Redirect feed mengubah parameter ID atau kelompok produk.');
      }
      continue;
    }
    const rawBody = await upstream.text();
    const rawBytes = Buffer.byteLength(rawBody, 'utf8');
    if (rawBytes > MAX_UPSTREAM_FEED_BYTES) throw new Error('Respons upstream feed melebihi batas aman 32 MB.');
    const contentType = upstream.headers.get('content-type') || 'text/plain; charset=utf-8';
    const body = source === 'list' && /text\/html/i.test(contentType)
      ? compactOkeHtmlPriceList(rawBody)
      : rawBody;
    const responseBytes = Buffer.byteLength(body, 'utf8');
    if (responseBytes > MAX_COMPACT_FEED_BYTES) throw new Error('Daftar harga masih terlalu besar setelah diringkas (maksimum 12 MB).');
    return { status: upstream.status, body, contentType, rawBytes, responseBytes };
  }
  throw new Error('Feed OkeConnect tidak dapat diambil setelah redirect.');
}

async function proxyPriceFeed(input, requestId, reject) {
  const source = String(input?.source || '').toLowerCase();
  let url;
  try { url = validateOfficialFeedUrl(input?.url, source); }
  catch (error) { return reject(400, 'price-feed-url-rejected', error.message); }
  const timeoutMs = Math.min(25000, Math.max(5000, Number(input?.timeoutMs) || 15000));
  const startedAt = Date.now();
  try {
    const result = await fetchOfficialFeed(source, url.toString(), timeoutMs);
    console.info(JSON.stringify({
      event: 'okeconnect_price_feed_complete', requestId, source,
      providerStatus: result.status,
      upstreamBytes: result.rawBytes,
      responseBytes: result.responseBytes,
      compacted: result.rawBytes !== result.responseBytes,
      elapsedMs: Date.now() - startedAt
    }));
    return reply(result.status, result.body, result.contentType, {
      'x-oke-static-egress': 'tencent-scf',
      'x-oke-feed-source': source,
      'x-oke-gateway-request-id': requestId
    });
  } catch (error) {
    console.error(JSON.stringify({ event: 'okeconnect_price_feed_error', requestId, source, elapsedMs: Date.now() - startedAt }));
    return reject(502, 'price-feed-upstream-failed', `Gateway tidak dapat mengambil feed ${source}: ${String(error?.message || 'koneksi upstream gagal').slice(0, 180)}`);
  }
}


async function proxyDigiflazz(input, requestId, reject) {
  const path = String(input?.path || '');
  const body = input?.body && typeof input.body === 'object' && !Array.isArray(input.body) ? input.body : {};
  const pingMatch = /^\/report\/hooks\/[A-Za-z0-9_-]{6,80}\/pings$/.test(path);
  if (!['/price-list', '/transaction'].includes(path) && !pingMatch) return reject(400, 'digiflazz-path-not-allowed', 'Gateway hanya mengizinkan API Buyer pascabayar dan ping webhook Digiflazz.');
  if (pingMatch) {
    // Ping endpoint uses an empty POST body and does not require Buyer signature fields.
  } else if (path === '/price-list') {
    if (String(body.cmd || '') !== 'pasca') return reject(400, 'digiflazz-command-not-allowed', 'Gateway hanya mengizinkan price-list pascabayar (cmd=pasca).');
  } else if (path === '/transaction') {
    const command = String(body.commands || '');
    if (!['inq-pasca', 'pay-pasca', 'status-pasca'].includes(command)) return reject(400, 'digiflazz-command-not-allowed', 'Gateway hanya mengizinkan transaksi pascabayar Digiflazz.');
    if (!/^[A-Z0-9]{4,5}$/.test(String(body.buyer_sku_code || ''))) return reject(400, 'digiflazz-sku-invalid', 'buyer_sku_code harus 4–5 huruf kapital atau angka.');
    if (!/^[A-Za-z0-9._-]{6,80}$/.test(String(body.ref_id || ''))) return reject(400, 'digiflazz-ref-invalid', 'ref_id tidak valid.');
    if (!String(body.customer_no || '').trim()) return reject(400, 'digiflazz-customer-invalid', 'customer_no wajib diisi.');
    if (body.amount !== undefined && (command !== 'inq-pasca' || !Number.isSafeInteger(Number(body.amount)) || Number(body.amount) <= 0)) {
      return reject(400, 'digiflazz-amount-invalid', 'amount hanya boleh berupa bilangan bulat positif pada inq-pasca.');
    }
  }
  if (!pingMatch && (!String(body.username || '').trim() || !/^[a-f0-9]{32}$/i.test(String(body.sign || '')))) {
    return reject(400, 'digiflazz-auth-fields-invalid', 'Username atau signature Digiflazz tidak valid.');
  }
  const target = new URL(`${DIGIFLAZZ_API_BASE}${path}`);
  const startedAt = Date.now();
  try {
    const upstream = await fetch(target.toString(), {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      ...(pingMatch ? {} : { body: JSON.stringify(body) }),
      redirect: 'error',
      signal: AbortSignal.timeout(path === '/price-list' ? 25000 : 30000)
    });
    const responseBody = await upstream.text();
    if (Buffer.byteLength(responseBody, 'utf8') > 12 * 1024 * 1024) {
      return reject(502, 'digiflazz-response-too-large', 'Respons Digiflazz melebihi batas 12 MB.');
    }
    console.info(JSON.stringify({
      event: 'digiflazz_proxy_complete', requestId,
      operation: pingMatch ? 'webhook-ping' : (path === '/price-list' ? 'price-list-pasca' : String(body.commands || 'transaction')),
      providerStatus: upstream.status,
      responseBytes: Buffer.byteLength(responseBody, 'utf8'),
      elapsedMs: Date.now() - startedAt
    }));
    return reply(upstream.status, responseBody, upstream.headers.get('content-type') || 'application/json; charset=utf-8', {
      'x-digiflazz-static-egress': 'tencent-scf',
      'x-digiflazz-provider-status': String(upstream.status),
      'x-digiflazz-gateway-request-id': requestId
    });
  } catch {
    console.error(JSON.stringify({ event: 'digiflazz_proxy_error', requestId, operation: path, elapsedMs: Date.now() - startedAt }));
    return reply(502, { error: 'Gateway SCF tidak berhasil menghubungi server Digiflazz.', requestId }, 'application/json; charset=utf-8', {
      'x-digiflazz-static-egress': 'tencent-scf',
      'x-digiflazz-gateway-error': 'upstream-fetch-failed',
      'x-digiflazz-gateway-request-id': requestId
    });
  }
}

async function proxy(event, rawBody) {
  const requestId = randomUUID();
  const startedAt = Date.now();
  const reject = (statusCode, code, message) => {
    console.warn(JSON.stringify({ event: 'okeconnect_proxy_rejected', requestId, code, statusCode, elapsedMs: Date.now() - startedAt }));
    return reply(statusCode, { error: message, requestId }, 'application/json; charset=utf-8', {
      'x-oke-static-egress': 'tencent-scf',
      'x-oke-gateway-request-id': requestId,
      'x-oke-gateway-stage': code
    });
  };
  const secret = String(process.env.OKE_STATIC_EGRESS_SHARED_SECRET || '').trim();
  if (secret.length < 32) return reject(503, 'gateway-secret-not-configured', 'Gateway secret belum dikonfigurasi dengan benar.');
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) return reject(413, 'request-too-large', 'Request gateway terlalu besar.');
  if (!verifyRequest(event, rawBody, secret)) return reject(401, 'signature-rejected', 'Autentikasi gateway tidak valid atau request kedaluwarsa.');

  let input;
  try { input = JSON.parse(rawBody); } catch { return reject(400, 'invalid-json', 'Body JSON tidak valid.'); }
  const endpoint = String(input?.endpoint || '');
  if (!['balance', 'trx', 'status', 'price-feed', 'digiflazz'].includes(endpoint)) return reject(400, 'endpoint-not-allowed', 'Endpoint gateway tidak diizinkan.');
  if (endpoint === 'price-feed') return proxyPriceFeed(input, requestId, reject);
  if (endpoint === 'digiflazz') return proxyDigiflazz(input, requestId, reject);
  const credentials = input?.credentials || {};
  const memberID = String(credentials.memberID || '').trim();
  const pin = String(credentials.pin || '').trim();
  const password = String(credentials.password || '').trim();
  if (!memberID || !pin || !password) return reject(400, 'credentials-incomplete', 'Kredensial H2H belum lengkap.');

  const baseRaw = String(input?.baseUrl || process.env.OKE_API_BASE_URL || 'https://h2h.okeconnect.com').trim();
  if (!validBaseUrl(baseRaw)) return reject(400, 'base-url-invalid', 'Base URL OkeConnect harus h2h.okeconnect.com atau b2b.okeconnect.com.');
  const allowedParams = new Set(['product', 'dest', 'refID', 'check', 'qty']);
  const params = input?.params && typeof input.params === 'object' && !Array.isArray(input.params) ? input.params : {};
  for (const key of Object.keys(params)) if (!allowedParams.has(key)) return reject(400, 'parameter-not-allowed', `Parameter ${key} tidak diizinkan.`);
  if (endpoint !== 'balance') {
    const isOpenNominal = /^BBS/i.test(String(params.product || '').trim());
    const hasQty = Object.prototype.hasOwnProperty.call(params, 'qty');
    if (isOpenNominal) {
      const qty = Number(params.qty);
      if (!hasQty || !Number.isSafeInteger(qty) || qty < 10000) {
        return reject(400, 'open-nominal-qty-invalid', 'Produk BBS wajib mengirim qty berupa bilangan bulat minimal 10000.');
      }
    } else if (hasQty) {
      return reject(400, 'qty-not-allowed', 'Parameter qty hanya diizinkan untuk produk bebas nominal berkode BBS.');
    }
  }
  if (endpoint !== 'balance') {
    for (const key of ['product', 'dest', 'refID']) {
      if (!String(params[key] || '').trim()) return reject(400, 'transaction-parameter-missing', `Parameter ${key} wajib untuk transaksi/status.`);
    }
  }
  if (endpoint === 'status' && String(params.check || '') !== '1') return reject(400, 'status-check-required', 'Pemeriksaan status wajib menggunakan check=1.');
  if (endpoint === 'trx' && params.check !== undefined) return reject(400, 'transaction-check-not-allowed', 'Parameter check tidak boleh untuk transaksi baru.');

  const target = new URL(endpoint === 'balance' ? '/balance' : '/trx', baseRaw);
  target.searchParams.set('memberID', memberID);
  target.searchParams.set('pin', pin);
  target.searchParams.set('password', password);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value) !== '') target.searchParams.set(key, String(value));
  }

  try {
    const upstream = await fetch(target.toString(), {
      method: 'GET',
      headers: { accept: 'application/json, text/plain, */*', 'cache-control': 'no-cache' },
      redirect: 'error',
      signal: AbortSignal.timeout(18000)
    });
    const body = await upstream.text();
    const contentType = upstream.headers.get('content-type') || 'text/plain; charset=utf-8';
    // Safe telemetry only: never log target URL/query, request body, or credentials.
    console.info(JSON.stringify({
      event: 'okeconnect_proxy_complete', requestId, endpoint,
      providerStatus: upstream.status, contentType,
      responseBytes: Buffer.byteLength(body, 'utf8'),
      elapsedMs: Date.now() - startedAt
    }));
    return reply(upstream.status, body, contentType, {
      'x-oke-static-egress': 'tencent-scf',
      'x-oke-provider-status': String(upstream.status),
      'x-oke-gateway-request-id': requestId
    });
  } catch (error) {
    console.error(JSON.stringify({
      event: 'okeconnect_proxy_error', requestId, endpoint,
      error: 'upstream-fetch-failed', elapsedMs: Date.now() - startedAt
    }));
    return reply(502, 'Gateway SCF tidak berhasil menghubungi server OkeConnect.', 'text/plain; charset=utf-8', {
      'x-oke-static-egress': 'tencent-scf',
      'x-oke-gateway-error': 'upstream-fetch-failed',
      'x-oke-gateway-request-id': requestId
    });
  }
}
export async function main_handler(event = {}) {
  const method = eventMethod(event);
  const path = eventPath(event).replace(/\/+$/, '') || '/';
  if (method === 'GET' && path.endsWith('/health')) return health();
  if (method !== 'POST' || !path.endsWith('/proxy')) return reply(404, { error: 'Route gateway tidak ditemukan.' });
  return proxy(event, eventBody(event));
}
