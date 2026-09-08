const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const argon2 = require('argon2');
const mysql = require('mysql2');
const Stripe = require('stripe');

// A dependency-free dotenv reader. Existing environment variables always win.
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (match && process.env[match[1]] === undefined) {
      process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  }
}

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'north_country_shop', waitForConnections: true,
  connectionLimit: 10, queueLimit: 0
});
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// Prices are integer cents and are never accepted from a browser.
const CATALOG = Object.freeze({
  'Organic Ashwagandha': 100,
  "Lion's Mane Extract": 100,
  'Herbal Sleep Tea Blend': 100,
  'Raw Local Propolis': 100
});

const taxMap = new Map();
for (const filename of fs.readdirSync(__dirname).filter(f => /^TAXRATES_ZIP5_[A-Z]{2}\d+\.csv$/.test(f))) {
  const lines = fs.readFileSync(path.join(__dirname, filename), 'utf8').split(/\r?\n/);
  const headers = (lines.shift() || '').split(',');
  const zip = headers.indexOf('ZipCode');
  const state = headers.indexOf('State');
  const region = headers.indexOf('TaxRegionName');
  const rate = headers.indexOf('EstimatedCombinedRate');
  if ([zip, state, region, rate].includes(-1)) continue;
  for (const line of lines) {
    const columns = line.split(',');
    if (columns.length <= Math.max(zip, state, region, rate)) continue;
    taxMap.set(columns[zip].trim().padStart(5, '0'), {
      state: columns[state].trim(), region: columns[region].trim(),
      combinedRate: Number.parseFloat(columns[rate]) || 0
    });
  }
}

const sessions = new Map();
const completedIntents = new Set();
const SESSION_TTL = 8 * 60 * 60 * 1000;
const rateLimits = new Map();
const MAX_BODY = 64 * 1024;
const STATIC_FILES = new Map([
  ['/', 'index.html'], ['/index.html', 'index.html'], ['/home.html', 'home.html'],
  ['/login.html', 'login.html'], ['/signup.html', 'signup.html'], ['/styles.css', 'styles.css']
]);

function json(res, status, value, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(value));
}

function securityHeaders(res) {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' https://api.stripe.com; frame-src https://js.stripe.com https://hooks.stripe.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(self "https://js.stripe.com")');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
}

function clientIp(req) {
  // Only honor proxy headers when explicitly deployed behind a trusted proxy.
  const raw = process.env.TRUST_PROXY === '1' ? req.headers['x-forwarded-for']?.split(',')[0] : req.socket.remoteAddress;
  return String(raw || 'unknown').trim().replace(/^::ffff:/, '');
}

function limited(req, bucket, max, windowMs = 15 * 60 * 1000) {
  const key = `${bucket}:${clientIp(req)}`;
  const now = Date.now();
  let entry = rateLimits.get(key);
  if (!entry || now >= entry.reset) entry = { count: 0, reset: now + windowMs };
  entry.count += 1;
  rateLimits.set(key, entry);
  return entry.count > max;
}

function readJson(req, res, callback) {
  let body = '';
  let size = 0;
  let ended = false;
  req.on('data', chunk => {
    size += chunk.length;
    if (size > MAX_BODY && !ended) {
      ended = true;
      json(res, 413, { success: false, error: 'Request too large.' });
      req.destroy();
    } else body += chunk;
  });
  req.on('end', () => {
    if (ended) return;
    try { callback(JSON.parse(body || '{}')); }
    catch { json(res, 400, { success: false, error: 'Invalid JSON payload.' }); }
  });
}

function sessionFor(req) {
  const token = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('session='))?.slice(8);
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expires < Date.now()) { sessions.delete(token); return null; }
  return { token, ...session };
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { user, expires: Date.now() + SESSION_TTL });
  return token;
}

function cookie(token, maxAge = SESSION_TTL / 1000) {
  return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function calculateCart(items, zipCode) {
  if (!Array.isArray(items) || items.length < 1 || items.length > 50) throw new Error('Invalid cart.');
  let subtotal = 0;
  const normalized = items.map(item => {
    const name = typeof item === 'string' ? item : item?.name;
    if (!Object.hasOwn(CATALOG, name)) throw new Error('Unknown catalog item.');
    subtotal += CATALOG[name];
    return name;
  });
  const zip = String(zipCode || '').match(/^\d{5}/)?.[0];
  const rate = zip && taxMap.get(zip) ? taxMap.get(zip).combinedRate : 0;
  const tax = Math.round(subtotal * rate);
  return { items: normalized, subtotal, tax, total: subtotal + tax, zip: zip || '' };
}

function proxyJson(url, headers, done) {
  https.get(url, { headers }, upstream => {
    let data = '';
    upstream.on('data', c => { if (data.length < 256000) data += c; });
    upstream.on('end', () => { try { done(null, JSON.parse(data)); } catch (error) { done(error); } });
  }).on('error', done);
}

const handler = (req, res) => {
  securityHeaders(res);
  const url = new URL(req.url, 'https://localhost');

  if (url.pathname === '/api/signup' && req.method === 'POST') {
    if (limited(req, 'auth', 20)) return json(res, 429, { success: false, message: 'Too many requests. Try again later.' });
    return readJson(req, res, async ({ name, email, password }) => {
      name = typeof name === 'string' ? name.trim() : '';
      email = typeof email === 'string' ? email.trim().toLowerCase() : '';
      if (!name || name.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || typeof password !== 'string' || password.length < 12 || password.length > 128) {
        return json(res, 400, { success: false, message: 'Enter a valid name, email, and password of 12–128 characters.' });
      }
      try {
        const hash = await argon2.hash(password, { type: argon2.argon2id });
        db.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash], err => {
          if (err?.code === 'ER_DUP_ENTRY') return json(res, 409, { success: false, message: 'Unable to create account with those details.' });
          if (err) return json(res, 500, { success: false, message: 'Unable to create account.' });
          json(res, 201, { success: true, message: 'Account created!' });
        });
      } catch { json(res, 500, { success: false, message: 'Unable to create account.' }); }
    });
  }

  if (url.pathname === '/api/login' && req.method === 'POST') {
    if (limited(req, 'auth', 20)) return json(res, 429, { success: false, message: 'Too many requests. Try again later.' });
    return readJson(req, res, ({ email, password }) => {
      email = typeof email === 'string' ? email.trim().toLowerCase() : '';
      db.execute('SELECT id, name, email, password_hash FROM users WHERE email = ?', [email], async (err, rows) => {
        const fallback = '$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';
        let valid = false;
        try { valid = await argon2.verify(rows?.[0]?.password_hash || fallback, typeof password === 'string' ? password : ''); } catch {}
        if (err || !rows?.length || !valid) return json(res, 401, { success: false, message: 'Invalid email or password.' });
        const user = { id: rows[0].id, name: rows[0].name, email: rows[0].email };
        const token = createSession(user);
        json(res, 200, { success: true, message: 'Authenticated!', user }, { 'Set-Cookie': cookie(token) });
      });
    });
  }

  if (url.pathname === '/api/session' && req.method === 'GET') {
    const session = sessionFor(req);
    return json(res, 200, { authenticated: Boolean(session), user: session?.user || null });
  }
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const session = sessionFor(req);
    if (session) sessions.delete(session.token);
    return json(res, 200, { success: true }, { 'Set-Cookie': cookie('', 0) });
  }

  if (url.pathname === '/api/stripe-config' && req.method === 'GET') {
    return json(res, 200, { publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '' });
  }
  if (url.pathname === '/api/create-payment-intent' && req.method === 'POST') {
    if (limited(req, 'payment', 10, 60 * 1000)) return json(res, 429, { error: 'Too many payment requests. Try again shortly.' });
    return readJson(req, res, async ({ items, zipCode }) => {
      try {
        if (!stripe) throw new Error('Stripe is not configured.');
        const cart = calculateCart(items, zipCode);
        const intent = await stripe.paymentIntents.create({
          amount: cart.total, currency: 'usd', automatic_payment_methods: { enabled: true },
          metadata: { cart_hash: crypto.createHash('sha256').update(JSON.stringify(cart.items)).digest('hex'), zip: cart.zip }
        });
        json(res, 200, { clientSecret: intent.client_secret, amount: cart.total });
      } catch (error) { console.error('Payment intent:', error.message); json(res, 400, { error: 'Unable to create payment.' }); }
    });
  }
  if (url.pathname === '/api/place-order' && req.method === 'POST') {
    if (limited(req, 'payment', 10, 60 * 1000)) return json(res, 429, { success: false, error: 'Too many payment requests.' });
    return readJson(req, res, async ({ paymentIntentId, items, zipCode }) => {
      try {
        if (!stripe || !/^pi_[A-Za-z0-9]+$/.test(paymentIntentId || '')) throw new Error('Invalid payment.');
        const cart = calculateCart(items, zipCode);
        const intent = await stripe.paymentIntents.retrieve(paymentIntentId);
        const expectedHash = crypto.createHash('sha256').update(JSON.stringify(cart.items)).digest('hex');
        if (intent.status !== 'succeeded' || intent.amount_received !== cart.total || intent.currency !== 'usd' || intent.metadata.cart_hash !== expectedHash) {
          return json(res, 402, { success: false, error: 'Payment has not been successfully verified.' });
        }
        if (completedIntents.has(intent.id)) return json(res, 409, { success: false, error: 'This payment has already been used.' });
        completedIntents.add(intent.id);
        const userId = sessionFor(req)?.user.id || null;
        db.execute('INSERT INTO orders (user_id, total_price, status, created_at) VALUES (?, ?, ?, NOW())', [userId, cart.total / 100, 'completed'], (err, result) => {
          if (err) { completedIntents.delete(intent.id); return json(res, 500, { success: false, error: 'Database error saving order.' }); }
          json(res, 201, { success: true, message: 'Order placed!', orderId: result.insertId });
        });
      } catch (error) { console.error('Place order:', error.message); json(res, 400, { success: false, error: 'Unable to verify order.' }); }
    });
  }

  if (url.pathname === '/api/calculate-tax' && req.method === 'POST') {
    return readJson(req, res, ({ zipCode, address }) => {
      const zip = String(zipCode || address || '').match(/\b\d{5}\b/)?.[0];
      const details = zip && taxMap.get(zip);
      json(res, 200, details ? { success: true, zipCode: zip, taxDetails: details } : { success: false, error: 'No tax data for this ZIP.' });
    });
  }
  if (url.pathname === '/api/validate-address' && req.method === 'POST') {
    return readJson(req, res, ({ street, zip }) => {
      if (typeof street !== 'string' || !street.trim() || !/^\d{5}(?:-\d{4})?$/.test(zip || '')) return json(res, 400, { success: false, error: 'Street and ZIP are required.' });
      const query = encodeURIComponent(`${street.trim()}, ${zip}, USA`);
      proxyJson(`https://nominatim.openstreetmap.org/search?q=${query}&format=json&addressdetails=1&limit=1&countrycodes=us`, { 'User-Agent': process.env.APP_USER_AGENT || 'NorthCountryShop/1.0' }, (error, results) => {
        if (error || !results?.[0]?.address) return json(res, 200, { success: false, error: 'Address not found. Please check it.' });
        const a = results[0].address;
        json(res, 200, { success: true, matchedAddress: results[0].display_name, city: a.city || a.town || a.village || '', state: a.state || '', zip: a.postcode?.split('-')[0] || zip });
      });
    });
  }
  if (url.pathname === '/api/location' && req.method === 'GET') {
    if (!process.env.geoapi) return json(res, 503, { error: 'Location service is not configured.' });
    const ip = encodeURIComponent(clientIp(req));
    return proxyJson(`https://api.ipgeolocation.io/ipgeo?apiKey=${encodeURIComponent(process.env.geoapi)}&ip=${ip}`, {}, (error, value) => {
      if (error || value?.message) return json(res, 502, { error: 'Location lookup failed.' });
      json(res, 200, { city: value.city, region_code: value.state_code?.replace('US-', '') || value.state_prov, country_code: value.country_code2 });
    });
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed.' }, { Allow: 'GET, HEAD' });
  const filename = STATIC_FILES.get(url.pathname);
  if (!filename) return json(res, 404, { error: 'Not found.' });
  const filePath = path.join(__dirname, filename);
  fs.readFile(filePath, (error, content) => {
    if (error) return json(res, 404, { error: 'Not found.' });
    const type = path.extname(filename) === '.css' ? 'text/css; charset=utf-8' : 'text/html; charset=utf-8';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': filename.endsWith('.html') ? 'no-cache' : 'public, max-age=3600' });
    res.end(req.method === 'HEAD' ? undefined : content);
  });
};

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of sessions) if (value.expires < now) sessions.delete(key);
  for (const [key, value] of rateLimits) if (value.reset < now) rateLimits.delete(key);
}, 30 * 60 * 1000).unref();

const port = Number(process.env.PORT) || 8080;
const key = path.resolve(__dirname, process.env.SSL_KEY_FILE || 'server.key');
const cert = path.resolve(__dirname, process.env.SSL_CERT_FILE || 'server.crt');
const server = fs.existsSync(key) && fs.existsSync(cert)
  ? https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert), minVersion: 'TLSv1.2' }, handler)
  : http.createServer(handler);
server.listen(port, () => console.log(`Server listening on port ${port}${server instanceof https.Server ? ' with TLS' : ''}.`));
