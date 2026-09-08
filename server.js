const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const mysql = require('mysql2');
const argon2 = require('argon2');
 
// Load .env manually and clean trailing carriage returns (\r) or surrounding quotes
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf-8').split('\n').forEach(line => {
    const idx = line.indexOf('=');
    if (idx === -1) return;
    const key = line.substring(0, idx).trim();
    const val = line.substring(idx + 1).trim().replace(/['"\r]/g, '');
    if (key && val) process.env[key] = val;
  });
  console.log('🔑 Environment Config Loaded.');
}
 
// SSL/TLS
const sslKeyPath  = path.join(__dirname, process.env.SSL_KEY_FILE  || 'server.key');
const sslCertPath = path.join(__dirname, process.env.SSL_CERT_FILE || 'server.crt');
const options = {
  key:  fs.readFileSync(sslKeyPath),
  cert: fs.readFileSync(sslCertPath),
  // SECURITY: require TLS 1.2 minimum
  minVersion: 'TLSv1.2',
};
 
// MySQL connection pool
const db = mysql.createPool({
  host:             process.env.DB_HOST     || 'localhost',
  user:             process.env.DB_USER     || 'root',
  password:         process.env.DB_PASSWORD || process.env.DB_PASS || '',
  database:         process.env.DB_NAME     || 'north_country_shop',
  waitForConnections: true,
  connectionLimit:  10,
  queueLimit:       0
});
 
// =========================================================================
// SECURITY: IN-MEMORY RATE LIMITER
// Limits /api/login and /api/signup to 20 attempts per IP per 15 minutes
// =========================================================================
const rateLimitStore = new Map();
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX       = 20;
 
function checkRateLimit(ip) {
  const now   = Date.now();
  const entry = rateLimitStore.get(ip) || { count: 0, windowStart: now };
  if (now - entry.windowStart > RATE_WINDOW_MS) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count++;
  rateLimitStore.set(ip, entry);
  return entry.count > RATE_MAX;
}
 
// Prune stale entries every 30 minutes
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [ip, entry] of rateLimitStore) {
    if (entry.windowStart < cutoff) rateLimitStore.delete(ip);
  }
}, 30 * 60 * 1000);
 
// SECURITY: Read request body with a 64 KB size cap to prevent memory exhaustion
const MAX_BODY_BYTES = 64 * 1024;
function readBody(req, res, cb) {
  let body  = '';
  let bytes = 0;
  req.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Request too large.' }));
      req.destroy();
      return;
    }
    body += chunk.toString();
  });
  req.on('end', () => cb(body));
}
 
// SECURITY: Add security headers to every response
function setSecurityHeaders(res) {
  res.setHeader('Strict-Transport-Security',  'max-age=63072000; includeSubDomains');
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',            'DENY');
  res.setHeader('X-XSS-Protection',           '1; mode=block');
  res.setHeader('Referrer-Policy',            'strict-origin-when-cross-origin');
}
 
// =========================================================================
// NATIONWIDE IN-MEMORY TAX PRE-LOADING
// =========================================================================
const taxMap = new Map();
 
function loadTaxData() {
  try {
    const taxFiles = fs.readdirSync(__dirname).filter(f =>
      f.startsWith('TAXRATES_ZIP5_') && f.endsWith('.csv')
    );
 
    if (!taxFiles.length) {
      console.log('⚠️ No TAXRATES_ZIP5_*.csv files found.');
      return;
    }
 
    console.log(`📂 Found ${taxFiles.length} tax file(s). Loading...`);
 
    for (const filename of taxFiles) {
      const lines = fs.readFileSync(path.join(__dirname, filename), 'utf-8').split('\n');
      if (lines.length < 2) continue;
 
      const headers     = lines[0].split(',');
      const zipIdx      = headers.indexOf('ZipCode');
      const stateIdx    = headers.indexOf('State');
      const regionIdx   = headers.indexOf('TaxRegionName');
      const combinedIdx = headers.indexOf('EstimatedCombinedRate');
 
      if ([zipIdx, stateIdx, regionIdx, combinedIdx].includes(-1)) {
        console.log(`❌ Skipping ${filename}: header mismatch.`);
        continue;
      }
 
      for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].trim().split(',');
        if (cols.length <= Math.max(zipIdx, stateIdx, regionIdx, combinedIdx)) continue;
        const zipCode = cols[zipIdx].trim().padStart(5, '0');
        taxMap.set(zipCode, {
          state:        cols[stateIdx].trim(),
          region:       cols[regionIdx].trim(),
          combinedRate: parseFloat(cols[combinedIdx]) || 0
        });
      }
    }
 
    console.log(`📊 Tax map ready: ${taxMap.size} ZIP codes indexed.`);
  } catch (err) {
    console.error('❌ Tax map build error:', err.message);
  }
}
loadTaxData();
// =========================================================================
 
const server = https.createServer(options, (req, res) => {
 
  // Apply security headers to every response
  setSecurityHeaders(res);
 
  const clientIp = (req.socket.remoteAddress || '').replace('::ffff:', '');
 
  // ── ENDPOINT 1: Sign-Up ───────────────────────────────────────────────
  if (req.url === '/api/signup' && req.method === 'POST') {
    // SECURITY: rate limit signup
    if (checkRateLimit(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: false, message: 'Too many requests. Try again later.' }));
    }
 
    readBody(req, res, async body => {
      try {
        const { name, email, password } = JSON.parse(body);
 
        // SECURITY: validate inputs before touching the DB
        if (!name || typeof name !== 'string' || name.trim().length < 1 || name.length > 120) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, message: 'Invalid name.' }));
        }
        if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || email.length > 254) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, message: 'Invalid email address.' }));
        }
        if (!password || typeof password !== 'string' || password.length < 12 || password.length > 128) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, message: 'Password must be 12–128 characters.' }));
        }
 
        const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
 
        db.execute('SELECT id FROM users WHERE email = ?', [email.trim().toLowerCase()], (err, results) => {
          if (err) { res.writeHead(500, {'Content-Type':'application/json'}); return res.end(JSON.stringify({success:false,message:'DB error.'})); }
          if (results.length > 0) {
            res.writeHead(400, {'Content-Type':'application/json'});
            return res.end(JSON.stringify({success:false,message:'Email already registered!'}));
          }
          db.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name.trim(), email.trim().toLowerCase(), passwordHash], (err, result) => {
            if (err) { res.writeHead(500, {'Content-Type':'application/json'}); return res.end(JSON.stringify({success:false,message:'DB write error.'})); }
            console.log(`👤 Registered: ${name.trim()} (${email.trim()})`);
            res.writeHead(200, {'Content-Type':'application/json'});
            res.end(JSON.stringify({success:true,message:'Account created!'}));
          });
        });
      } catch (e) {
        res.writeHead(500, {'Content-Type':'application/json'});
        res.end(JSON.stringify({success:false,message:'Server error.'}));
      }
    });
    return;
  }
 
  // ── ENDPOINT 2: Log-In ────────────────────────────────────────────────
  if (req.url === '/api/login' && req.method === 'POST') {
    // SECURITY: rate limit login to slow brute-force attacks
    if (checkRateLimit(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: false, message: 'Too many requests. Try again later.' }));
    }
 
    readBody(req, res, body => {
      try {
        const { email: rawEmail, password } = JSON.parse(body);
        const email = (rawEmail || '').trim().toLowerCase();
        db.execute('SELECT id, name, email, password_hash FROM users WHERE email = ?', [email], async (err, results) => {
          if (err) { res.writeHead(500, {'Content-Type':'application/json'}); return res.end(JSON.stringify({success:false,message:'DB error.'})); }
 
          // SECURITY: always run argon2.verify even when user not found
          // This prevents timing attacks that reveal whether an email exists
          const dummyHash = '$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';
          const hashToVerify = results.length ? results[0].password_hash : dummyHash;
          let match = false;
          try { match = await argon2.verify(hashToVerify, password || ''); } catch {}
 
          if (!results.length || !match) {
            res.writeHead(401, {'Content-Type':'application/json'});
            return res.end(JSON.stringify({success:false,message:'Invalid email or password!'}));
          }
          const user = results[0];
          console.log(`🔒 Login: ${user.name} (id=${user.id})`);
          res.writeHead(200, {'Content-Type':'application/json'});
          res.end(JSON.stringify({
            success: true,
            message: 'Authenticated!',
            user: { id: user.id, name: user.name, email: user.email }
          }));
        });
      } catch (e) {
        res.writeHead(500, {'Content-Type':'application/json'});
        res.end(JSON.stringify({success:false,message:'Auth error.'}));
      }
    });
    return;
  }
 
  // ── ENDPOINT 3: IP Geolocation ────────────────────────────────────────
  if (req.url === '/api/location' && req.method === 'GET') {
    const apiKey = process.env.geoapi;
    let cleanIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
      .replace('::ffff:', '').split(',')[0].trim();
    if (['127.0.0.1','::1','localhost'].includes(cleanIp)) {
      cleanIp = process.env.DEV_FALLBACK_IP || '2a0d:5600:222:5000:e519:a06:a750:7579';
    }
    https.get(`https://api.ipgeolocation.io/ipgeo?apiKey=${apiKey}&ip=${encodeURIComponent(cleanIp)}`, geoRes => {
      let data = '';
      geoRes.on('data', c => { data += c; });
      geoRes.on('end', () => {
        try {
          const p = JSON.parse(data);
          if (p.message) { res.writeHead(400, {'Content-Type':'application/json'}); return res.end(JSON.stringify({error:p.message})); }
          res.writeHead(200, {'Content-Type':'application/json'});
          res.end(JSON.stringify({
            city:         p.city,
            region_code:  p.state_code ? p.state_code.replace('US-','') : p.state_prov,
            country_code: p.country_code2
          }));
        } catch { res.writeHead(500, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Parse error.'})); }
      });
    }).on('error', () => { res.writeHead(500, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Geo request failed.'})); });
    return;
  }
 
  // ── ENDPOINT 4: Tax Lookup ────────────────────────────────────────────
  if (req.url === '/api/calculate-tax' && req.method === 'POST') {
    readBody(req, res, body => {
      try {
        const { address } = JSON.parse(body);
        if (!address?.trim()) {
          res.writeHead(400, {'Content-Type':'application/json'});
          return res.end(JSON.stringify({success:false,error:'Address cannot be empty.'}));
        }
        const osmUrl = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(address)}&format=json&addressdetails=1&limit=1`;
        https.get(osmUrl, {headers:{'User-Agent': process.env.APP_USER_AGENT || 'NorthCountryShopTaxApp/1.0'}}, osmRes => {
          let data = '';
          osmRes.on('data', c => { data += c; });
          osmRes.on('end', () => {
            try {
              const results = JSON.parse(data);
              if (!results.length || !results[0].address) {
                res.writeHead(200, {'Content-Type':'application/json'});
                return res.end(JSON.stringify({success:false,error:'Could not verify address.'}));
              }
              const rawZip = results[0].address.postcode;
              if (!rawZip) {
                res.writeHead(200, {'Content-Type':'application/json'});
                return res.end(JSON.stringify({success:false,error:'No ZIP code found for this address.'}));
              }
              const cleanZip = rawZip.split('-')[0].trim().padStart(5,'0');
              if (taxMap.has(cleanZip)) {
                res.writeHead(200, {'Content-Type':'application/json'});
                res.end(JSON.stringify({success:true, matchedAddress:results[0].display_name, zipCode:cleanZip, taxDetails:taxMap.get(cleanZip)}));
              } else {
                res.writeHead(200, {'Content-Type':'application/json'});
                res.end(JSON.stringify({success:false, zipCode:cleanZip, error:`ZIP ${cleanZip} not in tax dataset.`}));
              }
            } catch { res.writeHead(500, {'Content-Type':'application/json'}); res.end(JSON.stringify({success:false,error:'Parse error.'})); }
          });
        }).on('error', () => { res.writeHead(500, {'Content-Type':'application/json'}); res.end(JSON.stringify({success:false,error:'Address lookup failed.'})); });
      } catch { res.writeHead(400, {'Content-Type':'application/json'}); res.end(JSON.stringify({success:false,error:'Invalid payload.'})); }
    });
    return;
  }
 
  // ── ENDPOINT 4b: Address Validation (Census + Nominatim fallback) ──────────
  if (req.url === '/api/validate-address' && req.method === 'POST') {
    readBody(req, res, body => {
      try {
        const { street, zip } = JSON.parse(body);
        if (!street || !zip) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Street and ZIP are required.' }));
        }

        function tryNominatim(street, zip, res) {
          const query = encodeURIComponent(`${street}, ${zip}, USA`);
          const osmUrl = `https://nominatim.openstreetmap.org/search?q=${query}&format=json&addressdetails=1&limit=1&countrycodes=us`;
          https.get(osmUrl, { headers: { 'User-Agent': process.env.APP_USER_AGENT || 'NorthCountryShop/1.0' } }, osmRes => {
            let data = '';
            osmRes.on('data', c => { data += c; });
            osmRes.on('end', () => {
              try {
                const results = JSON.parse(data);
                if (!results.length || !results[0].address) {
                  res.writeHead(200, { 'Content-Type': 'application/json' });
                  return res.end(JSON.stringify({ success: false, error: 'Address not found. Please check your street address and ZIP code.' }));
                }
                const addr = results[0].address;
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                  success: true,
                  matchedAddress: results[0].display_name,
                  city: addr.city || addr.town || addr.village || addr.county || '',
                  state: addr.state || '',
                  zip: addr.postcode ? addr.postcode.split('-')[0] : zip
                }));
              } catch {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Address validation failed.' }));
              }
            });
          }).on('error', () => {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Address validation service unavailable.' }));
          });
        }

        const params = new URLSearchParams({
          street: street.trim(),
          zip: zip.trim(),
          benchmark: 'Public_AR_Current',
          format: 'json'
        });
        const censusUrl = `https://geocoding.geo.census.gov/geocoder/locations/address?${params}`;
        https.get(censusUrl, { headers: { 'User-Agent': 'NorthCountryShop/1.0' } }, censusRes => {
          let data = '';
          censusRes.on('data', c => { data += c; });
          censusRes.on('end', () => {
            try {
              const result = JSON.parse(data);
              const matches = result?.result?.addressMatches;
              if (!matches || matches.length === 0) {
                // Fallback to Nominatim
                return tryNominatim(street, zip, res);
              }
              const match = matches[0];
              const components = match.addressComponents;
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                success: true,
                matchedAddress: match.matchedAddress,
                city: components.city,
                state: components.state,
                zip: components.zip
              }));
            } catch {
              tryNominatim(street, zip, res);
            }
          });
        }).on('error', () => {
          tryNominatim(street, zip, res);
        });
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid request.' }));
      }
    });
    return;
  }

  // ── ENDPOINT 5a: Stripe Config ───────────────────────────────────────────
  if (req.url === '/api/stripe-config' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY }));
  }

  // ── ENDPOINT 5b: Create Payment Intent ──────────────────────────────────
  if (req.url === '/api/create-payment-intent' && req.method === 'POST') {
    readBody(req, res, async body => {
      try {
        const { totalPrice } = JSON.parse(body);
        const amount = Math.round(parseFloat(totalPrice) * 100);
        if (!amount || amount <= 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Invalid amount.' }));
        }
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: 'usd',
          automatic_payment_methods: { enabled: true },
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ clientSecret: paymentIntent.client_secret }));
      } catch (err) {
        console.error('Stripe error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payment intent creation failed.' }));
      }
    });
    return;
  }

  // ── ENDPOINT 5: Place Order ───────────────────────────────────────────
  if (req.url === '/api/place-order' && req.method === 'POST') {
    readBody(req, res, body => {
      try {
        const { userId, totalPrice } = JSON.parse(body);
 
        const price = parseFloat(totalPrice);
        if (!totalPrice || isNaN(price) || price <= 0) {
          res.writeHead(400, {'Content-Type':'application/json'});
          return res.end(JSON.stringify({success:false, error:'Invalid or missing totalPrice.'}));
        }
 
        const safeUserId = (userId && Number.isInteger(Number(userId))) ? Number(userId) : null;
 
        db.execute(
          'INSERT INTO orders (user_id, total_price, status, created_at) VALUES (?, ?, ?, NOW())',
          [safeUserId, price, 'completed'],
          (err, result) => {
            if (err) {
              console.error('❌ Order DB error:', err);
              res.writeHead(500, {'Content-Type':'application/json'});
              return res.end(JSON.stringify({success:false, error:'Database error saving order.'}));
            }
            const label = safeUserId ? `User #${safeUserId}` : 'Guest';
            console.log(`🛒 Order #${result.insertId} — ${label} — $${price.toFixed(2)}`);
            res.writeHead(200, {'Content-Type':'application/json'});
            res.end(JSON.stringify({success:true, message:'Order placed!', orderId:result.insertId}));
          }
        );
      } catch (err) {
        console.error('❌ place-order error:', err);
        res.writeHead(400, {'Content-Type':'application/json'});
        res.end(JSON.stringify({success:false, error:'Malformed JSON payload.'}));
      }
    });
    return;
  }
 
  // ── ENDPOINT 6: Static File Server ───────────────────────────────────
  // SECURITY: prevent path traversal by confirming resolved path stays inside __dirname
  const STATIC_ROOT = path.resolve(__dirname);
  const requestedFile = req.url === '/' ? 'index.html' : req.url.split('?')[0];
  const filePath = path.resolve(path.join(STATIC_ROOT, requestedFile));
 
  if (!filePath.startsWith(STATIC_ROOT + path.sep) && filePath !== STATIC_ROOT) {
    res.writeHead(403, {'Content-Type':'text/html'});
    return res.end('<h1>403 Forbidden</h1>');
  }
 
  const mimeTypes = {
    '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
    '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg'
  };
  const contentType = mimeTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') { res.writeHead(404, {'Content-Type':'text/html'}); res.end('<h1>404 Not Found</h1>'); }
      else { res.writeHead(500); res.end(`Server Error: ${err.code}`); }
    } else {
      res.writeHead(200, {'Content-Type': contentType});
      res.end(content, 'utf-8');
    }
  });
 
});
 
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🔒 Server running at https://localhost:${PORT}`);
});