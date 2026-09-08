const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2');
const argon2 = require('argon2');
const crypto = require('crypto');

// ENVIRONMENT VARIABLES

const envPath = path.join(__dirname, '.env');

if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf-8') .split('\n')
    .forEach(line => {
      const idx = line.indexOf('=');

      if (idx === -1) return;

      const key = line.substring(0, idx).trim();
      const val = line .substring(idx + 1) .trim() .replace(/['"\r]/g, '');

      if (key && !key.startsWith('#') && process.env[key] === undefined) {
        process.env[key] = val;
      }
    });

  console.log('🔑 Environment Config Loaded.');
}

// SSL / TLS

const sslKeyPath = path.join( __dirname, process.env.SSL_KEY_FILE || 'server.key' );

const sslCertPath = path.join( __dirname, process.env.SSL_CERT_FILE || 'server.crt' );

const options = {
  key: fs.readFileSync(sslKeyPath), cert: fs.readFileSync(sslCertPath),

  // SECURITY: TLS 1.2 or newer only
  minVersion: 'TLSv1.2'
};

// MYSQL

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER || 'root', password:
    process.env.DB_PASSWORD || process.env.DB_PASS || '', database: process.env.DB_NAME ||
    'north_country_shop',

  waitForConnections: true, connectionLimit: 10, queueLimit: 0
});

// RATE LIMITING

const rateLimitStore = new Map();

const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX = 20;

function checkRateLimit(ip) {
  const now = Date.now();

  const entry =
    rateLimitStore.get(ip) || {
      count: 0, windowStart: now
    };

  if (now - entry.windowStart > RATE_WINDOW_MS) {
    rateLimitStore.set(ip, {
      count: 1, windowStart: now
    });

    return false;
  }

  entry.count++;

  rateLimitStore.set(ip, entry);

  return entry.count > RATE_MAX;
}

setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;

  for (const [ip, entry] of rateLimitStore) {
    if (entry.windowStart < cutoff) {
      rateLimitStore.delete(ip);
    }
  }
}, 30 * 60 * 1000);

// REQUEST BODY SIZE LIMIT

const MAX_BODY_BYTES = 64 * 1024;

function readBody(req, res, cb) {
  let body = '';
  let bytes = 0;
  let ended = false;

  req.on('data', chunk => {
    if (ended) return;

    bytes += chunk.length;

    if (bytes > MAX_BODY_BYTES) {
      ended = true;

      res.writeHead(413, {
        'Content-Type': 'application/json'
      });

      res.end(
        JSON.stringify({
          success: false, error: 'Request too large.'
        })
      );

      req.resume();

      return;
    }

    body += chunk.toString();
  });

  req.on('end', () => {
    if (!ended) {
      cb(body);
    }
  });
}

// SECURITY HEADERS

function setSecurityHeaders(res) {
  res.setHeader( 'Strict-Transport-Security', 'max-age=63072000; includeSubDomains'
  );

  res.setHeader( 'X-Content-Type-Options', 'nosniff' );

  res.setHeader( 'X-Frame-Options', 'DENY' );

  res.setHeader( 'Referrer-Policy', 'strict-origin-when-cross-origin' );

  res.setHeader( 'Permissions-Policy', 'camera=(), microphone=(), geolocation=(self)' );
}

// TAX DATA

const taxMap = new Map();

function loadTaxData() {
  try {
    const taxFiles = fs .readdirSync(__dirname) .filter( file => file.startsWith('TAXRATES_ZIP5_') &&
          file.endsWith('.csv') );

    if (!taxFiles.length) {
      console.log( '⚠️ No TAXRATES_ZIP5_*.csv files found.' );

      return;
    }

    console.log(
      `📂 Found ${taxFiles.length} tax file(s). Loading...`
    );

    for (const filename of taxFiles) {
      const filePath = path.join( __dirname, filename );

      const lines = fs .readFileSync(filePath, 'utf-8') .split('\n');

      if (lines.length < 2) {
        continue;
      }

      const headers = lines[0].replace(/^\uFEFF/, '').trim().split(',').map(value => value.trim());

      const zipIdx = headers.indexOf('ZipCode');

      const stateIdx = headers.indexOf('State');

      const regionIdx = headers.indexOf('TaxRegionName');

      const combinedIdx = headers.indexOf( 'EstimatedCombinedRate' );

      if ( [ zipIdx, stateIdx, regionIdx, combinedIdx ].includes(-1)
      ) {
        console.log(
          `❌ Skipping ${filename}: header mismatch.`
        );

        continue;
      }

      for ( let i = 1;
        i < lines.length;
        i++
      ) {
        const cols = lines[i].trim().split(',');

        if ( cols.length <= Math.max( zipIdx, stateIdx, regionIdx, combinedIdx )
        ) {
          continue;
        }

        const zipCode = cols[zipIdx] .trim() .padStart(5, '0');

        taxMap.set(zipCode, {
          state: cols[stateIdx].trim(),

          region: cols[regionIdx].trim(),

          combinedRate: parseFloat( cols[combinedIdx] ) || 0
        });
      }
    }

    console.log(
      `📊 Tax map ready: ${taxMap.size} ZIP codes indexed.`
    );
  } catch (err) {
    console.error( '❌ Tax map build error:', err.message );
  }
}

loadTaxData();

// SERVER-SIDE SESSIONS

// IMPORTANT:
// This Map MUST be outside createServer().
// Otherwise every request would get a new session store.

const sessions = new Map();

const SESSION_MAX_AGE = 60 * 60 * 2; // 2 hours

function createSession(userId) {
  const sessionId = crypto .randomBytes(32) .toString('hex');

  sessions.set(sessionId, {
    userId, expiresAt: Date.now() + SESSION_MAX_AGE * 1000
  });

  return sessionId;
}

function getSessionId(req) {
  const cookieHeader = req.headers.cookie || '';

  const parts = cookieHeader.split(';');

  for (const part of parts) {
    const [ name, ...valueParts ] = part.trim().split('=');

    if (name === 'session_id') {
      try {
        return decodeURIComponent( valueParts.join('=') );
      } catch {
        return null;
      }
    }
  }

  return null;
}

function getSession(req) {
  const sessionId = getSessionId(req);

  if (!sessionId) {
    return null;
  }

  const session = sessions.get(sessionId);

  if (!session) {
    return null;
  }

  if ( Date.now() > session.expiresAt
  ) {
    sessions.delete(sessionId);

    return null;
  }

  return session;
}

function setSessionCookie( res, sessionId
) {
  res.setHeader( 'Set-Cookie',

    `session_id=${encodeURIComponent(
      sessionId
    )}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE}`
  );
}

function clearSessionCookie(res) {
  res.setHeader( 'Set-Cookie',

    'session_id=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
  );
}

// Delete expired sessions every 30 minutes

setInterval(() => {
  const now = Date.now();

  for ( const [ sessionId, session ] of sessions
  ) {
    if ( now > session.expiresAt
    ) {
      sessions.delete( sessionId );
    }
  }
}, 30 * 60 * 1000);

// PRODUCT CATALOG

// SECURITY:
// Browser prices are NEVER trusted.
// All real prices live here.

const PRODUCT_PRICES = {
  'Organic Ashwagandha': 100, "Lion's Mane Extract": 100, 'Herbal Sleep Tea Blend': 100,
  'Raw Local Propolis': 100
};

// STRIPE

const stripe = require('stripe')( process.env.STRIPE_SECRET_KEY );

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function json(res, status, data) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function text(value, label, max = 120) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) fail(400, `Invalid ${label}.`);
  return value.trim();
}
function email(value) {
  const result = text(value, 'email', 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result)) fail(400, 'Invalid email.');
  return result;
}
function zip(value) {
  if (typeof value !== 'string' || !/^\d{5}(-\d{4})?$/.test(value.trim())) fail(400, 'Invalid ZIP code.');
  return value.trim().slice(0, 5);
}
function cookie(req, name) {
  const part = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return part ? part.slice(name.length + 1) : '';
}
function setCookie(res, name, value, age = SESSION_MAX_AGE) {
  res.setHeader('Set-Cookie', `${name}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`);
}
function guestToken(req, res) {
  let token = cookie(req, 'checkout_id');
  if (!/^[a-f0-9]{64}$/.test(token)) token = crypto.randomBytes(32).toString('hex');
  setCookie(res, 'checkout_id', token, 86400);
  return token;
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

const prices = PRODUCT_PRICES;
async function createPayment(req, res, body) {
  if (!Array.isArray(body.items) || !body.items.length || body.items.length > 100) fail(400, 'Cart must contain 1–100 items.');
  let subtotal = 0;
  for (const item of body.items) {
    if (!item || typeof item.name !== 'string' || !Object.hasOwn(prices, item.name)) fail(400, 'Invalid product.');
    subtotal += prices[item.name];
  }
  const code = zip(body.zipCode);
  const taxDetails = taxMap.get(code);
  if (!taxDetails) fail(400, 'ZIP code is not available in the tax dataset.');
  const customer = body.customer || {};
  const contact = { name: text(customer.name, 'name'), email: email(customer.email),
    street: text(customer.street, 'street', 200), city: text(customer.city, 'city'), state: text(customer.state, 'state') };
  const user = getSession(req);
  if (!user) {
    const [columns] = await db.promise().execute(
      "SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'user_id'"
    );
    if (columns[0]?.IS_NULLABLE !== 'YES') {
      fail(503, 'Guest checkout is unavailable because this database requires an account for orders. Please sign in.');
    }
  }
  // A guest must possess this HttpOnly cookie to finalize their own payment.
  const owner = user ? { userId: String(user.userId) } : { guestHash: tokenHash(guestToken(req, res)) };
  const tax = Math.round(subtotal * taxDetails.combinedRate);
  const payment = await stripe.paymentIntents.create({
    amount: subtotal + tax, currency: 'usd', payment_method_types: ['card'], receipt_email: contact.email,
    shipping: { name: contact.name, address: { line1: contact.street, city: contact.city,
      state: contact.state, postal_code: code, country: 'US' } },
    metadata: { ...owner, app: 'north-country-demo', subtotal: String(subtotal), tax: String(tax) }
  });
  return { success: true, clientSecret: payment.client_secret, subtotal: subtotal / 100, tax: tax / 100, total: (subtotal + tax) / 100 };
}
async function placeOrder(req, body) {
  if (typeof body.paymentIntentId !== 'string' || !/^pi_[A-Za-z0-9]+$/.test(body.paymentIntentId)) fail(400, 'Invalid payment confirmation.');
  const payment = await stripe.paymentIntents.retrieve(body.paymentIntentId);
  const meta = payment.metadata || {};
  const user = getSession(req);
  const token = cookie(req, 'checkout_id');
  const ownsPayment = meta.userId ? user && String(user.userId) === meta.userId
    : /^[a-f0-9]{64}$/.test(token) && meta.guestHash === tokenHash(token);
  if (meta.app !== 'north-country-demo' || !ownsPayment) fail(403, 'Payment does not belong to this checkout.');
  if (payment.status !== 'succeeded' || payment.currency !== 'usd' ||
      !Number.isInteger(payment.amount_received) || payment.amount_received <= 0 || payment.amount_received !== payment.amount) {
    fail(400, 'Payment has not succeeded for the full amount.');
  }
  // Guest orders have NULL user_id; never create a fake registered account.
  const userId = meta.userId ? user.userId : null;
  try {
    const [result] = await db.promise().execute(
      'INSERT INTO orders (user_id, total_price, status, stripe_payment_intent_id, created_at) VALUES (?, ?, ?, ?, NOW())',
      [userId, payment.amount_received / 100, 'completed', payment.id]);
    return { success: true, orderId: result.insertId };
  } catch (error) {
    if (error.code !== 'ER_DUP_ENTRY') throw error;
    const [rows] = await db.promise().execute('SELECT id FROM orders WHERE stripe_payment_intent_id = ? AND user_id <=> ?', [payment.id, userId]);
    if (!rows.length) throw error;
    return { success: true, orderId: rows[0].id };
  }
}

// HTTPS SERVER

const server = https.createServer( options,
    (req, res) => {

      setSecurityHeaders(res);

      const requestPath = req.url.split('?')[0];

      const clientIp = ( req.socket.remoteAddress || '' ).replace( '::ffff:', '' );

      // SIGN UP

      if ( requestPath === '/api/signup' && req.method === 'POST'
      ) {
        if ( checkRateLimit( clientIp )
        ) {
          res.writeHead( 429,
            {
              'Content-Type': 'application/json'
            }
          );

          return res.end(
            JSON.stringify({
              success: false, message: 'Too many requests. Try again later.'
            })
          );
        }

        readBody( req, res,
          async body => {
            try {
              const {
                name, email, password
              } =
                JSON.parse(body);

              if ( !name || typeof name !== 'string' || name.trim().length < 1 || name.length > 120
              ) {
                res.writeHead( 400,
                  {
                    'Content-Type': 'application/json'
                  }
                );

                return res.end(
                  JSON.stringify({
                    success: false, message: 'Invalid name.'
                  })
                );
              }

              if ( !email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test( email.trim()
                ) || email.length > 254
              ) {
                res.writeHead( 400,
                  {
                    'Content-Type': 'application/json'
                  }
                );

                return res.end(
                  JSON.stringify({
                    success: false, message: 'Invalid email address.'
                  })
                );
              }

              if ( !password || typeof password !== 'string' || password.length < 12 || password.length > 128
              ) {
                res.writeHead( 400,
                  {
                    'Content-Type': 'application/json'
                  }
                );

                return res.end(
                  JSON.stringify({
                    success: false, message: 'Password must be 12–128 characters.'
                  })
                );
              }

              const cleanName = name.trim();

              const cleanEmail = email .trim() .toLowerCase();

              const passwordHash = await argon2.hash( password,
                  {
                    type: argon2.argon2id
                  }
                );

              db.execute( `SELECT id FROM users WHERE email = ?`,

                [cleanEmail],

                ( err, results
                ) => {
                  if (err) {
                    console.error( 'Signup DB error:', err.message );

                    res.writeHead( 500,
                      {
                        'Content-Type': 'application/json'
                      }
                    );

                    return res.end(
                      JSON.stringify({
                        success: false, message: 'Database error.'
                      })
                    );
                  }

                  if ( results.length > 0
                  ) {
                    res.writeHead( 400,
                      {
                        'Content-Type': 'application/json'
                      }
                    );

                    return res.end(
                      JSON.stringify({
                        success: false, message: 'Email already registered!'
                      })
                    );
                  }

                  db.execute( `INSERT INTO users ( name, email, password_hash ) VALUES (?, ?, ?)`,

                    [ cleanName, cleanEmail, passwordHash ],

                    ( insertErr
                    ) => {
                      if ( insertErr
                      ) {
                        console.error( 'Signup insert error:', insertErr.message );

                        res.writeHead( 500,
                          {
                            'Content-Type': 'application/json'
                          }
                        );

                        return res.end( JSON.stringify(
                            {
                              success: false, message: 'Could not create account.'
                            }
                          ) );
                      }

                      console.log(
                        `👤 Registered: ${cleanName} (${cleanEmail})`
                      );

                      res.writeHead( 200,
                        {
                          'Content-Type': 'application/json'
                        }
                      );

                      res.end(
                        JSON.stringify({
                          success: true, message: 'Account created!'
                        })
                      );
                    }
                  );
                }
              );
            } catch (
              err
            ) {
              console.error( 'Signup error:', err.message );

              res.writeHead( 400,
                {
                  'Content-Type': 'application/json'
                }
              );

              res.end(
                JSON.stringify({
                  success: false, message: 'Invalid signup request.'
                })
              );
            }
          }
        );

        return;
      }

      // LOGIN

      if ( requestPath === '/api/login' && req.method === 'POST'
      ) {
        if ( checkRateLimit( clientIp )
        ) {
          res.writeHead( 429,
            {
              'Content-Type': 'application/json'
            }
          );

          return res.end(
            JSON.stringify({
              success: false, message: 'Too many requests. Try again later.'
            })
          );
        }

        readBody( req, res,
          body => {
            try {
              const {
                email: rawEmail, password
              } =
                JSON.parse(body);

              const email = String( rawEmail || '' ) .trim() .toLowerCase();

              if ( !email || typeof password !== 'string'
              ) {
                res.writeHead( 400,
                  {
                    'Content-Type': 'application/json'
                  }
                );

                return res.end(
                  JSON.stringify({
                    success: false, message: 'Email and password are required.'
                  })
                );
              }

              db.execute( `SELECT id, name, email, password_hash FROM users WHERE email = ?`,

                [email],

                async ( err, results
                ) => {
                  if (err) {
                    console.error( 'Login DB error:', err.message );

                    res.writeHead( 500,
                      {
                        'Content-Type': 'application/json'
                      }
                    );

                    return res.end(
                      JSON.stringify({
                        success: false, message: 'Database error.'
                      })
                    );
                  }

                  let match = false;

                  if ( results.length
                  ) {
                    try {
                      match = await argon2.verify( results[0] .password_hash, password );
                    } catch {
                      match = false;
                    }
                  }

                  if ( !results.length || !match
                  ) {
                    res.writeHead( 401,
                      {
                        'Content-Type': 'application/json'
                      }
                    );

                    return res.end(
                      JSON.stringify({
                        success: false, message: 'Invalid email or password!'
                      })
                    );
                  }

                  const user = results[0];

                  // SECURITY:
                  // Create server-side
                  // authentication session.

                  const sessionId = createSession( user.id );

                  setSessionCookie( res, sessionId );

                  console.log(
                    `🔒 Login: ${user.name} (id=${user.id})`
                  );

                  res.writeHead( 200,
                    {
                      'Content-Type': 'application/json'
                    }
                  );

                  res.end(
                    JSON.stringify({
                      success: true,

                      message: 'Authenticated!',

                      user: {
                        name: user.name,

                        email: user.email
                      }
                    })
                  );
                }
              );
            } catch (
              err
            ) {
              res.writeHead( 400,
                {
                  'Content-Type': 'application/json'
                }
              );

              res.end(
                JSON.stringify({
                  success: false, message: 'Invalid login request.'
                })
              );
            }
          }
        );

        return;
      }

      // LOGOUT

      if ( requestPath === '/api/logout' && req.method === 'POST'
      ) {
        const sessionId = getSessionId(req);

        if (sessionId) {
          sessions.delete( sessionId );
        }

        clearSessionCookie( res );

        res.writeHead( 200,
          {
            'Content-Type': 'application/json'
          }
        );

        return res.end(
          JSON.stringify({
            success: true
          })
        );
      }

      // IP GEOLOCATION

      if ( requestPath === '/api/location' && req.method === 'GET'
      ) {
        const apiKey = process.env.geoapi;

        let cleanIp = ( req.socket .remoteAddress || '' ) .replace( '::ffff:', '' ) .trim();

        if ( [ '127.0.0.1', '::1', 'localhost' ].includes(cleanIp)
        ) {
          cleanIp = process.env .DEV_FALLBACK_IP || '127.0.0.1';
        }

        if (!apiKey) {
          res.writeHead( 500,
            {
              'Content-Type': 'application/json'
            }
          );

          return res.end(
            JSON.stringify({
              error: 'Geolocation API key is not configured.'
            })
          );
        }

        const geoUrl =
          `https://api.ipgeolocation.io/ipgeo?apiKey=${encodeURIComponent(
            apiKey
          )}&ip=${encodeURIComponent(
            cleanIp
          )}`;

        https .get( geoUrl,
            geoRes => {
              let data = '';

              geoRes.on( 'data',
                chunk => {
                  data += chunk;
                }
              );

              geoRes.on( 'end',
                () => {
                  try {
                    const parsed = JSON.parse( data );

                    if ( parsed.message
                    ) {
                      res.writeHead( 400,
                        {
                          'Content-Type': 'application/json'
                        }
                      );

                      return res.end(
                        JSON.stringify({
                          error: parsed.message
                        })
                      );
                    }

                    res.writeHead( 200,
                      {
                        'Content-Type': 'application/json'
                      }
                    );

                    res.end(
                      JSON.stringify({
                        city: parsed.city,

                        region_code: parsed .state_code ? parsed.state_code.replace( 'US-', '' ) : parsed
                                .state_prov,

                        country_code: parsed .country_code2
                      })
                    );
                  } catch {
                    res.writeHead( 500,
                      {
                        'Content-Type': 'application/json'
                      }
                    );

                    res.end(
                      JSON.stringify({
                        error: 'Geolocation response error.'
                      })
                    );
                  }
                }
              );
            }
          ) .on( 'error',
            () => {
              res.writeHead( 500,
                {
                  'Content-Type': 'application/json'
                }
              );

              res.end(
                JSON.stringify({
                  error: 'Geo request failed.'
                })
              );
            }
          );

        return;
      }

      // TAX LOOKUP

      if ( requestPath === '/api/calculate-tax' && req.method === 'POST'
      ) {
        readBody(req, res, raw => {
          try {
            const body = JSON.parse(raw);
            const code = zip(body.zipCode || body.address);
            const taxDetails = taxMap.get(code);
            if (!taxDetails) fail(400, 'ZIP code is not available in the tax dataset.');
            json(res, 200, { success: true, zipCode: code, taxDetails });
          } catch (error) {
            json(res, error.status || 400, { success: false, error: error.message });
          }
        });
        return;
      }

      // ADDRESS VALIDATION

      if ( requestPath === '/api/validate-address' && req.method === 'POST'
      ) {
        readBody( req, res,
          body => {
            try {
              const {
                street, zip
              } =
                JSON.parse(body);

              if ( !street || !zip
              ) {
                res.writeHead( 400,
                  {
                    'Content-Type': 'application/json'
                  }
                );

                return res.end(
                  JSON.stringify({
                    success: false, error: 'Street and ZIP are required.'
                  })
                );
              }

              function tryNominatim() {
                const query = encodeURIComponent(
                    `${street}, ${zip}, USA`
                  );

                const osmUrl =
                  `https://nominatim.openstreetmap.org/search?q=${query}&format=json&addressdetails=1&limit=1&countrycodes=us`;

                https .get( osmUrl,
                    {
                      headers: {
                        'User-Agent': process.env .APP_USER_AGENT || 'NorthCountryShop/1.0'
                      }
                    },
                    osmRes => {
                      let data = '';

                      osmRes.on( 'data',
                        chunk => {
                          data += chunk;
                        }
                      );

                      osmRes.on( 'end',
                        () => {
                          try {
                            const results = JSON.parse( data );

                            if ( !results.length || !results[0] .address
                            ) {
                              res.writeHead( 200,
                                {
                                  'Content-Type': 'application/json'
                                }
                              );

                              return res.end( JSON.stringify(
                                  {
                                    success: false,

                                    error: 'Address not found. Please check your street address and ZIP code.'
                                  }
                                ) );
                            }

                            const addr = results[0] .address;

                            res.writeHead( 200,
                              {
                                'Content-Type': 'application/json'
                              }
                            );

                            res.end( JSON.stringify(
                                {
                                  success: true,

                                  matchedAddress: results[0] .display_name,

                                  city: addr.city || addr.town || addr.village || addr.county || '',

                                  state: addr.state || '',

                                  zip: addr.postcode ? addr.postcode.split( '-' )[0] : zip
                                }
                              ) );
                          } catch {
                            res.writeHead( 500,
                              {
                                'Content-Type': 'application/json'
                              }
                            );

                            res.end( JSON.stringify(
                                {
                                  success: false,

                                  error: 'Address validation failed.'
                                }
                              ) );
                          }
                        }
                      );
                    }
                  ) .on( 'error',
                    () => {
                      res.writeHead( 500,
                        {
                          'Content-Type': 'application/json'
                        }
                      );

                      res.end( JSON.stringify(
                          {
                            success: false,

                            error: 'Address validation service unavailable.'
                          }
                        ) );
                    }
                  );
              }

              const params = new URLSearchParams(
                  {
                    street: street.trim(),

                    zip: zip.trim(),

                    benchmark: 'Public_AR_Current',

                    format: 'json'
                  }
                );

              const censusUrl =
                `https://geocoding.geo.census.gov/geocoder/locations/address?${params}`;

              https .get( censusUrl,
                  {
                    headers: {
                      'User-Agent': 'NorthCountryShop/1.0'
                    }
                  },
                  censusRes => {
                    let data = '';

                    censusRes.on( 'data',
                      chunk => {
                        data += chunk;
                      }
                    );

                    censusRes.on( 'end',
                      () => {
                        try {
                          const result = JSON.parse( data );

                          const matches = result ?.result ?.addressMatches;

                          if ( !matches || matches.length === 0
                          ) {
                            return tryNominatim();
                          }

                          const match = matches[0];

                          const components = match .addressComponents;

                          res.writeHead( 200,
                            {
                              'Content-Type': 'application/json'
                            }
                          );

                          res.end( JSON.stringify(
                              {
                                success: true,

                                matchedAddress: match .matchedAddress,

                                city: components .city,

                                state: components .state,

                                zip: components .zip
                              }
                            ) );
                        } catch {
                          tryNominatim();
                        }
                      }
                    );
                  }
                ) .on( 'error',
                  () => {
                    tryNominatim();
                  }
                );
            } catch {
              res.writeHead( 400,
                {
                  'Content-Type': 'application/json'
                }
              );

              res.end(
                JSON.stringify({
                  success: false, error: 'Invalid request.'
                })
              );
            }
          }
        );

        return;
      }

      // STRIPE CONFIG

      if ( requestPath === '/api/stripe-config' && req.method === 'GET'
      ) {
        res.writeHead( 200,
          {
            'Content-Type': 'application/json'
          }
        );

        return res.end(
          JSON.stringify({
            publishableKey: process.env .STRIPE_PUBLISHABLE_KEY
          })
        );
      }

      // Payment routes support signed-in customers and guest checkout.
      if (req.method === 'POST' && ['/api/create-payment-intent', '/api/place-order'].includes(requestPath)) {
        readBody(req, res, async raw => {
          try {
            let body;
            try { body = JSON.parse(raw); } catch { fail(400, 'Invalid JSON payload.'); }
            if (!body || typeof body !== 'object' || Array.isArray(body)) fail(400, 'Invalid payload.');
            const result = requestPath === '/api/create-payment-intent'
              ? await createPayment(req, res, body) : await placeOrder(req, body);
            json(res, 200, result);
          } catch (error) {
            console.error('Checkout error:', error.message);
            json(res, error.status || 500, { success: false, error: error.status ? error.message : 'Unable to process checkout.' });
          }
        });
        return;
      }

      // STATIC FILE SERVER

      // SECURITY:
      // Explicit allowlist prevents:
      // /.env
      // /server.js
      // /server.key
      // /server.crt
      // /package.json
      // tax CSVs
      // from being downloaded.

      const PUBLIC_FILES = new Set([ '/', '/home.html', '/index.html', '/login.html', '/signup.html',
          '/styles.css' ]);

      if ( !PUBLIC_FILES.has( requestPath )
      ) {
        res.writeHead( 404,
          {
            'Content-Type': 'text/html; charset=utf-8'
          }
        );

        return res.end( '<h1>404 Not Found</h1>' );
      }

      const requestedFile = requestPath === '/' ? 'home.html' : requestPath.slice( 1 );

      const filePath = path.join( __dirname, requestedFile );

      const mimeTypes = {
        '.html': 'text/html; charset=utf-8',

        '.css': 'text/css; charset=utf-8'
      };

      const contentType = mimeTypes[ path .extname(filePath) .toLowerCase() ] || 'application/octet-stream';

      fs.readFile( filePath, ( err, content
        ) => {
          if (err) {
            res.writeHead( 404,
              {
                'Content-Type': 'text/html; charset=utf-8'
              }
            );

            return res.end( '<h1>404 Not Found</h1>' );
          }

          res.writeHead( 200,
            {
              'Content-Type': contentType
            }
          );

          res.end(content);
        }
      );
    }
  );

// START SERVER

const PORT = process.env.PORT || 8080;

server.listen( PORT,
  () => {
    console.log(
      `🔒 Server running at https://localhost:${PORT}`
    );
  }
);
