# North Country Herbal Supplements

A small Node.js storefront with MySQL accounts, a browser cart, ZIP-based tax calculation, and Stripe PaymentIntents. The existing static design is served by a deliberately narrow allowlist in `server.js`.

## Security model

- Passwords are hashed with Argon2id and authentication is represented by an opaque, expiring `HttpOnly`, `Secure`, `SameSite=Strict` session cookie. User identity is never stored in `localStorage`.
- Product prices are integer cents in the server catalog. Both payment creation and order completion recalculate totals from catalog item names and the server tax dataset.
- An order is completed only after Stripe reports its PaymentIntent as `succeeded`, with the expected USD amount and cart hash. A process-local replay guard prevents immediate duplicate fulfillment.
- Authentication and payment routes are rate limited, request bodies are capped, proxy IP headers are distrusted by default, and all responses receive CSP, HSTS, clickjacking, MIME-sniffing, referrer, opener, and permissions protections.
- Static serving exposes only the four HTML pages and stylesheet. Secrets, user exports, archives, source, tax data, certificates, and dotfiles cannot be downloaded.

The included session, limiter, and replay stores are in memory and are appropriate for a single process. For multiple instances or durable fulfillment, move these to Redis/a database and add a unique database constraint for the Stripe PaymentIntent ID. Stripe webhooks are also recommended as the durable fulfillment source.

## Requirements

- Node.js 20 or newer
- MySQL with `users` and `orders` tables
- A Stripe account and API keys
- A TLS certificate for production

The server expects `users(id, name, email, password_hash)` (with a unique email) and `orders(id, user_id, total_price, status, created_at)`. Grant the application database user only the required `SELECT` and `INSERT` permissions.

## Setup

```bash
git clone https://github.com/tcseledy/North-Country-Herbal-Supplements.git
cd North-Country-Herbal-Supplements
npm ci
cp .env.example .env
# Fill in .env, then provide server.key and server.crt.
npm start
```

When certificate files are present the application listens with TLS 1.2 or newer. Without them it uses HTTP for local development, but secure authentication cookies require HTTPS. Terminate TLS at a trusted reverse proxy in production if certificates are not loaded by Node directly; set `TRUST_PROXY=1` only when clients cannot bypass that proxy.

Visit `https://localhost:8080/home.html`. Cart and unfinished form data remain browser-local for convenience, but neither is trusted by checkout APIs.

## Configuration

See `.env.example`. Never use the example values in production or commit `.env`, certificates, customer exports, database dumps, or source archives.

## Checks

```bash
npm test
```

This command checks the JavaScript syntax of `server.js`; it does not run database, browser, or payment integration tests.

Before deployment, use Stripe test mode to exercise successful, declined, and interrupted payments and verify your MySQL schema and least-privilege grants.

## Project structure

| Path | Purpose |
| --- | --- |
| `home.html` | Storefront landing page |
| `index.html` | Product catalog, cart, and checkout |
| `login.html`, `signup.html` | Account forms |
| `styles.css` | Shared page styles |
| `server.js` | HTTP/HTTPS server, authentication, tax, and payment APIs |
| `TAXRATES_ZIP5_*.csv` | ZIP-based tax datasets used by the server |
| `.env.example` | Configuration template with placeholder values |
| `package.json`, `package-lock.json` | Node.js commands and dependencies |
