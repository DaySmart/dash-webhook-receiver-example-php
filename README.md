# dash-webhook-receiver-example-php

A Laravel 13 reference implementation showing how to correctly receive webhooks from the Dash webhook system.

It demonstrates:

- **OPTIONS validation handshake** — responds with `WebHook-Allowed-Origin` and `WebHook-Allowed-Rate` to authorize the subscription
- **RFC 9421 HTTP Message Signature verification** — hand-rolled, no extra packages; covers Content-Digest, signature base reconstruction, JWK→PEM conversion, and replay-window enforcement. This is deliberate for a reference implementation — see the note below for library alternatives if you're adapting this for production
- **Deduplication** via `WebHook-ID` — retried deliveries aren't re-verified or re-stored; they get the same response as the original delivery
- **Correct HTTP response codes** — `204` on success, `401` on verification failure, `500` lets the sender retry with backoff
- **Live dashboard** — Livewire 4 event feed that auto-refreshes every 3 seconds

## Prerequisites

- [Docker](https://docs.docker.com/get-started/get-docker/) and Docker Compose v2
- [ngrok](https://ngrok.com/download) (or another HTTPS tunnel) — only needed if you're pointing a **real** Dash sender at this app rather than testing locally; see [Pointing the sender at this app](#pointing-the-sender-at-this-app)

## Quick start

```bash
git clone https://github.com/DaySmart/dash-webhook-receiver-example-php
cd dash-webhook-receiver-example-php

cp .env.example .env

# Set your sender's JWKS URL in .env:
# WEBHOOK_SENDER_JWKS_URL=https://api.yoursender.com/.well-known/jwks.json

docker compose up --build
```

The app starts at **http://localhost:8000**.  
Migrations run automatically on first boot.

## Development mode & debugging

`docker-compose.yml` builds the `app` service from the Dockerfile's `dev` target, which installs dev Composer dependencies and enables Xdebug. Step debugging is on by default (`XDEBUG_MODE=debug,develop`); point your IDE's debugger at port `9003` and set a path mapping from the project root to `/var/www/html`.

To disable Xdebug (e.g. for a quick perf check), set in `.env`:

```
XDEBUG_MODE=off
```

The `production` target (used for the [published image](#using-the-published-docker-image)) skips Xdebug and dev dependencies entirely.

## Using the published Docker image

Every published [release](https://github.com/DaySmart/dash-webhook-receiver-example-php/releases) builds and pushes an image to GitHub Container Registry, so you don't have to build it yourself:

```
ghcr.io/daysmart/dash-webhook-receiver-example-php
```

Available tags:

| Tag                   | Meaning                                      |
|-----------------------|----------------------------------------------|
| `latest`              | Most recent non-prerelease release           |
| `vMAJOR.MINOR.PATCH`  | An exact release, e.g. `v1.2.3`              |
| `vMAJOR.MINOR`        | Latest patch within that minor version       |
| `vMAJOR`              | Latest minor/patch within that major version |

The image only contains PHP-FPM (listening on port `9000`, not HTTP) — it needs a web server in front of it that proxies `.php` requests over FastCGI, and a MySQL database. The simplest way to run it is to reuse the same [`docker-compose.yml`](docker-compose.yml) setup from the quick start, swapping the `app` service's `build:` block for the published image (it's built from the `production` target, so no dev dependencies or Xdebug):

```yaml
services:
  app:
    image: ghcr.io/daysmart/dash-webhook-receiver-example-php:latest
    # ...rest of the app service unchanged (volumes, env_file, depends_on, restart)
    # drop `environment: XDEBUG_MODE` and `extra_hosts` — not used by this image
```

Then run `docker compose up` (no `--build` needed) from a checkout that still has `.env` and `docker/nginx.conf` in place, since the `web` and `app` services mount those from the host.

The image is built with a [`.dockerignore`](.dockerignore) that excludes `.git`, `.env*`, tests, and CI/editor config from the build context, so building locally with a real `.env` present won't bake `APP_KEY`, `WEBHOOK_SECRET`, or anything else in it into the image. The entrypoint also runs whatever command the image is given (`docker run ghcr.io/daysmart/dash-webhook-receiver-example-php php artisan migrate:status`, for example) rather than always launching `php-fpm`.

## Pointing the sender at this app

Dash requires subscription URLs to be `https://` in real (non-local) environments, so a bare `http://localhost:8000/webhooks` only works if the sender and this app are on the same machine. To receive a real staging webhook from a sender you don't control, tunnel the app to a public HTTPS URL with ngrok:

1. Start the app: `docker compose up --build` (it's listening on `http://localhost:8000`)
2. In a separate terminal, tunnel port `8000`: `ngrok http 8000`
3. ngrok prints a forwarding URL like `https://abcd1234.ngrok-free.app` — this is public and HTTPS. Nothing on the app side needs to change to accept it: nginx isn't restricted to a specific `server_name` (`docker/nginx.conf`), and signature verification derives `@authority` from whatever `Host` header the request actually arrives with (`WEBHOOK_SENDER_ORIGIN` in `.env` only checks the sender's `WebHook-Request-Origin` header, not your tunnel's hostname)
4. Create the webhook subscription on the sender with `url: https://abcd1234.ngrok-free.app/webhooks` (use your own forwarding URL, and keep the trailing `/webhooks`)
5. The sender performs an OPTIONS handshake — this app responds with `200 OK` and the `WebHook-Allowed-Origin` / `WebHook-Allowed-Rate` headers
6. Once validated, the sender will POST CloudEvents v1.0 payloads through the tunnel to `/webhooks`
7. Verified events appear in the dashboard at `http://localhost:8000` within 3 seconds

ngrok's free tier reissues a new random URL every time you restart it, so you'll need to update the sender's subscription URL each session — a paid plan's static domain avoids that if you're doing this repeatedly.

## Configuration

All settings live in `.env` (copied from `.env.example`):

| Variable                   | Default       | Description                                                                                                                                                                      |
|----------------------------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `WEBHOOK_SENDER_JWKS_URL`  | *(required)*  | URL of the sender's JWKS endpoint                                                                                                                                                |
| `WEBHOOK_SENDER_ORIGIN`    | `*`           | Expected `WebHook-Request-Origin` **hostname** (e.g. `api.example.com`, not a URL). A handshake requesting a different origin is refused. `*` accepts and echoes back any origin |
| `WEBHOOK_ALLOWED_RATE`     | `1000`        | Requests/minute advertised in handshake                                                                                                                                          |
| `WEBHOOK_REPLAY_WINDOW`    | `300`         | Acceptable clock skew in seconds for the `created` parameter                                                                                                                     |
| `WEBHOOK_SECRET`           | *(optional)*  | Bearer secret for secondary authenticity check                                                                                                                                   |
| `WEBHOOK_JWKS_CACHE_TTL`   | `3600`        | Seconds to cache the sender's JWKS. An unrecognised `keyid` triggers one uncached refetch before being rejected, so rotation isn't blocked on this expiring                      |

## How verification works

Each incoming POST goes through `VerifyWebhookSignature` middleware before the controller runs:

1. **Content-Digest** — SHA-256 the raw body, compare to the `Content-Digest: sha-256=:<base64>:` header (RFC 9530)
2. **Parse `Signature-Input`** — extract the covered component list, `keyid`, `alg`, and `created`
3. **Replay window** — assert `|now - created| ≤ WEBHOOK_REPLAY_WINDOW` seconds, and reject a past `expires` if the sender sent one (Dash doesn't today, but RFC 9421 defines it)
4. **JWKS fetch** — GET `WEBHOOK_SENDER_JWKS_URL`, find a matching, `"use": "sig"` key by `kid` (response cached; a key marked `"use": "enc"` is never accepted for verification). A `kid` missing from the cached JWKS triggers one uncached refetch before being treated as unknown, so key rotation doesn't wait out the cache TTL. A fetch that fails outright (non-2xx, timeout, malformed response) is **not** treated as a bad signature — it propagates as a `500` so the sender retries instead of abandoning the delivery over what's usually a transient outage. The signature's declared `alg` is then cross-checked against the resolved key's type/curve — `openssl_verify()` otherwise infers RSA vs. ECDSA from the key alone and would accept a mismatched `alg`
5. **Signature base** — reconstruct `"component": value\n` lines + `"@signature-params": …\n` (RFC 9421 §2.5). `@authority` is the lowercased `Host` header with the port appended unless it's `443`, and `@query` is the *raw, unsorted* query string (`Request::getQueryString()` alphabetically re-sorts it, which would break verification against Dash's `parse_url`-order signature). A component that isn't a derived (`@…`) value and isn't present as a request header is a hard failure per RFC 9421, not an empty string — this is what lets a newly-covered header work correctly without any code change here
6. **Verify** — RSA and EC (P-256/P-384) keys via `openssl_verify()` (hand-rolled JWK→PEM via ASN.1 DER); OKP (Ed25519) keys via `sodium_crypto_sign_verify_detached()` against the raw JWK key bytes, since EdDSA signs the message directly rather than a pre-hashed digest
7. **Bearer secret** — optional constant-time comparison of `Authorization: Bearer <secret>`

A genuine verification failure returns `401 Unauthorized` with a generic `{"error": "Webhook verification failed"}` body — the specific reason (bad digest, unknown key, stale timestamp, etc.) is logged server-side, not exposed in the response — and the sender marks the delivery `Abandoned` (no retry for 4xx). The delivery is still persisted with `signature_verified = false` so failed attempts stay visible in the dashboard instead of vanishing on rejection.

Retries reuse the sender's `WebHook-ID`. Whatever outcome was stored for the **first** delivery with that ID is authoritative for every retry after it — a retry is never independently re-verified, even if this particular attempt would have verified differently than the original.

> **Note:** The JWK↔PEM conversion and raw↔DER ECDSA signature encoding here are hand-rolled intentionally, to show what RFC 9421 verification actually does at the byte level. In production code you don't have to write this yourself — [`web-token/jwt-library`](https://github.com/web-token/jwt-framework) provides `Jose\Component\Core\Util\ECSignature::toAsn1()` / `fromAsn1()` for the raw↔DER conversion, and `ECKey`/`RSAKey` utilities for JWK→key conversion.

## Key files

| File                                                                                                         | Purpose                                           |
|--------------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| [`app/Services/WebhookSignatureVerifier.php`](app/Services/WebhookSignatureVerifier.php)                     | Full RFC 9421 verifier — the core of this example |
| [`app/Services/JwksCache.php`](app/Services/JwksCache.php)                                                   | Fetches and caches the sender's JWKS              |
| [`app/Http/Middleware/VerifyWebhookSignature.php`](app/Http/Middleware/VerifyWebhookSignature.php)           | Middleware that calls the verifier                |
| [`app/Http/Controllers/WebhookHandshakeController.php`](app/Http/Controllers/WebhookHandshakeController.php) | OPTIONS handshake                                 |
| [`app/Http/Controllers/WebhookController.php`](app/Http/Controllers/WebhookController.php)                   | Stores every delivery, verified or not            |
| [`app/Livewire/EventFeed.php`](app/Livewire/EventFeed.php)                                                   | Live dashboard component                          |
| [`config/webhook-receiver.php`](config/webhook-receiver.php)                                                 | All configurable values                           |

## HTTP response codes

| Scenario                                  | Code | Effect on sender                                   |
|-------------------------------------------|------|----------------------------------------------------|
| Verified + stored                         | 204  | Marked `Delivered`                                 |
| Retry of a `WebHook-ID` that verified     | 204  | Marked `Delivered` (idempotent)                    |
| Retry of a `WebHook-ID` that failed       | 401  | Marked `Abandoned` — the original failure stands   |
| Verification failed                       | 401  | Marked `Abandoned` — no retry                      |
| Sender's JWKS unreachable, or other error | 500  | Marked `Failed` — retried with exponential backoff |

> **Do not** return `410 Gone` or `415 Unsupported Media Type` unless you intentionally want the sender to permanently deactivate the subscription.

## Security notes

The dashboard at `GET /` has **no authentication** and can display the raw payload and headers of every delivery, so treat it accordingly:

- Run it only on `localhost` when possible. If you tunnel it with ngrok to receive a real staging webhook (see [Pointing the sender at this app](#pointing-the-sender-at-this-app)), the forwarding URL is reachable by anyone who has it for as long as the tunnel is up — don't add ngrok's `--basic-auth` or an OAuth wall, since the sender can't authenticate to those and its requests would never reach the app. Keep the exposure window short: only start the tunnel while you're actively capturing a delivery, and stop it once you're done. `robots.txt` also disallows indexing as a backstop, but that isn't a substitute for not exposing it.
- The `Authorization`, `Cookie`, and `Proxy-Authorization` request headers are redacted before being persisted, since Dash sends the subscription's Bearer secret as `Authorization` on every delivery and that secret is otherwise only ever shown once at subscription creation.
- Adding a real login to the dashboard is out of scope for this reference implementation — if you deploy it as a long-running service rather than a local debugging tool, put it behind your own authentication (e.g. a reverse proxy with basic auth, or a VPN).

## License

MIT — see [LICENSE](LICENSE).
