# Security Policy

This repository is a **reference implementation** demonstrating how to receive and verify Dash
webhooks (RFC 9421 HTTP Message Signatures, replay-window enforcement, etc.). It is not a
production service, but the signature-verification code is security-sensitive and mistakes here
could mislead anyone adapting it for production. We take reports about it seriously.

## Supported Versions

This project does not maintain multiple release branches. Security fixes are applied to the
latest version on the `main` branch only.

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Instead, report it privately using GitHub's built-in reporting flow:

1. Go to the [Security tab](https://github.com/DaySmart/dash-webhook-receiver-example-php/security) of this repository.
2. Click **"Report a vulnerability"** to open a private advisory.

Please include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof-of-concept
- The affected file(s)/line(s), if known
- Any suggested remediation

We'll acknowledge new reports as soon as we're able, and keep you updated as we investigate and
address the issue. Once a fix is available, we'll coordinate on disclosure timing with you before
publishing details.

## Scope

Examples of in-scope issues:

- Flaws in the RFC 9421 signature verification logic (e.g. signature bypass, incorrect
  Content-Digest validation, JWK→PEM conversion bugs)
- Replay-window or deduplication logic that could allow forged/replayed webhook deliveries to be
  accepted
- Other vulnerabilities in application code under `app/`

Out of scope:

- Vulnerabilities in third-party dependencies (please report these upstream, e.g. via
  [Packagist](https://packagist.org/) advisories or the dependency's own repository)
- Issues that only affect local development ergonomics (e.g. Docker/Xdebug configuration) with no
  security impact
