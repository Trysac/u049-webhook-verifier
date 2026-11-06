# webhook-verifier

[![npm version](https://img.shields.io/npm/v/@trysac/webhook-verifier.svg)](https://www.npmjs.com/package/@trysac/webhook-verifier)
[![license: MIT](https://img.shields.io/npm/l/@trysac/webhook-verifier.svg)](LICENSE)
[![CI](https://github.com/Trysac/u049-webhook-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u049-webhook-verifier/actions/workflows/ci.yml)

Verify HMAC webhook signatures on the raw body with GitHub, Standard Webhooks and Stripe-style presets, timestamp tolerance, replay store and key rotation

## Problem

Webhook endpoints are public URLs, so anyone can post forged events unless the signature is checked, and a valid request can be replayed later. Each provider signs a slightly different payload, and teams compare signatures with plain equality, verify a re-serialised body or remember replay keys before checking the signature. This library verifies raw-body HMAC signatures with spec-exact presets, a strict check order and a bounded replay store.

## Install

```sh
npm install @trysac/webhook-verifier
```

Requires Node.js 20 or newer. The package ships ES modules with TypeScript declarations and has no runtime dependencies.

## Usage

```ts
import { presets, verify } from "@trysac/webhook-verifier";

const headers = { "x-hub-signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17" };
const secrets = ["It's a Secret to Everybody"];
console.log(await verify("Hello, World!", headers, { secrets, scheme: presets.githubStyle }));
```

The example prints `{ ok: true }`. Pass the exact bytes received as the body, never a re-serialised object. `verify` does not reject for request data; it resolves `{ ok: false, reason }` instead. Check order: body size, required headers, header parsing, timestamp tolerance, signature (all secrets against all signatures), then replay.

## API

| Export | Signature | Description |
|---|---|---|
| `verify` | `(rawBody, headers, options: VerifyOptions) => Promise<VerifyResult>` | Verifies a delivery. Result is `{ ok: true; timestamp?; id? }` or `{ ok: false; reason }`. |
| `sign` | `(rawBody, secret, scheme, { timestamp?, id? }?) => Record<string, string>` | Produces the signature headers a sender attaches. |
| `presets` | `{ githubStyle, standardWebhooks, stripeStyle }` | Spec-exact `Scheme` presets. |
| `MemoryReplayStore` | `new MemoryReplayStore({ clock?, maxEntries? })` | In-memory `ReplayStore` with at most `maxEntries` keys (default 100000). Expired keys are evicted first. |
| `ReplayStore` | `{ checkAndRemember(key, ttlMs): Promise<'new' \| 'seen' \| 'full'> }` | Interface for a custom or shared replay store. |
| `Scheme` | interface | Describes how a provider signs, transports and parses signatures. |
| `VerifyOptions` | interface | `secrets` (1 to 16), `scheme`, `toleranceSeconds?`, `replayStore?`, `replayTtlSeconds?` (default 86400), `maxBodyBytes?` (default 1048576), `clock?` (milliseconds). |
| `WebhookConfigError` | `class extends Error { code: 'invalid_options' }` | Thrown (the promise rejects) for invalid options, such as an empty secret list, negative tolerance or a non-base64 `whsec_` secret, and for a body or headers of the wrong type. Messages never contain secrets. |

`VerifyResult` failure reasons: `missing_header`, `malformed_header`, `body_too_large`, `timestamp_out_of_range`, `signature_mismatch`, `replayed`, `replay_store_full`.

Limits: body 1048576 bytes by default; header values 8192 characters; delivery ids 256 characters; 32 signatures per header; 16 secrets; replay keys 1024 characters. `toleranceSeconds` is enforced only when set. Timestamped schemes then use a replay TTL of twice the tolerance.

## Security

The threat model, the defended threats and the limits that are not defended are described in [docs/SECURITY.md](docs/SECURITY.md).

## Development

```sh
npm install
npm run check   # lint, format, types, tests with coverage, docs, secrets
```

See [AGENTS.md](AGENTS.md) for the full command list and [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[MIT](LICENSE) © 2026 Miguel Gomez
