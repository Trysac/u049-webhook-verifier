# Architecture

## Overview

`@trysac/webhook-verifier` is a small, dependency-free TypeScript library published to npm as ES modules with type declarations. It verifies HMAC-SHA256 webhook signatures on the raw body for GitHub, Standard Webhooks and Stripe-style presets, with optional timestamp tolerance, a replay store and secret rotation.

## Modules

| Module | Responsibility |
|---|---|
| `src/index.ts` | Public API. Contains the scheme presets, `verify`, `sign`, `MemoryReplayStore` and `WebhookConfigError`. Everything consumers import is exported from here. |
| `test/index.test.ts` | Vitest suite for the public API. |

Internal helpers (header lookup, base64 decoding, option resolution) live in `src/index.ts` and are not exported.

## Boundaries

- No runtime dependencies. The code uses only `node:crypto` and the global `TextEncoder`; any addition is justified in [STACK.md](STACK.md).
- The library never logs and never configures logging.
- `verify` resolves `{ ok: false, reason }` for any request data. It rejects only for invalid configuration, a body that is neither a string nor a `Uint8Array`, a headers value that is not a plain object, and a replay store that throws. Configuration failures are thrown as `WebhookConfigError` (code `invalid_options`).
- The replay store is an interface. `MemoryReplayStore` is process-local; shared storage requires a custom `ReplayStore`.

## Verification flow

1. Validate options and the body type.
2. Reject bodies larger than `maxBodyBytes`.
3. Check required headers case-insensitively, then parse signatures, timestamp and id.
4. Check the timestamp against the injected clock when a tolerance is set.
5. Compute the HMAC for every secret and compare with every candidate signature using `timingSafeEqual`, without early exit.
6. Only after a valid signature, check and remember the replay key.

## Build and distribution

`npm run build` compiles `src/` to `dist/` with `tsconfig.build.json`. Only `dist/` is published (`files` in `package.json`).

## Decisions

Architectural decisions are recorded in [decisions/](decisions/), starting with [0001](decisions/0001-record-architecture-decisions.md).
