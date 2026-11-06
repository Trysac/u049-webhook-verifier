# Security

This document describes the threat model of `@trysac/webhook-verifier`. To report a vulnerability, see the repository `SECURITY.md`.

## Threat model

Webhook endpoints are public URLs. The library verifies HMAC-SHA256 signatures computed over the raw request body. Every defended item below is covered by at least one test.

| Threat | Defence |
|---|---|
| Forged or tampered bodies | The signature is recomputed over the exact received bytes (a string body is UTF-8 encoded). Any change to the body, id, timestamp or secret gives `signature_mismatch`. Always pass the raw body, never a re-serialised object. |
| Comparison timing | Signatures are compared with `crypto.timingSafeEqual`. Every secret is compared against every signature with no early exit. Wrong-length signatures are counted as mismatches before the comparison (the lengths are public). |
| Stale timestamps | For timestamped schemes (Standard Webhooks, Stripe style) the timestamp must be within `toleranceSeconds` of the injected clock, but only when a tolerance is set. A timestamp exactly `toleranceSeconds` away is accepted. A non-finite clock value fails closed. |
| Replays within the TTL | With a `replayStore`, a verified delivery is remembered. The key is `<scheme>:<id>` when the scheme carries an id, otherwise `<scheme>:<timestamp>:<signature hex>`. A second delivery returns `replayed`. The TTL is twice `toleranceSeconds` for timestamped schemes when a tolerance is set, otherwise `replayTtlSeconds` (default 86400). |
| Replay-key poisoning | A key is remembered only after the signature verified, so a forged request cannot burn the id of a genuine delivery. |
| Oversized bodies | `maxBodyBytes` (default 1048576) is checked first, before any header parsing or HMAC. Header values are limited to 8192 characters, delivery ids to 256 characters and signature lists to 32 entries. |
| Replay store exhaustion | `MemoryReplayStore` holds at most `maxEntries` keys (default 100000). Expired keys are evicted first. When it is still full it answers `full` and `verify` returns `replay_store_full` (fail closed). |

## Header grammar

- GitHub: `X-Hub-Signature-256` must match `^sha256=[0-9a-fA-F]{64}$`.
- Stripe style: comma-separated `key=value` pairs, exactly one `t` matching `^[0-9]{1,15}$`, one or more `v1` of 64 hex characters, other keys (such as `v0`) ignored. The full secret string is the HMAC key and the signed content is `<t>.<body>`.
- Standard Webhooks: `webhook-timestamp` matches `^[0-9]{1,15}$`; `webhook-signature` holds space-separated entries and only `v1,<base64>` entries are decoded (strict canonical base64); the signed content is `<id>.<timestamp>.<body>`; a `whsec_` secret is base64-decoded before use. A malformed `v1` entry, or a header without any `v1` entry, is malformed.

## Recommended configuration

- Set `toleranceSeconds` (for example 300) for timestamped schemes. It is enforced only when set.
- Provide a `replayStore`. For several instances, implement `ReplayStore` on shared storage; `MemoryReplayStore` is per process.
- Rotate secrets by listing the old and the new secret in `secrets`.

## Not defended

- Replays after the TTL for schemes without a timestamp (GitHub).
- Replays across instances unless they share a `ReplayStore`.
- Leaked secrets.
- The GitHub delivery id header (`X-GitHub-Delivery`) is not covered by the signature. An attacker who captured a genuine delivery can change it to bypass replay detection. GitHub signs no timestamp, so this cannot be fixed on the receiver side.

## Operational notes

- The library never logs and never configures logging. Results contain only `ok`, a reason code, the timestamp and the id; never secrets or signatures.
- `WebhookConfigError` (code `invalid_options`) is thrown for configuration mistakes and never contains secrets or caller input.
- Out of scope: ed25519 (`v1a`) signatures, provider SDKs and framework adapters.
