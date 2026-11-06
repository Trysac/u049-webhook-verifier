# Project record: webhook-verifier

## Objective

Verify HMAC webhook signatures on the raw body with GitHub, Standard Webhooks and Stripe-style presets, with timestamp tolerance, a bounded replay store and key rotation. The utility is for Node.js services that receive webhooks and must reject forged, tampered, stale or replayed deliveries, using a fixed check order and fail-closed behavior.

## Scope

In scope:

- Verification of GitHub (`X-Hub-Signature-256`), Standard Webhooks and Stripe-style signatures on the raw body.
- Signature creation with `sign` for the same schemes, for tests and sender-side use.
- Timestamp tolerance when configured, a replay store interface, and an in-memory bounded implementation.
- Secret rotation by listing several secrets.
- The public API documented in the README.

Out of scope:

- ed25519 (`v1a`) signatures.
- Provider SDKs and framework adapters.
- Shared or persistent replay storage; a shared store must be supplied by the caller through the `ReplayStore` interface.
- Logging and metrics.

## Timeline

| Date | Milestone |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Values are taken from the factory ledger and the time log. None are estimated in this file.

| Metric | Value | Source |
|---|---|---|
| Tokens (input / output) | 329465 / 76038 | factory ledger |
| Hours (human) | pending measurement | time log |
| Cost (USD) | 0.5845 | factory ledger |

## Factory run u049 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 3128 | 59402 | 0 | 4473 | 0.3006 |
| fix-1 | claude-sonnet-5-5 | no | 8 | 1024 | 9304 | 62570 | 0.0398 |
| fix-2 | claude-sonnet-5-5 | no | 10 | 1828 | 9196 | 75694 | 0.0489 |
| audit | claude-sonnet-5-5 | no | 10 | 3144 | 39988 | 105534 | 0.1420 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 1854 | 9039 | 41971 | 0.0453 |
| docs | claude-haiku-5-5 | no | 36061 | 8786 | 0 | 0 | 0.0080 |

Total: $0.5845. Prices: Anthropic list prices.
