# Fixed check order with a bounded replay store and spec-exact presets

Status: accepted (generated, pending human review)

## Context

Webhook receivers commonly compare signatures with plain equality, verify a re-serialised body or remember replay keys before the signature is verified. Each provider (GitHub, Standard Webhooks, Stripe) signs a slightly different payload, so a single hard-coded format would not serve them all.

## Decision

Describe each provider as a Scheme object (header parsing, signed payload, secret decoding, header formatting) and run all of them through one verify() pipeline with a fixed order: body size, headers, parsing, timestamp tolerance, signature (all secrets times all signatures, no early exit, timingSafeEqual after a length check), then replay. Replay keys are remembered only after the signature verified, so unauthenticated requests cannot poison them. The ReplayStore interface is pluggable and the bundled MemoryReplayStore has a maxEntries bound, evicts expired keys first and answers 'full' so that verify fails closed. Request data never causes a rejected promise; only configuration errors (WebhookConfigError) do. Timestamp tolerance is enforced only when toleranceSeconds is set.

## Consequences

Adding a provider only needs a new Scheme. The pipeline is easy to audit and each threat has one test. Callers must supply the raw body and should set toleranceSeconds and a replayStore. Memory use of the bundled store is bounded, but multi-instance deployments need their own shared ReplayStore. Replays after the TTL for schemes without a timestamp are not defended.
