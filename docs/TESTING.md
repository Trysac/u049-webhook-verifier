# Testing

## Tools

- [Vitest](https://vitest.dev/) runs the suite in `test/`.
- Coverage is collected with V8 (`@vitest/coverage-v8`) over `src/`.

## Commands

```sh
npm test            # vitest run --coverage
npx vitest          # watch mode while developing
npm run check       # every gate, including tests
```

## Test suite

The only test file is `test/index.test.ts`. It imports the public entry point `src/index.ts` and covers:

- GitHub preset: the published vector, case-insensitive hex and header names, Uint8Array bodies and secrets, malformed values, array and duplicate header spellings, missing headers, delivery id length, tampered bodies and wrong secrets.
- Standard Webhooks preset: the published vector, entries with other version prefixes, the exact timestamp text with leading zeros, `whsec_` and raw secrets, invalid timestamps and signature lists, a 31-byte signature, and binding of id and timestamp.
- Stripe-style preset: the derived vector (labelled as derived in the test), `v0` and unknown keys, malformed headers, and mismatched bodies.
- Timestamp tolerance: exact boundary at 300 seconds, 301 seconds rejected, a non-finite clock failing closed, and no check for schemes without a timestamp.
- Replay protection: duplicate ids, forged deliveries not burning ids, keys without ids, default and custom TTLs, a full store failing closed, unknown store answers, and no store access for rejected deliveries.
- `MemoryReplayStore`: eviction of expired keys, re-admission after expiry, default limits and input validation.
- Key rotation: a second secret matching, rejection of unknown secrets, comparison of every pair without early exit, no comparison for wrong-length signatures, and single-byte differences at the first and last position.
- Body size limit: rejection before any HMAC, acceptance at exactly the limit, and the 1048576-byte default.
- Configuration errors: invalid options, non-base64 `whsec_` secrets not echoed in messages, and invalid option, body and header types.
- `sign`: published vectors, delivery id round trip, Uint8Array bodies and invalid parameters.
- Scheme helpers and frozen presets.

`timingSafeEqual` is wrapped with a spy so that tests can assert how often it is called.

## Rules

- Coverage must stay at or above 80 % for lines, branches, functions and statements (`vitest.config.ts`). Lowering the thresholds is not allowed.
- Test through the public entry point (`src/index.ts`) and assert observable behavior: return values, thrown errors and their messages.
- Each bug fix adds a test that fails without the fix.
- Tests are deterministic: no network, clocks and randomness are injected, and no state is shared between tests.

## Reports

Coverage reports are written to `coverage/` (text summary and `lcov`). The folder is ignored by git.
