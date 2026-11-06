/**
 * Verification of HMAC-signed webhook deliveries.
 *
 * Provides spec-exact presets for GitHub, Standard Webhooks and Stripe-style
 * signatures, timestamp tolerance, key rotation and a bounded replay store.
 * The library never logs and results never contain secrets or signatures.
 *
 * Threat model (see docs/SECURITY.md): forged or tampered bodies, comparison
 * timing, stale timestamps, replays within the TTL, replay-key poisoning and
 * oversized bodies are defended. Replays after the TTL for schemes without a
 * timestamp, replays across instances without a shared store and leaked
 * secrets are not.
 *
 * @packageDocumentation
 */
import { createHmac, timingSafeEqual } from "node:crypto";

const MAX_HEADER_LENGTH = 8192;
const MAX_SIGNATURES = 32;
const MAX_ID_LENGTH = 256;
const MAX_SECRETS = 16;
const MAX_REPLAY_KEY_LENGTH = 1024;
const MAX_TIMESTAMP = 999_999_999_999_999;
const DEFAULT_MAX_BODY_BYTES = 1_048_576;
const DEFAULT_REPLAY_TTL_SECONDS = 86_400;
const DEFAULT_MAX_ENTRIES = 100_000;

const TIMESTAMP_PATTERN = /^[0-9]{1,15}$/;
const HEX_SIGNATURE_PATTERN = /^[0-9a-fA-F]{64}$/;
const GITHUB_SIGNATURE_PATTERN = /^sha256=([0-9a-fA-F]{64})$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

const encoder = new TextEncoder();

/** A header value as delivered by Node.js style HTTP servers. */
export type HeaderValue = string | string[] | undefined;

/** Case-insensitive header accessor handed to scheme parsers. */
export type HeaderLookup = (name: string) => HeaderValue;

/** Parameters of a signature that are not part of the body. */
export interface SignParams {
  /** Timestamp in integer seconds. */
  timestamp?: number;
  /** Delivery or message identifier. */
  id?: string;
}

/**
 * Error raised for invalid configuration (never for request data).
 * Messages never contain secrets or caller input.
 */
export class WebhookConfigError extends Error {
  /** Stable machine-readable code. */
  readonly code = "invalid_options" as const;

  /**
   * @param message - Static description of the invalid option.
   */
  constructor(message: string) {
    super(message);
    this.name = "WebhookConfigError";
  }
}

function configError(message: string): WebhookConfigError {
  return new WebhookConfigError(message);
}

/** Describes how a provider signs and transports webhook signatures. */
export interface Scheme {
  /** Short stable name, used as the replay key prefix. */
  name: string;
  /** HMAC hash algorithm. */
  algorithm: "sha256";
  /** Encoding of the signature on the wire. */
  encoding: "hex" | "base64";
  /** Lower-case names of headers that must be present. */
  requiredHeaders: string[];
  /** Decoded candidate signatures, or null when the header is malformed. */
  parseSignatures(h: HeaderLookup): Uint8Array[] | null;
  /** Seconds timestamp; undefined when the scheme has none, null when malformed. */
  parseTimestamp(h: HeaderLookup): number | null | undefined;
  /**
   * Exact timestamp text used in the signed content. Optional: when absent the
   * decimal form of the parsed timestamp is used.
   */
  parseTimestampText?(h: HeaderLookup): string | undefined;
  /** Delivery identifier, when the scheme carries one. */
  parseId(h: HeaderLookup): string | undefined;
  /** Builds the exact byte string that is signed. */
  signedPayload(p: { body: Uint8Array; timestamp?: string; id?: string }): Uint8Array;
  /** Turns a configured secret into HMAC key bytes. */
  decodeSecret(s: string | Uint8Array): Uint8Array;
  /** Builds the headers a sender attaches to a delivery. */
  formatHeaders(sig: Uint8Array, p: SignParams): Record<string, string>;
}

function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function hexBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function decodeBase64Strict(text: string): Uint8Array | null {
  if (text.length === 0 || text.length % 4 !== 0 || !BASE64_PATTERN.test(text)) {
    return null;
  }
  const buffer = Buffer.from(text, "base64");
  return buffer.toString("base64") === text ? new Uint8Array(buffer) : null;
}

function rawSecret(secret: string | Uint8Array): Uint8Array {
  const bytes: unknown = typeof secret === "string" ? encoder.encode(secret) : secret;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw configError("secret must be a non-empty string or Uint8Array");
  }
  return bytes;
}

function timestampFrom(value: HeaderValue): number | null {
  return typeof value === "string" && TIMESTAMP_PATTERN.test(value) ? Number(value) : null;
}

function checkTimestamp(timestamp: number | undefined): string {
  if (
    timestamp === undefined ||
    !Number.isSafeInteger(timestamp) ||
    timestamp < 0 ||
    timestamp > MAX_TIMESTAMP
  ) {
    throw configError("timestamp must be a non-negative integer of at most 15 digits");
  }
  return String(timestamp);
}

function checkId(id: string | undefined): string {
  if (typeof id !== "string" || id.length === 0 || id.length > MAX_ID_LENGTH) {
    throw configError("id must be a non-empty string of at most 256 chars");
  }
  return id;
}

function withPrefix(prefix: string, body: Uint8Array): Uint8Array {
  return new Uint8Array(Buffer.concat([encoder.encode(prefix), body]));
}

const githubStyle: Scheme = {
  name: "github",
  algorithm: "sha256",
  encoding: "hex",
  requiredHeaders: ["x-hub-signature-256"],
  parseSignatures(h) {
    const value = h("x-hub-signature-256");
    if (typeof value !== "string") {
      return null;
    }
    const match = GITHUB_SIGNATURE_PATTERN.exec(value);
    const hex = match?.[1];
    return hex === undefined ? null : [hexBytes(hex)];
  },
  parseTimestamp() {
    return undefined;
  },
  parseId(h) {
    const value = h("x-github-delivery");
    return typeof value === "string" && value.length > 0 ? value : undefined;
  },
  signedPayload({ body }) {
    return body;
  },
  decodeSecret: rawSecret,
  formatHeaders(sig, p) {
    const headers: Record<string, string> = {
      "X-Hub-Signature-256": `sha256=${hexOf(sig)}`,
    };
    if (p.id !== undefined) {
      headers["X-GitHub-Delivery"] = checkId(p.id);
    }
    return headers;
  },
};

const standardWebhooks: Scheme = {
  name: "standard-webhooks",
  algorithm: "sha256",
  encoding: "base64",
  requiredHeaders: ["webhook-id", "webhook-timestamp", "webhook-signature"],
  parseSignatures(h) {
    const id = h("webhook-id");
    if (typeof id !== "string" || id.length === 0) {
      return null;
    }
    const value = h("webhook-signature");
    if (typeof value !== "string" || value.length > MAX_HEADER_LENGTH) {
      return null;
    }
    const signatures: Uint8Array[] = [];
    for (const entry of value.split(" ")) {
      if (entry === "") {
        continue;
      }
      const comma = entry.indexOf(",");
      if (comma < 0) {
        return null;
      }
      if (entry.slice(0, comma) !== "v1") {
        continue;
      }
      const decoded = decodeBase64Strict(entry.slice(comma + 1));
      if (decoded === null || signatures.length >= MAX_SIGNATURES) {
        return null;
      }
      signatures.push(decoded);
    }
    return signatures.length === 0 ? null : signatures;
  },
  parseTimestamp(h) {
    return timestampFrom(h("webhook-timestamp"));
  },
  parseTimestampText(h) {
    const value = h("webhook-timestamp");
    return typeof value === "string" ? value : undefined;
  },
  parseId(h) {
    const value = h("webhook-id");
    return typeof value === "string" && value.length > 0 ? value : undefined;
  },
  signedPayload({ body, timestamp, id }) {
    if (timestamp === undefined || id === undefined) {
      throw configError("standard webhooks requires an id and a timestamp");
    }
    return withPrefix(`${id}.${timestamp}.`, body);
  },
  decodeSecret(secret) {
    if (typeof secret !== "string") {
      return rawSecret(secret);
    }
    const encoded = secret.startsWith("whsec_") ? secret.slice(6) : secret;
    const decoded = decodeBase64Strict(encoded);
    if (decoded === null) {
      throw configError("webhook secret is not valid base64");
    }
    return decoded;
  },
  formatHeaders(sig, p) {
    return {
      "webhook-id": checkId(p.id),
      "webhook-timestamp": checkTimestamp(p.timestamp),
      "webhook-signature": `v1,${Buffer.from(sig).toString("base64")}`,
    };
  },
};

interface StripeParts {
  readonly t: string;
  readonly v1: string[];
}

function parseStripe(h: HeaderLookup): StripeParts | null {
  const value = h("stripe-signature");
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_HEADER_LENGTH) {
    return null;
  }
  let t: string | undefined;
  const v1: string[] = [];
  for (const part of value.split(",")) {
    const eq = part.indexOf("=");
    if (eq <= 0) {
      return null;
    }
    const key = part.slice(0, eq);
    const item = part.slice(eq + 1);
    if (key === "t") {
      if (t !== undefined || !TIMESTAMP_PATTERN.test(item)) {
        return null;
      }
      t = item;
    } else if (key === "v1") {
      if (!HEX_SIGNATURE_PATTERN.test(item) || v1.length >= MAX_SIGNATURES) {
        return null;
      }
      v1.push(item);
    }
  }
  return t === undefined || v1.length === 0 ? null : { t, v1 };
}

const stripeStyle: Scheme = {
  name: "stripe",
  algorithm: "sha256",
  encoding: "hex",
  requiredHeaders: ["stripe-signature"],
  parseSignatures(h) {
    const parts = parseStripe(h);
    return parts === null ? null : parts.v1.map(hexBytes);
  },
  parseTimestamp(h) {
    const parts = parseStripe(h);
    return parts === null ? null : Number(parts.t);
  },
  parseTimestampText(h) {
    return parseStripe(h)?.t;
  },
  parseId() {
    return undefined;
  },
  signedPayload({ body, timestamp }) {
    if (timestamp === undefined) {
      throw configError("stripe style requires a timestamp");
    }
    return withPrefix(`${timestamp}.`, body);
  },
  decodeSecret: rawSecret,
  formatHeaders(sig, p) {
    return {
      "Stripe-Signature": `t=${checkTimestamp(p.timestamp)},v1=${hexOf(sig)}`,
    };
  },
};

/** Built-in schemes. */
export const presets: {
  readonly githubStyle: Scheme;
  readonly standardWebhooks: Scheme;
  readonly stripeStyle: Scheme;
} = Object.freeze({ githubStyle, standardWebhooks, stripeStyle });

/** Outcome of recording a replay key. */
export type ReplayOutcome = "new" | "seen" | "full";

/** Remembers delivery keys so that a verified delivery is accepted once. */
export interface ReplayStore {
  /**
   * Atomically checks and remembers a key.
   *
   * @param key - Replay key.
   * @param ttlMs - How long to remember the key, in milliseconds.
   * @returns `new` when remembered, `seen` for a live duplicate, `full` when
   * the store cannot accept more keys (callers must fail closed).
   */
  checkAndRemember(key: string, ttlMs: number): Promise<ReplayOutcome>;
}

/**
 * In-memory replay store with a maximum number of entries. Expired keys are
 * evicted first; when the store is still full it answers `full`.
 */
export class MemoryReplayStore implements ReplayStore {
  readonly #entries = new Map<string, number>();
  readonly #clock: () => number;
  readonly #maxEntries: number;
  #minExpiry = Number.POSITIVE_INFINITY;

  /**
   * @param opts - Optional injected clock (milliseconds) and entry limit
   * (default 100000).
   * @throws {WebhookConfigError} When `maxEntries` is not a positive integer.
   */
  constructor(opts: { clock?: () => number; maxEntries?: number } = {}) {
    const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw configError("maxEntries must be a positive integer");
    }
    this.#maxEntries = maxEntries;
    this.#clock = opts.clock ?? Date.now;
  }

  /** Number of keys currently held, including not yet evicted expired keys. */
  get size(): number {
    return this.#entries.size;
  }

  /** @inheritdoc */
  async checkAndRemember(key: string, ttlMs: number): Promise<ReplayOutcome> {
    if (typeof key !== "string" || key.length === 0 || key.length > MAX_REPLAY_KEY_LENGTH) {
      throw configError("replay key must be 1 to 1024 characters");
    }
    if (!Number.isFinite(ttlMs) || ttlMs < 0) {
      throw configError("ttlMs must be a non-negative finite number");
    }
    const now = this.#clock();
    const existing = this.#entries.get(key);
    if (existing !== undefined) {
      if (existing > now) {
        return "seen";
      }
      this.#entries.delete(key);
    }
    if (this.#entries.size >= this.#maxEntries) {
      this.#sweep(now);
      if (this.#entries.size >= this.#maxEntries) {
        return "full";
      }
    }
    const expiry = now + ttlMs;
    this.#entries.set(key, expiry);
    if (expiry < this.#minExpiry) {
      this.#minExpiry = expiry;
    }
    return "new";
  }

  #sweep(now: number): void {
    if (now < this.#minExpiry) {
      return;
    }
    let minExpiry = Number.POSITIVE_INFINITY;
    for (const [key, expiry] of this.#entries) {
      if (expiry <= now) {
        this.#entries.delete(key);
      } else if (expiry < minExpiry) {
        minExpiry = expiry;
      }
    }
    this.#minExpiry = minExpiry;
  }
}

/** Options of {@link verify}. */
export interface VerifyOptions {
  /** Accepted secrets (1 to 16); every one is tried, which enables rotation. */
  secrets: Array<string | Uint8Array>;
  /** Signature scheme. */
  scheme: Scheme;
  /**
   * Maximum clock skew in seconds for timestamped schemes. Enforced only when
   * set (300 is a common choice); a timestamp exactly this far away is
   * accepted.
   */
  toleranceSeconds?: number;
  /** Replay store. Without one, no replay protection is applied. */
  replayStore?: ReplayStore;
  /**
   * Replay TTL in seconds, used when the scheme has no timestamp or no
   * tolerance is set (default 86400). With a timestamp and a tolerance the TTL
   * is twice the tolerance.
   */
  replayTtlSeconds?: number;
  /** Maximum body size in bytes (default 1048576). */
  maxBodyBytes?: number;
  /** Clock in milliseconds (default `Date.now`). */
  clock?: () => number;
}

/** Reasons a delivery is rejected. */
export type FailureReason =
  | "missing_header"
  | "malformed_header"
  | "body_too_large"
  | "timestamp_out_of_range"
  | "signature_mismatch"
  | "replayed"
  | "replay_store_full";

/** Result of {@link verify}. Never contains secrets or signatures. */
export type VerifyResult =
  | { readonly ok: true; readonly timestamp?: number; readonly id?: string }
  | { readonly ok: false; readonly reason: FailureReason };

interface ResolvedOptions {
  readonly scheme: Scheme;
  readonly keys: readonly Uint8Array[];
  readonly toleranceSeconds: number | undefined;
  readonly replayTtlSeconds: number;
  readonly replayStore: ReplayStore | undefined;
  readonly maxBodyBytes: number;
  readonly clock: () => number;
}

function resolveOptions(options: VerifyOptions): ResolvedOptions {
  if (typeof options !== "object" || options === null) {
    throw configError("options must be an object");
  }
  const { scheme, secrets } = options;
  if (typeof scheme !== "object" || scheme === null) {
    throw configError("scheme is required");
  }
  if (!Array.isArray(secrets) || secrets.length === 0 || secrets.length > MAX_SECRETS) {
    throw configError("secrets must contain 1 to 16 entries");
  }
  const keys = secrets.map((secret) => scheme.decodeSecret(secret));
  const tolerance = options.toleranceSeconds;
  if (tolerance !== undefined && !(Number.isFinite(tolerance) && tolerance >= 0)) {
    throw configError("toleranceSeconds must be a non-negative number");
  }
  const replayTtlSeconds = options.replayTtlSeconds ?? DEFAULT_REPLAY_TTL_SECONDS;
  if (!(Number.isFinite(replayTtlSeconds) && replayTtlSeconds > 0)) {
    throw configError("replayTtlSeconds must be a positive number");
  }
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw configError("maxBodyBytes must be a positive integer");
  }
  const clock = options.clock ?? Date.now;
  if (typeof clock !== "function") {
    throw configError("clock must be a function");
  }
  const store = options.replayStore;
  if (store !== undefined && typeof store.checkAndRemember !== "function") {
    throw configError("replayStore must implement checkAndRemember");
  }
  return {
    scheme,
    keys,
    toleranceSeconds: tolerance,
    replayTtlSeconds,
    replayStore: store,
    maxBodyBytes,
    clock,
  };
}

function buildLookup(headers: unknown): HeaderLookup {
  if (typeof headers !== "object" || headers === null) {
    throw configError("headers must be an object");
  }
  if (Array.isArray(headers)) {
    throw configError("headers must be an object");
  }
  const map = new Map<string, HeaderValue>();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    const lower = name.toLowerCase();
    // Two spellings of one header are ambiguous: expose them as malformed.
    map.set(lower, map.has(lower) ? [] : (value as HeaderValue));
  }
  return (name) => map.get(name.toLowerCase());
}

function fail(reason: FailureReason): VerifyResult {
  return { ok: false, reason };
}

/**
 * Verifies a webhook delivery against the raw request body.
 *
 * Check order: body size, required headers (case-insensitive), header
 * parsing, timestamp tolerance, signature (all secrets against all
 * signatures, no early exit), then replay. A replay key is remembered only
 * after the signature verified. The promise never rejects for request data;
 * it rejects with {@link WebhookConfigError} for invalid configuration or a
 * non-string, non-Uint8Array body, and with the store error if the replay
 * store itself fails (the delivery is then not accepted).
 *
 * @param rawBody - The exact bytes received (a string is UTF-8 encoded).
 * @param headers - Request headers.
 * @param options - Secrets, scheme and limits.
 * @returns `{ ok: true }` or `{ ok: false, reason }`.
 */
export async function verify(
  rawBody: Uint8Array | string,
  headers: Record<string, string | string[] | undefined>,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const cfg = resolveOptions(options);
  if (typeof rawBody !== "string" && !(rawBody instanceof Uint8Array)) {
    throw configError("rawBody must be a string or Uint8Array");
  }
  const size =
    typeof rawBody === "string" ? Buffer.byteLength(rawBody, "utf8") : rawBody.byteLength;
  if (size > cfg.maxBodyBytes) {
    return fail("body_too_large");
  }
  const lookup = buildLookup(headers);
  const { scheme } = cfg;
  for (const name of scheme.requiredHeaders) {
    if (lookup(name) === undefined) {
      return fail("missing_header");
    }
  }
  const signatures = scheme.parseSignatures(lookup);
  const timestamp = scheme.parseTimestamp(lookup);
  const id = scheme.parseId(lookup);
  if (signatures === null || timestamp === null) {
    return fail("malformed_header");
  }
  if (id !== undefined && id.length > MAX_ID_LENGTH) {
    return fail("malformed_header");
  }
  if (timestamp !== undefined && cfg.toleranceSeconds !== undefined) {
    const skew = Math.abs(cfg.clock() - timestamp * 1000);
    if (!(skew <= cfg.toleranceSeconds * 1000)) {
      return fail("timestamp_out_of_range");
    }
  }
  const timestampText =
    timestamp === undefined
      ? undefined
      : (scheme.parseTimestampText?.(lookup) ?? String(timestamp));
  const body = typeof rawBody === "string" ? encoder.encode(rawBody) : rawBody;
  const payload = scheme.signedPayload({
    body,
    ...(timestampText === undefined ? {} : { timestamp: timestampText }),
    ...(id === undefined ? {} : { id }),
  });
  let matched: Uint8Array | undefined;
  for (const key of cfg.keys) {
    const expected = createHmac(scheme.algorithm, key).update(payload).digest();
    for (const candidate of signatures) {
      const equal = candidate.length === expected.length && timingSafeEqual(candidate, expected);
      if (equal && matched === undefined) {
        matched = candidate;
      }
    }
  }
  if (matched === undefined) {
    return fail("signature_mismatch");
  }
  if (cfg.replayStore !== undefined) {
    const replayKey =
      id === undefined
        ? `${scheme.name}:${timestampText ?? ""}:${hexOf(matched)}`
        : `${scheme.name}:${id}`;
    const ttlSeconds =
      timestamp !== undefined && cfg.toleranceSeconds !== undefined
        ? 2 * cfg.toleranceSeconds
        : cfg.replayTtlSeconds;
    const outcome = await cfg.replayStore.checkAndRemember(replayKey, ttlSeconds * 1000);
    if (outcome === "seen") {
      return fail("replayed");
    }
    if (outcome !== "new") {
      return fail("replay_store_full");
    }
  }
  const result: { ok: true; timestamp?: number; id?: string } = { ok: true };
  if (timestamp !== undefined) {
    result.timestamp = timestamp;
  }
  if (id !== undefined) {
    result.id = id;
  }
  return result;
}

/**
 * Signs a body and returns the headers a sender attaches.
 *
 * @param rawBody - Exact body bytes (a string is UTF-8 encoded).
 * @param secret - Secret in the scheme's configured form.
 * @param scheme - Signature scheme.
 * @param p - Timestamp (integer seconds) and id, as the scheme requires.
 * @returns Header name to value map.
 * @throws {WebhookConfigError} For an invalid secret, body, timestamp or id.
 */
export function sign(
  rawBody: Uint8Array | string,
  secret: string | Uint8Array,
  scheme: Scheme,
  p: SignParams = {},
): Record<string, string> {
  if (typeof rawBody !== "string" && !(rawBody instanceof Uint8Array)) {
    throw configError("rawBody must be a string or Uint8Array");
  }
  const key = scheme.decodeSecret(secret);
  const timestamp = p.timestamp === undefined ? undefined : checkTimestamp(p.timestamp);
  const id = p.id === undefined ? undefined : checkId(p.id);
  const body = typeof rawBody === "string" ? encoder.encode(rawBody) : rawBody;
  const payload = scheme.signedPayload({
    body,
    ...(timestamp === undefined ? {} : { timestamp }),
    ...(id === undefined ? {} : { id }),
  });
  const digest = createHmac(scheme.algorithm, key).update(payload).digest();
  return scheme.formatHeaders(new Uint8Array(digest), p);
}
