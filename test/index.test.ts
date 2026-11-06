import { createHmac, timingSafeEqual } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReplayStore, Scheme, VerifyOptions } from "../src/index.js";
import { MemoryReplayStore, presets, sign, verify, WebhookConfigError } from "../src/index.js";

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

type Headers = Record<string, string | string[] | undefined>;

const GH_SECRET = "It's a Secret to Everybody";
const GH_HEX = "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
const GH_SIG = `sha256=${GH_HEX}`;
const GH_BODY = "Hello, World!";

const SW_SECRET = ["whsec", "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"].join("_");
const SW_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const SW_TS = "1614265330";
const SW_BODY = '{"test": 2432232314}';
const SW_SIG = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
const swClock = (): number => 1614265330 * 1000;

const ST_SECRET = "whsec_test_secret";
const ST_HEX = "248a374f50f943a28b0f6ab50faf9a7e7e29b710fa26df9fb1618b9bf8ea9c9a";
const ST_BODY = '{"id":"evt_1"}';
const ST_TS = 1_700_000_000;

function ghOptions(extra: Partial<VerifyOptions> = {}): VerifyOptions {
  return { secrets: [GH_SECRET], scheme: presets.githubStyle, ...extra };
}

function swHeaders(overrides: Headers = {}): Headers {
  return {
    "webhook-id": SW_ID,
    "webhook-timestamp": SW_TS,
    "webhook-signature": SW_SIG,
    ...overrides,
  };
}

function swOptions(extra: Partial<VerifyOptions> = {}): VerifyOptions {
  return {
    secrets: [SW_SECRET],
    scheme: presets.standardWebhooks,
    clock: swClock,
    ...extra,
  };
}

function stOptions(extra: Partial<VerifyOptions> = {}): VerifyOptions {
  return { secrets: [ST_SECRET], scheme: presets.stripeStyle, ...extra };
}

function stripeHmac(secret: string, ts: number, body: string): string {
  return createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
}

beforeEach(() => {
  vi.mocked(timingSafeEqual).mockClear();
});

describe("GitHub preset", () => {
  it("verifies the GitHub docs vector", async () => {
    const result = await verify(
      "Hello, World!",
      {
        "x-hub-signature-256":
          "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
      },
      {
        secrets: ["It's a Secret to Everybody"],
        scheme: presets.githubStyle,
      },
    );
    expect(result).toEqual({ ok: true });
  });

  it("accepts uppercase hex and any header casing", async () => {
    const upper = `sha256=${GH_HEX.toUpperCase()}`;
    expect(await verify(GH_BODY, { "x-hub-signature-256": upper }, ghOptions())).toEqual({
      ok: true,
    });
    expect(await verify(GH_BODY, { "X-HUB-SIGNATURE-256": GH_SIG }, ghOptions())).toEqual({
      ok: true,
    });
  });

  it("verifies Uint8Array bodies and secrets", async () => {
    const body = new TextEncoder().encode(GH_BODY);
    const secret = new TextEncoder().encode(GH_SECRET);
    const result = await verify(
      body,
      { "x-hub-signature-256": GH_SIG },
      ghOptions({ secrets: [secret] }),
    );
    expect(result).toEqual({ ok: true });
  });

  it("rejects sha1 and other malformed values", async () => {
    const bad = [
      "sha1=757107ea",
      "sha256=zz",
      `sha256=${GH_HEX}0`,
      `sha256=${GH_HEX.slice(1)}`,
      ` ${GH_SIG}`,
      `${GH_SIG}\n`,
      GH_HEX,
      "",
    ];
    for (const value of bad) {
      expect(await verify(GH_BODY, { "x-hub-signature-256": value }, ghOptions())).toEqual({
        ok: false,
        reason: "malformed_header",
      });
    }
  });

  it("rejects array values and duplicate spellings as malformed", async () => {
    expect(await verify(GH_BODY, { "x-hub-signature-256": [GH_SIG, GH_SIG] }, ghOptions())).toEqual(
      { ok: false, reason: "malformed_header" },
    );
    expect(
      await verify(
        GH_BODY,
        { "X-Hub-Signature-256": GH_SIG, "x-hub-signature-256": GH_SIG },
        ghOptions(),
      ),
    ).toEqual({ ok: false, reason: "malformed_header" });
  });

  it("reports a missing header", async () => {
    expect(await verify(GH_BODY, {}, ghOptions())).toEqual({
      ok: false,
      reason: "missing_header",
    });
    expect(await verify(GH_BODY, { "x-hub-signature-256": undefined }, ghOptions())).toEqual({
      ok: false,
      reason: "missing_header",
    });
  });

  it("returns the delivery id and rejects oversized ids", async () => {
    const ok = await verify(
      GH_BODY,
      { "x-hub-signature-256": GH_SIG, "x-github-delivery": "abc" },
      ghOptions(),
    );
    expect(ok).toEqual({ ok: true, id: "abc" });
    const long = await verify(
      GH_BODY,
      {
        "x-hub-signature-256": GH_SIG,
        "x-github-delivery": "a".repeat(257),
      },
      ghOptions(),
    );
    expect(long).toEqual({ ok: false, reason: "malformed_header" });
  });

  it("detects a tampered body and a wrong secret", async () => {
    const headers = { "x-hub-signature-256": GH_SIG };
    expect(await verify(`${GH_BODY} `, headers, ghOptions())).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
    expect(await verify(GH_BODY, headers, ghOptions({ secrets: ["other"] }))).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });
});

describe("Standard Webhooks preset", () => {
  it("verifies the published vector", async () => {
    const result = await verify(SW_BODY, swHeaders(), swOptions());
    expect(result).toEqual({ ok: true, timestamp: 1614265330, id: SW_ID });
  });

  it("ignores entries with other version prefixes", async () => {
    const headers = swHeaders({ "webhook-signature": `v1a,xyz ${SW_SIG}` });
    expect(await verify(SW_BODY, headers, swOptions())).toMatchObject({
      ok: true,
    });
  });

  it("works when the scheme has no parseTimestampText", async () => {
    const { parseTimestampText: _omit, ...rest } = presets.standardWebhooks;
    const scheme: Scheme = rest;
    expect(await verify(SW_BODY, swHeaders(), swOptions({ scheme }))).toMatchObject({ ok: true });
  });

  it("signs the exact timestamp text including leading zeros", async () => {
    const ts = "0001614265330";
    const digest = createHmac("sha256", Buffer.from(SW_SECRET.slice(6), "base64"))
      .update(`${SW_ID}.${ts}.${SW_BODY}`)
      .digest("base64");
    const headers = swHeaders({
      "webhook-timestamp": ts,
      "webhook-signature": `v1,${digest}`,
    });
    expect(await verify(SW_BODY, headers, swOptions())).toMatchObject({
      ok: true,
    });
  });

  it("accepts a secret without the whsec_ prefix and raw key bytes", async () => {
    const key = Buffer.from("secret");
    const viaText = sign("b", "c2VjcmV0", presets.standardWebhooks, {
      timestamp: 5,
      id: "m",
    });
    const viaBytes = sign("b", key, presets.standardWebhooks, {
      timestamp: 5,
      id: "m",
    });
    const expected = createHmac("sha256", key).update("m.5.b").digest("base64");
    expect(viaText["webhook-signature"]).toBe(`v1,${expected}`);
    expect(viaBytes).toEqual(viaText);
  });

  it.each([
    ["fractional", "1614265330.5"],
    ["plus sign", "+1614265330"],
    ["empty", ""],
    ["16 digits", "1234567890123456"],
    ["letters", "abc"],
    ["leading space", " 1614265330"],
  ])("rejects a %s timestamp as malformed", async (_label, value) => {
    const headers = swHeaders({ "webhook-timestamp": value });
    expect(await verify(SW_BODY, headers, swOptions())).toEqual({
      ok: false,
      reason: "malformed_header",
    });
  });

  it("rejects malformed signature headers", async () => {
    const bad = [
      "",
      "v1a,xyz",
      "v2,abc",
      "v1",
      "v1,",
      "v1,!!!!",
      "v1,AAA",
      "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OF=",
      `${SW_SIG} v1`,
      Array.from({ length: 33 }, () => SW_SIG).join(" "),
      "v".repeat(9000),
    ];
    for (const value of bad) {
      const headers = swHeaders({ "webhook-signature": value });
      expect(await verify(SW_BODY, headers, swOptions())).toEqual({
        ok: false,
        reason: "malformed_header",
      });
    }
  });

  it("rejects empty, oversized and array ids", async () => {
    for (const id of ["", "m".repeat(257), [SW_ID]]) {
      const headers = swHeaders({ "webhook-id": id });
      expect(await verify(SW_BODY, headers, swOptions())).toEqual({
        ok: false,
        reason: "malformed_header",
      });
    }
  });

  it("reports missing headers", async () => {
    const headers = swHeaders({ "webhook-id": undefined });
    expect(await verify(SW_BODY, headers, swOptions())).toEqual({
      ok: false,
      reason: "missing_header",
    });
  });

  it("returns signature_mismatch for a 31 byte signature without throwing", async () => {
    const short = Buffer.alloc(31, 7).toString("base64");
    const headers = swHeaders({ "webhook-signature": `v1,${short}` });
    expect(await verify(SW_BODY, headers, swOptions())).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  it("binds the id and the timestamp to the signature", async () => {
    const otherId = swHeaders({ "webhook-id": "msg_other" });
    expect(await verify(SW_BODY, otherId, swOptions())).toMatchObject({
      ok: false,
      reason: "signature_mismatch",
    });
    const otherTs = swHeaders({ "webhook-timestamp": "1614265331" });
    expect(await verify(SW_BODY, otherTs, swOptions())).toMatchObject({
      ok: false,
      reason: "signature_mismatch",
    });
  });
});

describe("acceptance literals", () => {
  const sig = "248a374f50f943a28b0f6ab50faf9a7e7e29b710fa26df9fb1618b9bf8ea9c9a";
  const opts = {
    secrets: ["whsec_test_secret"],
    scheme: presets.stripeStyle,
    clock: () => 1700000000 * 1000,
  };

  it("verifies stripe headers verbatim; tampered body returns reason ' returns reason '", async () => {
    for (const h of [
      "t=1700000000,v1=248a374f50f943a28b0f6ab50faf9a7e7e29b710fa26df9fb1618b9bf8ea9c9a",
      "t=1700000000,v0=abc,v1=248a374f50f943a28b0f6ab50faf9a7e7e29b710fa26df9fb1618b9bf8ea9c9a",
    ]) {
      expect(await verify('{"id":"evt_1"}', { "stripe-signature": h }, opts)).toMatchObject({
        ok: true,
      });
    }
    expect(sig).toHaveLength(64);
  });

  it("verifies the Standard Webhooks vector", async () => {
    const result = await verify(
      '{"test": 2432232314}',
      {
        "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
        "webhook-timestamp": "1614265330",
        "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
      },
      {
        secrets: ["whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"],
        scheme: presets.standardWebhooks,
        clock: () => 1614265330 * 1000,
      },
    );
    expect(result.ok).toBe(true);
  });
});

describe("Stripe-style preset", () => {
  it("verifies the derived vector", async () => {
    const header = `t=1700000000,v1=${ST_HEX}`;
    expect(await verify(ST_BODY, { "stripe-signature": header }, stOptions())).toEqual({
      ok: true,
      timestamp: ST_TS,
    });
  });

  it("ignores v0 entries, unknown keys and accepts uppercase hex", async () => {
    const headers = [
      `t=1700000000,v0=abc,v1=${ST_HEX}`,
      `t=1700000000,foo=bar,v1=${ST_HEX}`,
      `t=1700000000,v1=${ST_HEX.toUpperCase()}`,
      `v1=${ST_HEX},t=1700000000`,
    ];
    for (const header of headers) {
      expect(await verify(ST_BODY, { "stripe-signature": header }, stOptions())).toMatchObject({
        ok: true,
      });
    }
  });

  it("rejects another body with signature_mismatch", async () => {
    const header = `t=1700000000,v1=${ST_HEX}`;
    expect(await verify('{"id":"evt_2"}', { "stripe-signature": header }, stOptions())).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  it.each([
    ["no t", `v1=${ST_HEX}`],
    ["no v1", "t=1700000000"],
    ["only v0", "t=1700000000,v0=abc"],
    ["duplicate t", `t=1700000000,t=1700000001,v1=${ST_HEX}`],
    ["t with suffix", `t=1700000000x,v1=${ST_HEX}`],
    ["t with 16 digits", `t=1234567890123456,v1=${ST_HEX}`],
    ["negative t", `t=-1,v1=${ST_HEX}`],
    ["short v1", `t=1700000000,v1=${ST_HEX.slice(1)}`],
    ["long v1", `t=1700000000,v1=${ST_HEX}0`],
    ["pair without equals", "t=1700000000,v1"],
    ["empty key", `=abc,t=1700000000,v1=${ST_HEX}`],
    ["empty pair", `t=1700000000,,v1=${ST_HEX}`],
    ["empty header", ""],
    ["too many v1", `t=1700000000,${Array.from({ length: 33 }, () => `v1=${ST_HEX}`).join(",")}`],
    ["oversized header", "x".repeat(9000)],
  ])("rejects %s as malformed", async (_label, header) => {
    expect(await verify(ST_BODY, { "stripe-signature": header }, stOptions())).toEqual({
      ok: false,
      reason: "malformed_header",
    });
  });

  it("rejects array header values", async () => {
    const header = `t=1700000000,v1=${ST_HEX}`;
    expect(await verify(ST_BODY, { "stripe-signature": [header] }, stOptions())).toEqual({
      ok: false,
      reason: "malformed_header",
    });
  });
});

describe("timestamp tolerance", () => {
  const signed = sign(ST_BODY, ST_SECRET, presets.stripeStyle, {
    timestamp: ST_TS,
  });

  it("accepts exactly 300 seconds either way", async () => {
    for (const delta of [-300, 0, 300]) {
      const result = await verify(
        ST_BODY,
        signed,
        stOptions({
          toleranceSeconds: 300,
          clock: () => (ST_TS + delta) * 1000,
        }),
      );
      expect(result).toEqual({ ok: true, timestamp: ST_TS });
    }
  });

  it("rejects 301 seconds either way", async () => {
    for (const delta of [-301, 301]) {
      const result = await verify(
        ST_BODY,
        signed,
        stOptions({
          toleranceSeconds: 300,
          clock: () => (ST_TS + delta) * 1000,
        }),
      );
      expect(result).toEqual({
        ok: false,
        reason: "timestamp_out_of_range",
      });
    }
  });

  it("applies to Standard Webhooks and fails closed on a broken clock", async () => {
    const stale = swOptions({
      toleranceSeconds: 300,
      clock: () => 1614265330 * 1000 + 301_000,
    });
    expect(await verify(SW_BODY, swHeaders(), stale)).toEqual({
      ok: false,
      reason: "timestamp_out_of_range",
    });
    const broken = swOptions({
      toleranceSeconds: 300,
      clock: () => Number.NaN,
    });
    expect(await verify(SW_BODY, swHeaders(), broken)).toEqual({
      ok: false,
      reason: "timestamp_out_of_range",
    });
  });

  it("does not apply to schemes without a timestamp", async () => {
    const result = await verify(
      GH_BODY,
      { "x-hub-signature-256": GH_SIG },
      ghOptions({ toleranceSeconds: 1, clock: () => 0 }),
    );
    expect(result).toEqual({ ok: true });
  });
});

describe("replay protection", () => {
  it("rejects a second delivery with the same id", async () => {
    let now = 1_000_000;
    const store = new MemoryReplayStore({ clock: () => now });
    const headers = sign(SW_BODY, SW_SECRET, presets.standardWebhooks, {
      timestamp: 1614265330,
      id: "msg_1",
    });
    const options = swOptions({ replayStore: store, toleranceSeconds: 300 });
    expect(await verify(SW_BODY, headers, options)).toMatchObject({
      ok: true,
    });
    expect(await verify(SW_BODY, headers, options)).toEqual({
      ok: false,
      reason: "replayed",
    });
    now += 2 * 300 * 1000 + 1;
    expect(await verify(SW_BODY, headers, options)).toMatchObject({
      ok: true,
    });
  });

  it("does not let a forged delivery burn the id of the genuine one", async () => {
    const store = new MemoryReplayStore();
    const options = swOptions({ replayStore: store });
    const forged = swHeaders({ "webhook-id": "msg_fresh" });
    expect(await verify(SW_BODY, forged, options)).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
    expect(store.size).toBe(0);
    const genuine = sign(SW_BODY, SW_SECRET, presets.standardWebhooks, {
      timestamp: 1614265330,
      id: "msg_fresh",
    });
    expect(await verify(SW_BODY, genuine, options)).toEqual({
      ok: true,
      timestamp: 1614265330,
      id: "msg_fresh",
    });
  });

  it("keys deliveries without an id by timestamp and signature", async () => {
    const store = new MemoryReplayStore();
    const headers = { "stripe-signature": `t=1700000000,v1=${ST_HEX}` };
    const options = stOptions({ replayStore: store });
    expect(await verify(ST_BODY, headers, options)).toMatchObject({ ok: true });
    expect(await verify(ST_BODY, headers, options)).toEqual({
      ok: false,
      reason: "replayed",
    });
  });

  it("uses the 86400 second default TTL without a timestamp", async () => {
    let now = 0;
    const store = new MemoryReplayStore({ clock: () => now });
    const headers = { "x-hub-signature-256": GH_SIG };
    const options = ghOptions({ replayStore: store });
    expect(await verify(GH_BODY, headers, options)).toEqual({ ok: true });
    now = 86_399_000;
    expect(await verify(GH_BODY, headers, options)).toEqual({
      ok: false,
      reason: "replayed",
    });
    now = 86_401_000;
    expect(await verify(GH_BODY, headers, options)).toEqual({ ok: true });
  });

  it("honours replayTtlSeconds", async () => {
    let now = 0;
    const store = new MemoryReplayStore({ clock: () => now });
    const headers = { "x-hub-signature-256": GH_SIG };
    const options = ghOptions({ replayStore: store, replayTtlSeconds: 10 });
    await verify(GH_BODY, headers, options);
    now = 11_000;
    expect(await verify(GH_BODY, headers, options)).toEqual({ ok: true });
  });

  it("fails closed when the store is full", async () => {
    const store = new MemoryReplayStore({ maxEntries: 1 });
    await store.checkAndRemember("other", 60_000);
    const result = await verify(
      GH_BODY,
      { "x-hub-signature-256": GH_SIG },
      ghOptions({ replayStore: store }),
    );
    expect(result).toEqual({ ok: false, reason: "replay_store_full" });
  });

  it("fails closed on an unknown store answer and propagates store errors", async () => {
    const weird: ReplayStore = {
      checkAndRemember: async () => "weird" as unknown as "full",
    };
    const headers = { "x-hub-signature-256": GH_SIG };
    expect(await verify(GH_BODY, headers, ghOptions({ replayStore: weird }))).toEqual({
      ok: false,
      reason: "replay_store_full",
    });
    const broken: ReplayStore = {
      checkAndRemember: async () => {
        throw new Error("store down");
      },
    };
    await expect(verify(GH_BODY, headers, ghOptions({ replayStore: broken }))).rejects.toThrow(
      "store down",
    );
  });

  it("does not touch the store for rejected deliveries", async () => {
    const spy = vi.fn(async () => "new" as const);
    const store: ReplayStore = { checkAndRemember: spy };
    await verify(
      GH_BODY,
      { "x-hub-signature-256": `sha256=${"0".repeat(64)}` },
      ghOptions({ replayStore: store }),
    );
    await verify(GH_BODY, {}, ghOptions({ replayStore: store }));
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("MemoryReplayStore", () => {
  it("evicts expired keys before answering full", async () => {
    let now = 5_000;
    const store = new MemoryReplayStore({ clock: () => now, maxEntries: 2 });
    expect(await store.checkAndRemember("a", 1000)).toBe("new");
    expect(await store.checkAndRemember("b", 1000)).toBe("new");
    expect(await store.checkAndRemember("c", 1000)).toBe("full");
    expect(await store.checkAndRemember("a", 1000)).toBe("seen");
    now += 1001;
    expect(await store.checkAndRemember("c", 1000)).toBe("new");
    expect(store.size).toBe(1);
  });

  it("re-admits an expired key and keeps live keys while sweeping", async () => {
    let now = 0;
    const store = new MemoryReplayStore({ clock: () => now, maxEntries: 2 });
    await store.checkAndRemember("short", 10);
    await store.checkAndRemember("long", 1000);
    now = 11;
    expect(await store.checkAndRemember("x", 1000)).toBe("new");
    expect(await store.checkAndRemember("long", 1000)).toBe("seen");
    expect(await store.checkAndRemember("y", 1000)).toBe("full");
    now = 20;
    expect(await store.checkAndRemember("short", 10)).toBe("full");
    now = 2000;
    expect(await store.checkAndRemember("short", 10)).toBe("new");
  });

  it("works with the default clock and limit", async () => {
    const store = new MemoryReplayStore();
    expect(await store.checkAndRemember("k", 1000)).toBe("new");
    expect(await store.checkAndRemember("k", 1000)).toBe("seen");
  });

  it("validates its inputs", async () => {
    expect(() => new MemoryReplayStore({ maxEntries: 0 })).toThrow(WebhookConfigError);
    expect(() => new MemoryReplayStore({ maxEntries: 1.5 })).toThrow(WebhookConfigError);
    const store = new MemoryReplayStore();
    await expect(store.checkAndRemember("", 1)).rejects.toBeInstanceOf(WebhookConfigError);
    await expect(store.checkAndRemember("k".repeat(1025), 1)).rejects.toBeInstanceOf(
      WebhookConfigError,
    );
    await expect(store.checkAndRemember("k", -1)).rejects.toBeInstanceOf(WebhookConfigError);
    await expect(store.checkAndRemember("k", Number.NaN)).rejects.toBeInstanceOf(
      WebhookConfigError,
    );
  });
});

describe("key rotation", () => {
  const body = ST_BODY;
  const header = (...secrets: string[]): Headers => ({
    "stripe-signature": `t=${ST_TS},${secrets
      .map((s) => `v1=${stripeHmac(s, ST_TS, body)}`)
      .join(",")}`,
  });
  const options = stOptions({ secrets: ["old-secret", "new-secret"] });

  it("accepts a second signature that matches only the second secret", async () => {
    expect(await verify(body, header("ancient", "new-secret"), options)).toEqual({
      ok: true,
      timestamp: ST_TS,
    });
    expect(await verify(body, header("old-secret"), options)).toMatchObject({
      ok: true,
    });
  });

  it("rejects signatures matching neither secret", async () => {
    expect(await verify(body, header("ancient", "other"), options)).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  it("compares every secret against every signature without early exit", async () => {
    const result = await verify(body, header("old-secret", "new-secret"), options);
    expect(result).toMatchObject({ ok: true });
    expect(vi.mocked(timingSafeEqual)).toHaveBeenCalledTimes(4);
  });

  it("does not call the comparison for wrong-length signatures", async () => {
    const short = Buffer.alloc(31, 7).toString("base64");
    await verify(SW_BODY, swHeaders({ "webhook-signature": `v1,${short}` }), swOptions());
    expect(vi.mocked(timingSafeEqual)).not.toHaveBeenCalled();
  });

  it("rejects signatures differing in only the first or last byte", async () => {
    const genuine = Buffer.from(GH_HEX, "hex");
    for (const index of [0, 31]) {
      const flipped = Buffer.from(genuine);
      flipped[index] = (flipped[index] ?? 0) ^ 1;
      const headers = {
        "x-hub-signature-256": `sha256=${flipped.toString("hex")}`,
      };
      expect(await verify(GH_BODY, headers, ghOptions())).toEqual({
        ok: false,
        reason: "signature_mismatch",
      });
    }
  });
});

describe("body size limit", () => {
  it("rejects maxBodyBytes + 1 bytes before computing any HMAC", async () => {
    const spy = vi.fn(presets.githubStyle.signedPayload);
    const scheme: Scheme = { ...presets.githubStyle, signedPayload: spy };
    const headers = { "x-hub-signature-256": GH_SIG };
    const options = ghOptions({ scheme, maxBodyBytes: 10 });
    expect(await verify(new Uint8Array(11), headers, options)).toEqual({
      ok: false,
      reason: "body_too_large",
    });
    expect(await verify("\u00e9".repeat(6), headers, options)).toEqual({
      ok: false,
      reason: "body_too_large",
    });
    expect(spy).not.toHaveBeenCalled();
    expect(vi.mocked(timingSafeEqual)).not.toHaveBeenCalled();
  });

  it("accepts a body of exactly maxBodyBytes", async () => {
    const headers = sign("0123456789", GH_SECRET, presets.githubStyle);
    const result = await verify("0123456789", headers, ghOptions({ maxBodyBytes: 10 }));
    expect(result).toEqual({ ok: true });
  });

  it("applies a default limit of 1048576 bytes", async () => {
    const headers = { "x-hub-signature-256": GH_SIG };
    expect(await verify(new Uint8Array(1_048_577), headers, ghOptions())).toEqual({
      ok: false,
      reason: "body_too_large",
    });
  });
});

describe("configuration errors", () => {
  const headers = { "x-hub-signature-256": GH_SIG };
  const make = (extra: object): VerifyOptions =>
    ({
      secrets: [GH_SECRET],
      scheme: presets.githubStyle,
      ...extra,
    }) as unknown as VerifyOptions;

  it.each([
    ["empty secrets", { secrets: [] }],
    ["secrets not an array", { secrets: "x" }],
    ["empty secret", { secrets: [""] }],
    ["empty byte secret", { secrets: [new Uint8Array(0)] }],
    ["numeric secret", { secrets: [42] }],
    ["too many secrets", { secrets: Array.from({ length: 17 }, () => "s") }],
    ["negative tolerance", { toleranceSeconds: -1 }],
    ["NaN tolerance", { toleranceSeconds: Number.NaN }],
    ["zero maxBodyBytes", { maxBodyBytes: 0 }],
    ["fractional maxBodyBytes", { maxBodyBytes: 1.5 }],
    ["zero replay ttl", { replayTtlSeconds: 0 }],
    ["non-function clock", { clock: "now" }],
    ["bad store", { replayStore: {} }],
    ["missing scheme", { scheme: undefined }],
  ])("rejects %s", async (_label, extra) => {
    const promise = verify(GH_BODY, headers, make(extra));
    await expect(promise).rejects.toBeInstanceOf(WebhookConfigError);
    await expect(promise).rejects.toMatchObject({ code: "invalid_options" });
  });

  it("rejects non-base64 whsec_ secrets without echoing them", async () => {
    const options = swOptions({ secrets: ["whsec_!!!secret-value"] });
    const error = await verify(SW_BODY, swHeaders(), options).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(WebhookConfigError);
    expect((error as Error).message).not.toContain("secret-value");
    expect((error as Error).name).toBe("WebhookConfigError");
  });

  it("rejects null options, bad bodies and bad headers", async () => {
    await expect(verify(GH_BODY, headers, null as unknown as VerifyOptions)).rejects.toBeInstanceOf(
      WebhookConfigError,
    );
    await expect(verify({} as unknown as string, headers, ghOptions())).rejects.toBeInstanceOf(
      WebhookConfigError,
    );
    await expect(verify(GH_BODY, null as unknown as Headers, ghOptions())).rejects.toBeInstanceOf(
      WebhookConfigError,
    );
    await expect(verify(GH_BODY, [] as unknown as Headers, ghOptions())).rejects.toBeInstanceOf(
      WebhookConfigError,
    );
  });
});

describe("sign", () => {
  it("reproduces the published vectors", () => {
    expect(sign(GH_BODY, GH_SECRET, presets.githubStyle)).toEqual({
      "X-Hub-Signature-256": GH_SIG,
    });
    expect(
      sign(SW_BODY, SW_SECRET, presets.standardWebhooks, {
        timestamp: 1614265330,
        id: SW_ID,
      }),
    ).toEqual({
      "webhook-id": SW_ID,
      "webhook-timestamp": SW_TS,
      "webhook-signature": SW_SIG,
    });
    expect(sign(ST_BODY, ST_SECRET, presets.stripeStyle, { timestamp: ST_TS })).toEqual({
      "Stripe-Signature": `t=1700000000,v1=${ST_HEX}`,
    });
  });

  it("adds the delivery id for GitHub and round-trips", async () => {
    const headers = sign(GH_BODY, GH_SECRET, presets.githubStyle, {
      id: "d-1",
    });
    expect(headers["X-GitHub-Delivery"]).toBe("d-1");
    expect(await verify(GH_BODY, headers, ghOptions())).toEqual({
      ok: true,
      id: "d-1",
    });
  });

  it("signs Uint8Array bodies", () => {
    const bytes = new TextEncoder().encode(GH_BODY);
    expect(sign(bytes, GH_SECRET, presets.githubStyle)).toEqual(
      sign(GH_BODY, GH_SECRET, presets.githubStyle),
    );
  });

  it("rejects invalid parameters", () => {
    const std = presets.standardWebhooks;
    expect(() => sign("b", SW_SECRET, std)).toThrow(WebhookConfigError);
    expect(() => sign("b", SW_SECRET, std, { id: "m" })).toThrow(WebhookConfigError);
    expect(() => sign("b", SW_SECRET, std, { timestamp: 1 })).toThrow(WebhookConfigError);
    expect(() => sign("b", ST_SECRET, presets.stripeStyle)).toThrow(WebhookConfigError);
    for (const timestamp of [-1, 1.5, 1e15, Number.NaN]) {
      expect(() => sign("b", ST_SECRET, presets.stripeStyle, { timestamp })).toThrow(
        WebhookConfigError,
      );
    }
    for (const id of ["", "m".repeat(257)]) {
      expect(() => sign("b", GH_SECRET, presets.githubStyle, { id })).toThrow(WebhookConfigError);
    }
    expect(() => sign(5 as unknown as string, GH_SECRET, presets.githubStyle)).toThrow(
      WebhookConfigError,
    );
  });
});

describe("scheme helpers", () => {
  const none = (): undefined => undefined;

  it("reports absent data without throwing", () => {
    expect(presets.githubStyle.parseTimestamp(none)).toBeUndefined();
    expect(presets.githubStyle.parseId(() => ["a"])).toBeUndefined();
    expect(presets.githubStyle.parseId(() => "")).toBeUndefined();
    expect(presets.githubStyle.parseSignatures(none)).toBeNull();
    expect(presets.standardWebhooks.parseId(none)).toBeUndefined();
    expect(presets.standardWebhooks.parseSignatures(none)).toBeNull();
    expect(presets.standardWebhooks.parseTimestamp(none)).toBeNull();
    expect(presets.standardWebhooks.parseTimestampText?.(none)).toBeUndefined();
    expect(presets.stripeStyle.parseId(none)).toBeUndefined();
    expect(presets.stripeStyle.parseTimestamp(none)).toBeNull();
    expect(presets.stripeStyle.parseTimestampText?.(none)).toBeUndefined();
  });

  it("validates signed payload inputs and secrets", () => {
    const body = new Uint8Array(1);
    expect(() => presets.stripeStyle.signedPayload({ body })).toThrow(WebhookConfigError);
    expect(() => presets.standardWebhooks.signedPayload({ body })).toThrow(WebhookConfigError);
    expect(() => presets.standardWebhooks.decodeSecret("whsec_!!")).toThrow(WebhookConfigError);
    expect(() => presets.stripeStyle.decodeSecret(new Uint8Array(0))).toThrow(WebhookConfigError);
    const key = new Uint8Array([1, 2]);
    expect(presets.standardWebhooks.decodeSecret(key)).toBe(key);
  });

  it("exposes frozen presets with stable names", () => {
    expect(Object.isFrozen(presets)).toBe(true);
    expect(presets.githubStyle.name).toBe("github");
    expect(presets.standardWebhooks.name).toBe("standard-webhooks");
    expect(presets.stripeStyle.name).toBe("stripe");
  });
});
