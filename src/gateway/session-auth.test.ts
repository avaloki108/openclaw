import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  __testing,
  isSessionPinRequired,
  isSessionVerified,
  registerSessionPin,
  unregisterSessionPin,
  verifySessionPin,
} from "./session-auth.js";

const { authStates, pinRegistry, resolveAuthKey, MAX_ATTEMPTS, LOCKOUT_MS } = __testing;

// Clear module-level maps before each test for isolation.
beforeEach(() => {
  authStates.clear();
  pinRegistry.clear();
});

// ---------------------------------------------------------------------------
// registerSessionPin / isSessionPinRequired
// ---------------------------------------------------------------------------
describe("registerSessionPin / isSessionPinRequired", () => {
  it("returns false when no PIN registered", () => {
    expect(isSessionPinRequired("telegram:123")).toBe(false);
  });

  it("returns true after registering a PIN", () => {
    registerSessionPin("telegram:123", "1234");
    expect(isSessionPinRequired("telegram:123")).toBe(true);
  });

  it("subagent inherits parent PIN requirement", () => {
    registerSessionPin("telegram:123", "1234");
    expect(isSessionPinRequired("telegram:123:subagent:abc")).toBe(true);
  });

  it("deeply nested subagent inherits PIN requirement", () => {
    registerSessionPin("telegram:123", "1234");
    expect(isSessionPinRequired("telegram:123:subagent:abc:subagent:xyz")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// resolveAuthKey
// ---------------------------------------------------------------------------
describe("resolveAuthKey", () => {
  it("returns the key itself for non-subagent keys", () => {
    expect(resolveAuthKey("telegram:123")).toBe("telegram:123");
  });

  it("returns the parent key for a subagent key", () => {
    expect(resolveAuthKey("telegram:123:subagent:abc")).toBe("telegram:123");
  });

  it("returns the root ancestor for deeply nested subagent keys", () => {
    expect(resolveAuthKey("telegram:123:subagent:abc:subagent:xyz")).toBe("telegram:123");
  });
});

// ---------------------------------------------------------------------------
// verifySessionPin — success path
// ---------------------------------------------------------------------------
describe("verifySessionPin — success", () => {
  it("returns ok:true for a correct PIN", () => {
    registerSessionPin("sk1", "secret");
    const result = verifySessionPin("sk1", "secret");
    expect(result.ok).toBe(true);
  });

  it("marks session as verified after success", () => {
    registerSessionPin("sk1", "secret");
    verifySessionPin("sk1", "secret");
    expect(isSessionVerified("sk1")).toBe(true);
  });

  it("subagent is verified after parent PIN verified", () => {
    registerSessionPin("sk1", "secret");
    verifySessionPin("sk1", "secret");
    expect(isSessionVerified("sk1:subagent:abc")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// verifySessionPin — failure path
// ---------------------------------------------------------------------------
describe("verifySessionPin — failures", () => {
  it("returns ok:false for wrong PIN", () => {
    registerSessionPin("sk1", "secret");
    const result = verifySessionPin("sk1", "wrong");
    expect(result.ok).toBe(false);
  });

  it("returns ok:false for different-length PIN", () => {
    registerSessionPin("sk1", "1234");
    const result = verifySessionPin("sk1", "12345");
    expect(result.ok).toBe(false);
  });

  it("tracks attemptsLeft correctly", () => {
    registerSessionPin("sk1", "secret");
    const r1 = verifySessionPin("sk1", "bad");
    expect(r1).toMatchObject({ ok: false, locked: false, attemptsLeft: MAX_ATTEMPTS - 1 });
    const r2 = verifySessionPin("sk1", "bad");
    expect(r2).toMatchObject({ ok: false, locked: false, attemptsLeft: MAX_ATTEMPTS - 2 });
  });

  it("does not verify session on failure", () => {
    registerSessionPin("sk1", "secret");
    verifySessionPin("sk1", "bad");
    expect(isSessionVerified("sk1")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting / lockout
// ---------------------------------------------------------------------------
describe("lockout after MAX_ATTEMPTS failures", () => {
  it("locks after MAX_ATTEMPTS failed attempts", () => {
    registerSessionPin("sk1", "secret");
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      verifySessionPin("sk1", "bad");
    }
    const result = verifySessionPin("sk1", "secret");
    expect(result).toMatchObject({ ok: false, locked: true });
  });

  it("returns remainingMs > 0 while locked", () => {
    registerSessionPin("sk1", "secret");
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      verifySessionPin("sk1", "bad");
    }
    const result = verifySessionPin("sk1", "secret");
    if (result.ok || !result.locked) {
      throw new Error("should be locked");
    }
    expect(result.remainingMs).toBeGreaterThan(0);
    expect(result.remainingMs).toBeLessThanOrEqual(LOCKOUT_MS);
  });

  it("unlocks after lockout expires", () => {
    vi.useFakeTimers();
    registerSessionPin("sk1", "secret");
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      verifySessionPin("sk1", "bad");
    }
    // Advance time past lockout.
    vi.advanceTimersByTime(LOCKOUT_MS + 1);
    const result = verifySessionPin("sk1", "secret");
    expect(result.ok).toBe(true);
    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// unregisterSessionPin
// ---------------------------------------------------------------------------
describe("unregisterSessionPin", () => {
  it("removes PIN and auth state", () => {
    registerSessionPin("sk1", "secret");
    verifySessionPin("sk1", "secret");
    expect(isSessionVerified("sk1")).toBe(true);
    unregisterSessionPin("sk1");
    expect(isSessionPinRequired("sk1")).toBe(false);
    expect(isSessionVerified("sk1")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// No PIN configured edge case
// ---------------------------------------------------------------------------
describe("no PIN configured", () => {
  it("verifySessionPin returns ok:true when no PIN is registered", () => {
    // Gate should prevent this, but guard against the edge case.
    const result = verifySessionPin("sk_no_pin", "anything");
    expect(result.ok).toBe(true);
  });
});
