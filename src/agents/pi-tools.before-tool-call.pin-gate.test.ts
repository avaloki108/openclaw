/**
 * Unit tests for the PIN auth gate in runBeforeToolCallHook.
 * Verifies that tool calls are blocked when a PIN is required and not verified,
 * and that session_verify_pin is always exempt from blocking.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { __testing as sessionAuthTesting } from "../gateway/session-auth.js";
import { __testing, runBeforeToolCallHook } from "./pi-tools.before-tool-call.js";

const { adjustedParamsByToolCallId } = __testing;
const { authStates, pinRegistry } = sessionAuthTesting;

// Reset shared state before each test.
beforeEach(() => {
  authStates.clear();
  pinRegistry.clear();
  adjustedParamsByToolCallId.clear();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

import { registerSessionPin, verifySessionPin } from "../gateway/session-auth.js";

const SESSION_KEY = "telegram:test_session";

function makeCtx(overrides?: { pinRequired?: boolean; sessionKey?: string }) {
  return {
    sessionKey: SESSION_KEY,
    pinRequired: true,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Gate: blocked when PIN required and not verified
// ---------------------------------------------------------------------------
describe("PIN gate — blocked before verification", () => {
  it("blocks arbitrary tool calls when pin is required and not verified", async () => {
    registerSessionPin(SESSION_KEY, "1234");
    const result = await runBeforeToolCallHook({
      toolName: "read",
      params: { path: "/tmp/foo" },
      ctx: makeCtx(),
    });
    expect(result.blocked).toBe(true);
    expect(result.reason).toMatch(/session is locked/i);
  });

  it("does NOT block session_verify_pin regardless of verification state", async () => {
    registerSessionPin(SESSION_KEY, "1234");
    const result = await runBeforeToolCallHook({
      toolName: "session_verify_pin",
      params: { pin: "1234" },
      ctx: makeCtx(),
    });
    expect(result.blocked).toBe(false);
  });

  it("blocks write tool before verification", async () => {
    registerSessionPin(SESSION_KEY, "abc");
    const result = await runBeforeToolCallHook({
      toolName: "write",
      params: { path: "/tmp/x", content: "y" },
      ctx: makeCtx(),
    });
    expect(result.blocked).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Gate: allowed after verification
// ---------------------------------------------------------------------------
describe("PIN gate — allowed after verification", () => {
  it("allows tool calls after successful PIN verification", async () => {
    registerSessionPin(SESSION_KEY, "1234");
    verifySessionPin(SESSION_KEY, "1234");

    const result = await runBeforeToolCallHook({
      toolName: "read",
      params: { path: "/tmp/foo" },
      ctx: makeCtx(),
    });
    expect(result.blocked).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Gate: no-op when PIN not required
// ---------------------------------------------------------------------------
describe("PIN gate — no-op when pinRequired is false", () => {
  it("does not block tools when pinRequired is false even if session has unverified PIN", async () => {
    registerSessionPin(SESSION_KEY, "1234");
    const result = await runBeforeToolCallHook({
      toolName: "read",
      params: {},
      ctx: makeCtx({ pinRequired: false }),
    });
    expect(result.blocked).toBe(false);
  });

  it("does not block when sessionKey is absent", async () => {
    registerSessionPin(SESSION_KEY, "1234");
    const result = await runBeforeToolCallHook({
      toolName: "read",
      params: {},
      ctx: { pinRequired: true, sessionKey: undefined },
    });
    // No sessionKey → gate cannot look up PIN → passes through.
    expect(result.blocked).toBe(false);
  });
});
