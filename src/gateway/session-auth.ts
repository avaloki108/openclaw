import crypto from "node:crypto";

/** Maximum failed PIN attempts before lockout. */
const MAX_ATTEMPTS = 5;
/** Lockout duration after exceeding MAX_ATTEMPTS (5 minutes). */
const LOCKOUT_MS = 5 * 60 * 1000;

/** Separator used in subagent session keys to identify the parent. */
const SUBAGENT_SEPARATOR = ":subagent:";

type AuthState = {
  verified: boolean;
  attempts: number;
  /** Unix timestamp (ms) after which the lockout expires, if set. */
  lockedUntil?: number;
};

/** Map from canonical auth key (always parent session key for subagents) → state. */
const authStates = new Map<string, AuthState>();

/**
 * Map from session key → encoded PIN buffer.
 * Sub-agents are not registered here; they inherit via the parent key.
 */
const pinRegistry = new Map<string, Buffer>();

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * For a subagent session key like `<parent>:subagent:<id>`, return `<parent>`.
 * Handles deeper nesting by finding the first occurrence.
 * Returns undefined for non-subagent keys.
 */
function extractParentSessionKey(sessionKey: string): string | undefined {
  const idx = sessionKey.toLowerCase().indexOf(SUBAGENT_SEPARATOR);
  if (idx === -1) {
    return undefined;
  }
  return sessionKey.slice(0, idx);
}

/**
 * Walk up the subagent chain to find the canonical session key that has a
 * PIN registered, or return the key itself if no parent is found.
 */
function resolveAuthKey(sessionKey: string): string {
  const parent = extractParentSessionKey(sessionKey);
  if (parent === undefined) {
    return sessionKey;
  }
  // Parent is always the auth key — subagents inherit parent's auth state.
  return resolveAuthKey(parent);
}

/** Return the expected PIN buffer for this session key (or its ancestor). */
function resolveExpectedPin(sessionKey: string): Buffer | undefined {
  const authKey = resolveAuthKey(sessionKey);
  return pinRegistry.get(authKey);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Register a PIN for a session key.
 * Call this when the agent session is initialized (on tool creation) if the
 * config contains `session.auth.pin`.  Safe to call multiple times; the most
 * recent value wins.
 */
export function registerSessionPin(sessionKey: string, pin: string): void {
  // Store the PIN as a buffer for timingSafeEqual comparisons.
  pinRegistry.set(sessionKey, Buffer.from(pin, "utf8"));
}

/**
 * Remove all auth state and PIN registration for a session key.
 * Call on session reset or cleanup.
 */
export function unregisterSessionPin(sessionKey: string): void {
  const authKey = resolveAuthKey(sessionKey);
  pinRegistry.delete(authKey);
  authStates.delete(authKey);
}

/** Whether a PIN has been registered for this session key (or its parent). */
export function isSessionPinRequired(sessionKey: string): boolean {
  return resolveExpectedPin(sessionKey) !== undefined;
}

/**
 * Whether the session has been successfully verified this process lifetime.
 * Sub-agents inherit their parent's verified state.
 */
export function isSessionVerified(sessionKey: string): boolean {
  const authKey = resolveAuthKey(sessionKey);
  return authStates.get(authKey)?.verified === true;
}

export type VerifyPinResult =
  | { ok: true }
  | { ok: false; locked: true; remainingMs: number }
  | { ok: false; locked: false; attemptsLeft: number };

/**
 * Attempt to verify the session PIN.
 * - Uses `crypto.timingSafeEqual` — PIN never enters LLM context or logs.
 * - After MAX_ATTEMPTS failures, imposes a LOCKOUT_MS lockout.
 */
export function verifySessionPin(sessionKey: string, candidatePin: string): VerifyPinResult {
  const expectedPin = resolveExpectedPin(sessionKey);
  if (!expectedPin) {
    // No PIN configured — treat as open (gate should not have called this).
    return { ok: true };
  }

  const authKey = resolveAuthKey(sessionKey);
  const state: AuthState = authStates.get(authKey) ?? { verified: false, attempts: 0 };

  // Check lockout.
  if (state.lockedUntil !== undefined && Date.now() < state.lockedUntil) {
    authStates.set(authKey, state);
    return { ok: false, locked: true, remainingMs: state.lockedUntil - Date.now() };
  }

  // Constant-time comparison: buffers must be the same length.
  const candidateBuf = Buffer.from(candidatePin, "utf8");
  const lengthMatch = expectedPin.length === candidateBuf.length;
  // Use a same-length zero buffer if lengths differ so timingSafeEqual never throws.
  const compareBuf = lengthMatch ? candidateBuf : Buffer.alloc(expectedPin.length);
  const pinMatch = crypto.timingSafeEqual(expectedPin, compareBuf) && lengthMatch;

  if (pinMatch) {
    authStates.set(authKey, { verified: true, attempts: 0 });
    return { ok: true };
  }

  // Failed attempt.
  const newAttempts = state.attempts + 1;
  const nowLocked = newAttempts >= MAX_ATTEMPTS;
  const newState: AuthState = {
    verified: false,
    attempts: newAttempts,
    lockedUntil: nowLocked ? Date.now() + LOCKOUT_MS : state.lockedUntil,
  };
  authStates.set(authKey, newState);

  if (nowLocked) {
    return { ok: false, locked: true, remainingMs: LOCKOUT_MS };
  }
  return { ok: false, locked: false, attemptsLeft: MAX_ATTEMPTS - newAttempts };
}

// ---------------------------------------------------------------------------
// Test helpers (not exported from the public surface in production)
// ---------------------------------------------------------------------------
export const __testing = {
  authStates,
  pinRegistry,
  resolveAuthKey,
  MAX_ATTEMPTS,
  LOCKOUT_MS,
};
