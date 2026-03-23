import { Type } from "@sinclair/typebox";
import { verifySessionPin } from "../../gateway/session-auth.js";
import { type AnyAgentTool, jsonResult } from "./common.js";

const SessionVerifyPinSchema = Type.Object(
  {
    /**
     * The PIN to verify.  This value is NEVER echoed in tool outputs or logs.
     * It is compared using crypto.timingSafeEqual and then discarded.
     */
    pin: Type.String({ description: "The PIN to verify for this session." }),
  },
  { additionalProperties: true },
);

export type SessionVerifyPinOptions = {
  sessionKey?: string;
};

export function createSessionVerifyPinTool(options?: SessionVerifyPinOptions): AnyAgentTool {
  return {
    name: "session_verify_pin",
    description:
      "Verify the session PIN to unlock tool use. " +
      "Call this with the PIN the user provides before attempting any other tool. " +
      "The PIN is never stored or echoed.",
    parameters: SessionVerifyPinSchema,
    execute: async (_toolCallId, params) => {
      const p = params as { pin?: unknown };

      // Read the PIN without logging or forwarding it.
      const candidate = typeof p?.pin === "string" ? p.pin : "";

      const sessionKey = options?.sessionKey ?? "";
      if (!sessionKey) {
        return jsonResult({ success: false, message: "No active session to verify." });
      }

      const result = verifySessionPin(sessionKey, candidate);

      if (result.ok) {
        return jsonResult({ success: true, message: "PIN verified. Tools are now unlocked." });
      }

      if (result.locked) {
        const minutes = Math.ceil(result.remainingMs / 60_000);
        return jsonResult({
          success: false,
          locked: true,
          message: `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
        });
      }

      const left = result.attemptsLeft;
      return jsonResult({
        success: false,
        locked: false,
        message: `Incorrect PIN. ${left} attempt${left === 1 ? "" : "s"} remaining.`,
      });
    },
  };
}
