/**
 * Staged errors — every DarkPool SDK error carries a `stage` string so callers
 * can implement stage-specific recovery (per Appendix C.7 of the spec).
 *
 * Adopted stages:
 *   "attestation-verify"   — non-retryable. Abort immediately. Never ship order data.
 *   "auth-token-fetch"     — retryable with new JWT.
 *   "note-lock-check"      — the note is locked/consumed. Do not retry; pick another.
 *   "merkle-proof-fetch"   — indexer unreachable; retry.
 *   "proof-generation"     — client-side ZK failure (usually witness invalid).
 *   "transaction-send"     — Solana RPC error; safe to retry after checking nullifier state.
 *   "transaction-validate" — tx was sent but rejected; re-fetch Merkle root and retry.
 *   "instruction-build"    — logic error in SDK or user-supplied params.
 */
export type DarkPoolErrorStage =
  | "attestation-verify"
  | "auth-token-fetch"
  | "note-lock-check"
  | "merkle-proof-fetch"
  | "proof-generation"
  | "transaction-send"
  | "transaction-validate"
  | "instruction-build";

export class DarkPoolError extends Error {
  readonly stage: DarkPoolErrorStage;
  readonly cause?: unknown;

  constructor(stage: DarkPoolErrorStage, message: string, cause?: unknown) {
    super(`[${stage}] ${message}`);
    this.name = "DarkPoolError";
    this.stage = stage;
    this.cause = cause;
  }

  static isRetryable(err: unknown): boolean {
    if (!(err instanceof DarkPoolError)) return false;
    switch (err.stage) {
      case "auth-token-fetch":
      case "merkle-proof-fetch":
      case "transaction-send":
      case "transaction-validate":
        return true;
      case "attestation-verify":
      case "note-lock-check":
      case "proof-generation":
      case "instruction-build":
        return false;
    }
  }
}
