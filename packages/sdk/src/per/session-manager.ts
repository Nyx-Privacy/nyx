/**
 * PER Session Manager.
 *
 * Responsibilities (spec §20.5 step 67 + §23.3.1):
 *   - Fetch a JWT bearer token from the TEE via signed-nonce handshake.
 *   - Cache the JWT in memory; refresh on 401 from the TEE.
 *   - Expose a `sendInstruction(ix, jwt, params)` method that posts the tx
 *     to the TEE's PER RPC endpoint with `Authorization: Bearer {jwt}`.
 *
 * The live implementation is fully agnostic to MagicBlock internals — we talk
 * plain JSON-RPC + Ed25519 signatures. This makes the class trivially
 * mockable (see `MockPerSessionManager`) and keeps the SDK footprint small.
 */

import type {
  TransactionInstruction,
  TransactionSignature,
} from "@solana/web3.js";

import type { AttestationVerifier } from "./attestation.js";
import { defaultAttestationVerifier } from "./attestation.js";
import { DarkPoolError } from "../errors.js";

/** Callback: sign a 32-byte challenge nonce with the Trading Key. */
export type SignNonceFn = (nonce: Uint8Array) => Promise<Uint8Array>;

export interface AuthTokenResponse {
  token: string;
  /** Epoch ms at which the token expires. Optional; we refresh on 401 anyway. */
  expiresAt?: number;
}

export interface OrderSubmitContext {
  /** Used by implementations to attach the correct Solana-side signer. */
  traderPubkey: Uint8Array;
}

export interface IPerSessionManager {
  /** Verify the TEE attestation quote. Must be invoked before any order data. */
  verifyAttestation(): Promise<boolean>;
  /** Return the current JWT, fetching one if missing. */
  getToken(): Promise<string>;
  /** Invalidate the cached JWT (e.g., on 401). */
  invalidateToken(): void;
  /**
   * Send a signed instruction + transaction to the PER RPC. On 401, the
   * manager is expected to refresh the JWT and retry exactly once.
   */
  sendInstruction(
    ix: TransactionInstruction,
    jwt: string,
    ctx: OrderSubmitContext,
  ): Promise<TransactionSignature>;
}

export interface LivePerSessionManagerOptions {
  perRpcUrl: string;
  traderPubkey: Uint8Array;
  signNonce: SignNonceFn;
  attestationVerifier?: AttestationVerifier;
  /** Override fetch for tests / non-browser runtimes. */
  fetchImpl?: typeof fetch;
}

export class LivePerSessionManager implements IPerSessionManager {
  private readonly perRpcUrl: string;
  private readonly traderPubkey: Uint8Array;
  private readonly signNonce: SignNonceFn;
  private readonly attestationVerifier: AttestationVerifier;
  private readonly fetchImpl: typeof fetch;
  private cachedToken: string | null = null;

  constructor(opts: LivePerSessionManagerOptions) {
    this.perRpcUrl = opts.perRpcUrl.replace(/\/$/, "");
    this.traderPubkey = opts.traderPubkey;
    this.signNonce = opts.signNonce;
    this.attestationVerifier =
      opts.attestationVerifier ?? defaultAttestationVerifier();
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  verifyAttestation(): Promise<boolean> {
    return this.attestationVerifier(this.perRpcUrl);
  }

  async getToken(): Promise<string> {
    if (this.cachedToken) return this.cachedToken;
    const token = await this.fetchNewToken();
    this.cachedToken = token;
    return token;
  }

  invalidateToken(): void {
    this.cachedToken = null;
  }

  async sendInstruction(
    ix: TransactionInstruction,
    jwt: string,
    _ctx: OrderSubmitContext,
  ): Promise<TransactionSignature> {
    // Serialise the ix bytes directly; the real TEE re-wraps them in a tx with
    // its own blockhash before forwarding to L1. Phase 3 does not need a
    // recent blockhash on the client (we cannot fetch one from the PER RPC
    // before auth anyway — chicken and egg). The mock TEE accepts any body.
    const ixBytes = Buffer.concat([
      ix.programId.toBuffer(),
      Buffer.from(ix.data),
    ]);
    const body = {
      jsonrpc: "2.0",
      id: 1,
      method: "submitOrderIx",
      params: [ixBytes.toString("base64"), { encoding: "base64" }],
    };
    const res = await this.fetchImpl(`${this.perRpcUrl}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${jwt}`,
      },
      body: JSON.stringify(body),
    });
    if (res.status === 401) {
      this.invalidateToken();
      throw new DarkPoolError("auth-token-fetch", "JWT expired / rejected");
    }
    if (!res.ok) {
      throw new DarkPoolError(
        "transaction-send",
        `PER RPC returned ${res.status}`,
      );
    }
    const json = (await res.json()) as { result?: string; error?: unknown };
    if (json.error) {
      throw new DarkPoolError(
        "transaction-send",
        `PER RPC error: ${JSON.stringify(json.error)}`,
      );
    }
    if (!json.result) {
      throw new DarkPoolError("transaction-send", "PER RPC empty result");
    }
    return json.result;
  }

  private async fetchNewToken(): Promise<string> {
    // 1. Fetch a challenge nonce from the TEE.
    const nonceRes = await this.fetchImpl(`${this.perRpcUrl}/auth/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pubkey: Array.from(this.traderPubkey) }),
    });
    if (!nonceRes.ok) {
      throw new DarkPoolError(
        "auth-token-fetch",
        `challenge fetch failed: ${nonceRes.status}`,
      );
    }
    const nonceJson = (await nonceRes.json()) as { nonce: number[] };
    const nonce = new Uint8Array(nonceJson.nonce);

    // 2. Sign the nonce with the Trading Key.
    const sig = await this.signNonce(nonce);

    // 3. POST signature → receive JWT.
    const tokRes = await this.fetchImpl(`${this.perRpcUrl}/auth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        pubkey: Array.from(this.traderPubkey),
        nonce: Array.from(nonce),
        signature: Array.from(sig),
      }),
    });
    if (!tokRes.ok) {
      throw new DarkPoolError(
        "auth-token-fetch",
        `token exchange failed: ${tokRes.status}`,
      );
    }
    const tokJson = (await tokRes.json()) as AuthTokenResponse;
    if (!tokJson.token) {
      throw new DarkPoolError("auth-token-fetch", "no token in response");
    }
    return tokJson.token;
  }
}

/** Deterministic mock session manager for unit tests. */
export class MockPerSessionManager implements IPerSessionManager {
  public attestationOk = true;
  public fixedToken: string = "mock_jwt_ok";
  public tokenFetchCount = 0;
  public sendCallCount = 0;
  public injectNext401 = false;
  public injectNextFailure: DarkPoolError | null = null;
  /** Caller inspects this after `sendInstruction` returns. */
  public lastIx: TransactionInstruction | null = null;
  public lastJwt: string | null = null;

  constructor(private readonly replySignature: string = "mock_sig_stub") {}

  async verifyAttestation(): Promise<boolean> {
    return this.attestationOk;
  }
  async getToken(): Promise<string> {
    this.tokenFetchCount += 1;
    return this.fixedToken;
  }
  invalidateToken(): void {
    // Rotate the token to simulate a refresh; callers that compare the
    // pre-401 and post-401 token values can detect the refresh.
    this.fixedToken = `${this.fixedToken}_refreshed_${this.tokenFetchCount}`;
  }
  async sendInstruction(
    ix: TransactionInstruction,
    jwt: string,
  ): Promise<TransactionSignature> {
    this.sendCallCount += 1;
    this.lastIx = ix;
    this.lastJwt = jwt;
    if (this.injectNextFailure) {
      const err = this.injectNextFailure;
      this.injectNextFailure = null;
      throw err;
    }
    if (this.injectNext401) {
      this.injectNext401 = false;
      this.invalidateToken();
      throw new DarkPoolError("auth-token-fetch", "mock 401");
    }
    return this.replySignature;
  }
}
