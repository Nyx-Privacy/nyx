/**
 * Phase 3 — order submission test suite (§23.3.3).
 *
 * Covers the TS-side half of the 12-test matrix:
 *   1.  test_attestation_failure_aborts
 *   2.  test_invalid_jwt_rejected_by_tee
 *   4.  test_order_for_locked_note_rejected
 *   5.  test_order_for_consumed_note_rejected
 *   7.  test_lock_note_called_on_acceptance          (SDK wiring half)
 *   8.  test_jwt_refresh_on_401
 *   9.  test_order_inclusion_commitment_returned
 *  12.  test_order_submit_staged_errors
 *
 * The on-chain half (tests 3, 6, 10, 11 — permission group, root-key,
 * phantom-note, notional) lives in `programs/matching_engine/tests/`.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";

import { DarkPoolClient, type NoteStatusInfo } from "../src/client.js";
import { DarkPoolError } from "../src/errors.js";
import { UnimplementedProverSuite } from "../src/zk/prover-suite.js";
import {
  MockPerSessionManager,
  LivePerSessionManager,
} from "../src/per/session-manager.js";
import {
  getOrderSubmitFunction,
  type OrderParams,
} from "../src/orders/submit-order.js";
import type {
  AccountInfoProvider,
  MasterSeedStorage,
  MerkleProofProvider,
  SolanaConnectionProvider,
  TransactionForwarder,
} from "../src/providers.js";
import { startMockTeeServer, type MockTeeServerHandle } from "./mocks/mock-tee-server.js";

const VAULT_PROGRAM_ID = new PublicKey(
  "ELt4FH2gH8RaZkYbvbbDjGkX8dPhGFdWnspM4w1fdjoY",
);
const ME_PROGRAM_ID = new PublicKey(
  "DvYcaiBuaHgJFVjVd57JLM7ZMavzXvBezJwsvA46FJbH",
);

function makeAccountInfoProvider(
  statuses: Map<string, { data: Buffer; owner: PublicKey } | null>,
): AccountInfoProvider {
  return {
    getAccountInfo: async (pk: PublicKey) => statuses.get(pk.toBase58()) ?? null,
  };
}

function makeClient(opts: {
  noteStatus?: NoteStatusInfo;
  accountInfoStatuses?: Map<string, { data: Buffer; owner: PublicKey } | null>;
  perRpcUrl?: string;
}): DarkPoolClient {
  const conn: SolanaConnectionProvider = {
    connection: {} as never,
    perRpcUrl: opts.perRpcUrl ?? "http://127.0.0.1:65535",
  };
  const storage: MasterSeedStorage = {
    load: async () => new Uint8Array(64),
    store: async () => {},
    generate: async () => new Uint8Array(64),
  };
  const statuses = opts.accountInfoStatuses ?? new Map();
  const providers = {
    accountInfoProvider: makeAccountInfoProvider(statuses),
    transactionForwarder: {
      sendAndConfirm: async () => "unused",
    } as TransactionForwarder,
    merkleProofProvider: {
      getInclusionProof: async () => ({
        root: new Uint8Array(32),
        siblings: [],
        pathIndices: [],
      }),
    } as MerkleProofProvider,
  };
  const client = new DarkPoolClient({
    programId: VAULT_PROGRAM_ID,
    matchingEngineProgramId: ME_PROGRAM_ID,
    seedMode: { type: "csprng", storage },
    connectionProvider: conn,
    providers,
    zkProver: new UnimplementedProverSuite(),
    ownerCommitmentBlinding: 0n,
  });
  if (opts.noteStatus) {
    // Patch getNoteStatus to return the requested stub without needing PDA derivation.
    client.getNoteStatus = async (): Promise<NoteStatusInfo> =>
      opts.noteStatus as NoteStatusInfo;
  }
  return client;
}

function makeParams(overrides: Partial<OrderParams> = {}): OrderParams {
  const trading = Keypair.generate().publicKey;
  const tee = Keypair.generate().publicKey;
  const market = Keypair.generate().publicKey;
  const noteCommitment = new Uint8Array(32);
  for (let i = 0; i < 32; i++) noteCommitment[i] = i + 1;
  const userCommitment = new Uint8Array(32);
  for (let i = 0; i < 32; i++) userCommitment[i] = 33 + (i % 200);
  const orderId = new Uint8Array(16);
  for (let i = 0; i < 16; i++) orderId[i] = 100 + i;
  return {
    tradingKey: trading,
    market,
    teeAuthority: tee,
    userCommitment,
    noteCommitment,
    amount: 10n,
    priceLimit: 110n,
    side: "bid",
    noteAmount: 1_100_000n,
    expirySlot: 100n,
    orderId,
    ...overrides,
  };
}

describe("Phase 3 — getOrderSubmitFunction", () => {
  it("[test_attestation_failure_aborts] throws 'attestation-verify' and sends no tx", async () => {
    const client = makeClient({ noteStatus: { status: "active" } });
    const session = new MockPerSessionManager();
    session.attestationOk = false;
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(submit(makeParams())).rejects.toMatchObject({
      stage: "attestation-verify",
    });
    expect(session.sendCallCount).toBe(0);
    expect(session.tokenFetchCount).toBe(0);
  });

  it("[test_order_for_locked_note_rejected] throws 'note-lock-check' when status=locked", async () => {
    const client = makeClient({ noteStatus: { status: "locked" } });
    const session = new MockPerSessionManager();
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(submit(makeParams())).rejects.toMatchObject({
      stage: "note-lock-check",
    });
    expect(session.sendCallCount).toBe(0);
  });

  it("[test_order_for_consumed_note_rejected] throws 'note-lock-check' when status=consumed", async () => {
    const client = makeClient({ noteStatus: { status: "consumed" } });
    const session = new MockPerSessionManager();
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    await expect(submit(makeParams())).rejects.toMatchObject({
      stage: "note-lock-check",
    });
  });

  it("[test_order_inclusion_commitment_returned] happy-path returns receipt + inclusion commitment", async () => {
    const client = makeClient({ noteStatus: { status: "active" } });
    const session = new MockPerSessionManager("happy_sig_ok");
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    const receipt = await submit(makeParams());
    expect(receipt.signature).toBe("happy_sig_ok");
    expect(receipt.orderInclusionCommitment).toHaveLength(32);
    expect(receipt.darkClobPda).toBeInstanceOf(PublicKey);
    expect(receipt.noteLockPda).toBeInstanceOf(PublicKey);
    expect(session.sendCallCount).toBe(1);
    expect(session.lastJwt).toBe("mock_jwt_ok");
  });

  it("[test_jwt_refresh_on_401] on 401 the session manager refreshes and the order succeeds on retry", async () => {
    const client = makeClient({ noteStatus: { status: "active" } });
    const session = new MockPerSessionManager("retry_sig_ok");
    session.injectNext401 = true;
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    const receipt = await submit(makeParams());
    expect(receipt.signature).toBe("retry_sig_ok");
    // One fetch for the initial call + one for the post-401 refresh.
    expect(session.tokenFetchCount).toBeGreaterThanOrEqual(2);
    // Second sendInstruction uses the refreshed token — its value differs.
    expect(session.lastJwt).not.toBe("mock_jwt_ok");
    expect(session.sendCallCount).toBe(2);
  });

  it("[test_order_submit_staged_errors] each stage throws with its own `stage` tag", async () => {
    const client = makeClient({ noteStatus: { status: "active" } });
    // Stage 1: attestation
    const s1 = new MockPerSessionManager();
    s1.attestationOk = false;
    const f1 = getOrderSubmitFunction({ client }, { perSessionManager: s1 });
    await expect(f1(makeParams())).rejects.toMatchObject({ stage: "attestation-verify" });

    // Stage 2: auth-token-fetch
    const s2 = new MockPerSessionManager();
    s2.getToken = async () => {
      throw new DarkPoolError("auth-token-fetch", "mock");
    };
    const f2 = getOrderSubmitFunction({ client }, { perSessionManager: s2 });
    await expect(f2(makeParams())).rejects.toMatchObject({ stage: "auth-token-fetch" });

    // Stage 3: note-lock-check
    const clientLocked = makeClient({ noteStatus: { status: "locked" } });
    const s3 = new MockPerSessionManager();
    const f3 = getOrderSubmitFunction({ client: clientLocked }, { perSessionManager: s3 });
    await expect(f3(makeParams())).rejects.toMatchObject({ stage: "note-lock-check" });

    // Stage 5: transaction-send (non-401, non-retryable)
    const s5 = new MockPerSessionManager();
    s5.injectNextFailure = new DarkPoolError("transaction-send", "rpc-5xx");
    const f5 = getOrderSubmitFunction({ client }, { perSessionManager: s5 });
    await expect(f5(makeParams())).rejects.toMatchObject({ stage: "transaction-send" });
  });

  it("[test_lock_note_called_on_acceptance — SDK wiring] the built ix targets the NoteLock PDA", async () => {
    const client = makeClient({ noteStatus: { status: "active" } });
    const session = new MockPerSessionManager("ok_sig");
    const submit = getOrderSubmitFunction({ client }, { perSessionManager: session });
    const params = makeParams();
    const receipt = await submit(params);
    // After send, session.lastIx should exist and its accounts include the NoteLock PDA.
    expect(session.lastIx).not.toBeNull();
    const ix = session.lastIx!;
    const accounts = ix.keys.map((k) => k.pubkey.toBase58());
    expect(accounts).toContain(receipt.noteLockPda.toBase58());
  });
});

describe("Phase 3 — LivePerSessionManager + mock TEE HTTP", () => {
  let tee: MockTeeServerHandle;
  beforeAll(async () => {
    tee = await startMockTeeServer();
  });
  afterAll(async () => {
    await tee.close();
  });

  it("[test_invalid_jwt_rejected_by_tee] tampered JWT yields 401 from the TEE", async () => {
    const kp = Keypair.generate();
    const traderPubkey = kp.publicKey.toBytes();
    const nacl = await import("tweetnacl").catch(() => null as unknown as {
      sign: { detached: (m: Uint8Array, sk: Uint8Array) => Uint8Array };
    });
    const mgr = new LivePerSessionManager({
      perRpcUrl: tee.url,
      traderPubkey,
      signNonce: async (nonce) => {
        if (nacl) {
          return nacl.sign.detached(nonce, kp.secretKey);
        }
        // If tweetnacl isn't installed, return a dummy sig — mock server doesn't verify it.
        return new Uint8Array(64);
      },
    });

    // Happy token fetch.
    const attestOk = await mgr.verifyAttestation();
    expect(attestOk).toBe(true);
    const jwt = await mgr.getToken();
    expect(jwt).toMatch(/\./);

    // Tamper the JWT and send — server returns 401, SDK raises auth-token-fetch.
    const tamperedJwt = jwt.split(".")[0] + ".AAAA";
    const dummyIx = {
      keys: [],
      programId: VAULT_PROGRAM_ID,
      data: Buffer.from([0]),
    };
    await expect(
      mgr.sendInstruction(
        dummyIx as never,
        tamperedJwt,
        { traderPubkey },
      ),
    ).rejects.toMatchObject({ stage: "auth-token-fetch" });
  });

  it("[attestation-verify via HTTP] verifier returns false when server disables attestation", async () => {
    const kp = Keypair.generate();
    tee.setAttestationOk(false);
    const mgr = new LivePerSessionManager({
      perRpcUrl: tee.url,
      traderPubkey: kp.publicKey.toBytes(),
      signNonce: async () => new Uint8Array(64),
    });
    const ok = await mgr.verifyAttestation();
    expect(ok).toBe(false);
    tee.setAttestationOk(true);
  });
});
