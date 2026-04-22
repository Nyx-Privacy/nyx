# Nyx Darkpool — developer command cheat sheet

All commands assume your working directory is the repo root:

```sh
cd /Users/arnabnandi/nyx-monorepo
```

Organisation:
- §0  one-time setup
- §1  Rust (host-side)
- §2  Rust (BPF / on-chain)
- §3  TypeScript SDK
- §4  Circuits (circom / snarkjs)
- §5  "Everything is green" pre-commit gate
- §6  Ad-hoc probes + parity helpers
- §7  Running a single litesvm test with full logs
- §8  Resetting state (local disk + on-chain Merkle tree)
- §9  Devnet — deploy + environment + constants
- §10 Devnet E2E — L1-only happy-path (setup + trade flow)
- §11 Devnet E2E — ER (MagicBlock Ephemeral Rollup) cycle
- §12 Troubleshooting common failures

---

## 0. One-time environment setup

Bootstrap the TS side (needed by parity tests + snarkjs):

```sh
npm install
```

Download the Powers-of-Tau ceremony file and compile the circuits (produces
`.zkey`, `.wasm`, verifier-key Rust consts):

```sh
bash scripts/build-circuits.sh
```

Build the on-chain BPF programs (`target/deploy/vault.so` +
`target/deploy/matching_engine.so`) — required by the litesvm E2E tests:

```sh
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml
```

Build the small host-side CLI helpers used by the TS <-> Rust parity tests:

```sh
cargo build --examples -p darkpool-crypto
```

---

## 1. Host-side Rust

### Build

```sh
cargo build --workspace                  # full workspace (debug)
cargo build -p darkpool-crypto
cargo build -p vault --all-targets       # includes integration tests
cargo build -p matching_engine --all-targets
```

### Test

```sh
# Everything
cargo test --workspace

# Per-crate
cargo test -p darkpool-crypto
cargo test -p vault
cargo test -p matching_engine

# One integration test by file name
cargo test -p vault --test merkle_host
cargo test -p vault --test zk_spend_roundtrip
cargo test -p vault --test user_commitment_registration
cargo test -p vault --test settle            # Phase-5 settlement (15 scenarios)
cargo test -p vault --test set_protocol_config
cargo test -p vault --test reset_merkle_tree
cargo test -p matching_engine --test submit_order
cargo test -p matching_engine --test run_batch

# Single test name (substring)
cargo test -p vault canonical_payload_hash_fixed_vector
```

### Lint / typecheck

```sh
cargo clippy --workspace --all-targets -- -D warnings   # fails on any warning
cargo fmt --all                                         # apply
cargo fmt --all -- --check                              # verify only
```

---

## 2. On-chain (BPF / Solana) program

```sh
# Produces target/deploy/{vault,matching_engine}.so (required for litesvm tests)
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml

# Show compiled sizes
ls -lh target/deploy/vault.so target/deploy/matching_engine.so

# Per-program clean
cargo clean --manifest-path programs/vault/Cargo.toml
cargo clean --manifest-path programs/matching_engine/Cargo.toml

# Anchor-friendly full build (verifies Anchor macros still accept the code).
# The IDL is NOT used — our SDK hand-codes discriminators.
anchor build
```

---

## 3. TypeScript SDK

### Build / typecheck

```sh
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit   # fast typecheck
cd packages/sdk && npm run build                                  # full build
```

### Test

```sh
cd packages/sdk && ../../node_modules/.bin/vitest run                          # all
cd packages/sdk && ../../node_modules/.bin/vitest run tests/poseidon-parity.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest run tests/settle-builder.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest                              # watch
```

---

## 4. Circuits (circom / snarkjs)

```sh
# End-to-end: compile circom, run ceremony, write Rust VK consts
bash scripts/build-circuits.sh

# Inspect compiled artifacts
ls circuits/build/valid_wallet_create/
ls circuits/build/valid_spend/

# Regenerate just the Rust VK constants (if you tweaked the parser)
node scripts/parse-vk-to-rust.js \
  circuits/build/valid_wallet_create/verification_key.json \
  programs/vault/src/zk/vk_valid_wallet_create.rs

# Ad-hoc: round-trip proof through snarkjs + verify via cargo
cargo test -p vault --test zk_roundtrip -- --nocapture
```

---

## 5. "Everything is green" full gate

Run this before every commit. If any line fails, do not commit.

```sh
set -e
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml
cargo build --examples -p darkpool-crypto
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit
( cd packages/sdk && ../../node_modules/.bin/vitest run )
echo "ALL GREEN"
```

Expected counts (Phase 5 + ER wiring):

| Layer                  | Count                               |
|------------------------|-------------------------------------|
| Rust workspace tests   | 82 total (27 crypto + merkle + ZK + Phase-4 + Phase-5 settle + set_protocol_config + reset_merkle_tree + submit_order + run_batch) |
| TS SDK unit tests      | 75 passing / 12 skipped (devnet / ER gated) |

---

## 6. Ad-hoc probes

```sh
# Rebuild the derive-keys CLI (TS parity tests depend on it)
cargo build --example derive-keys -p darkpool-crypto
./target/debug/examples/derive-keys spending \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

# Rebuild the poseidon-hash helper
cargo build --example poseidon-hash -p darkpool-crypto
./target/debug/examples/poseidon-hash 2 42 42

# user-commitment helper
cargo build --example user-commitment -p darkpool-crypto

# Dep graph per target
cargo tree -p darkpool-crypto --target aarch64-apple-darwin | head -30
cargo tree -p darkpool-crypto --target sbf-solana-solana     | head -30
```

---

## 7. Running a single litesvm test with full logs

```sh
RUST_LOG=debug RUST_BACKTRACE=1 \
  cargo test -p vault --test user_commitment_registration -- --nocapture
```

`--nocapture` matters: without it `eprintln!` and any on-chain panic are hidden.

---

## 8. Resetting state

### 8.1 Local disk

```sh
# Nuke everything: target artifacts + node_modules + circuit build
cargo clean
rm -rf node_modules packages/sdk/dist packages/sdk/node_modules circuits/build

# Light reset (keep deps installed)
cargo clean -p vault -p darkpool-crypto
rm -rf packages/sdk/dist target/deploy/vault.so
```

### 8.2 On-chain Merkle tree reset (devnet / staging only)

The vault's incremental Merkle tree is a singleton PDA (`vault_config`).
Once initialised it accumulates leaves across every deposit / settlement.
That's fine in production but fatal in tests — the SDK's in-memory
`MerkleShadow` starts empty, so after a few runs the shadow root diverges
from the on-chain `current_root` and every `VALID_SPEND` withdrawal
fails with `StaleMerkleRoot` (error 0x1774).

**Symptom you'll see:**
```
Error Code: StaleMerkleRoot. Error Number: 6004.
Message: Merkle root provided by proof does not match current on-chain root.
```

**Cure:** call the dev-net-only `vault::reset_merkle_tree` admin ix. It
wipes `leaf_count`, `right_path[..]`, and the `roots[..]` ring buffer,
then recomputes `current_root` from `zero_subtree_roots`. Nullifier /
wallet / deposit-in-flight PDAs are NOT touched (they're separate PDAs).

You rarely call it manually — `devnet-setup.test.ts` does it for you:

```sh
# Running the setup test is the canonical way to "start fresh"
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts )
```

Setup steps (each prints a TX + explorer URL):
1. Create fresh BASE (9d) + QUOTE (6d) SPL mint pair.
2. `vault::initialize` (idempotent).
3. **`vault::reset_merkle_tree`** — wipes the tree.
4. `vault::set_protocol_config` — sets `protocol_owner_commitment` + fee
   rate (30 bps). Top byte of the protocol commitment is zeroed so the
   Poseidon input stays < BN254 Fr.
5. `matching_engine::init_mock_oracle` — creates a 16-byte NYXMKPTH
   stub (u64 TWAP). Pyth Pull-v2 feeds aren't reliable on devnet, and
   our `read_oracle` doesn't accept the legacy Pythnet layout.
6. `matching_engine::init_market` — wires baseMint / quoteMint / the
   mock oracle into a brand-new market PDA.
7. Writes `.devnet/e2e-config.json` with everything the trade-flow
   tests need (market pubkey, mint secret keys, protocol config, fee
   rate, oracle pubkey).

After setup completes you have: empty tree, a fresh market, mints you
fully control, protocol config set, and an oracle that trips the
circuit breaker only against a TWAP *you* set.

Re-run it any time the shadow-tree invariant fires.

---

## 9. Devnet — deploy + environment + constants

### 9.1 Deploy the programs

```sh
# One-time: generates + funds .devnet/keypairs/*
bash scripts/setup-devnet.sh

# Redeploys target/deploy/{vault,matching_engine}.so at the declared program IDs
bash scripts/deploy-devnet.sh
```

`deploy-devnet.sh` is idempotent — it reuses the existing program IDs
(upgrade in place). If you touched a program, remember to
`cargo build-sbf` first.

> **Stale BPF pitfall:** if you see `DeclaredProgramIdMismatch` (0x1004)
> or any `ProgramNotFound`, your `.so` is out of date. `touch`
> `programs/<prog>/src/lib.rs` and rebuild to force a fresh compile:
>
> ```sh
> touch programs/matching_engine/src/lib.rs
> cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml
> bash scripts/deploy-devnet.sh
> ```

### 9.2 Reference constants

| Thing                                   | Value                                         |
|-----------------------------------------|-----------------------------------------------|
| Vault program id                        | `ELt4FH2gH8RaZkYbvbbDjGkX8dPhGFdWnspM4w1fdjoY` |
| Matching-engine program id              | `DvYcaiBuaHgJFVjVd57JLM7ZMavzXvBezJwsvA46FJbH` |
| MagicBlock delegation program id        | `DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh` |
| MagicBlock magic program id             | `Magic11111111111111111111111111111111111111`  |
| MagicBlock magic context id             | `MagicContext1111111111111111111111111111111`  |
| MagicBlock ER devnet entry              | `https://devnet.magicblock.app`               |
| Permission program id (on-chain Rust)   | `ACLseoPoyC3cBqoUtkbjZ4aDrkurZW86v19pXz2XQnp1` |
| Env file (gitignored)                   | `packages/sdk/.env.devnet`                    |
| Test keypair dir (gitignored)           | `.devnet/keypairs/`                           |
| Runtime config (gitignored)             | `.devnet/e2e-config.json`                     |

---

## 10. Devnet E2E — L1-only happy-path

Two test files, always run setup first.

### 10.1 Setup — fresh mints + fresh market + Merkle-tree reset

```sh
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts )
```

See §8.2 for what happens inside.

### 10.2 Trade flow — deposit → match → settle → withdraw

```sh
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-trade-flow.test.ts )
```

`FUNDER_KEYPAIR` defaults to `admin` if unset. On free-tier RPCs the
admin rarely has enough SOL for both personas + protocol ATAs + ZK ixs,
so point it at a wallet you manually funded via a faucet.

What this exercises:
1. Persona generation (Alice, Bob) — persisted to `.devnet/keypairs/{alice,bob}-*`.
2. Funder top-ups Alice + Bob payer / trading keys if below thresholds.
3. Mint BASE / QUOTE balances.
4. `create_wallet` with VALID_WALLET_CREATE proof (idempotent-skip if
   the `WalletEntry` PDA already exists).
5. Deposit notes → shadow tree sync.
6. `submit_order` x2 — **on L1** (see §11.0 for why).
7. `run_batch` **on L1** — finds the crossing.
8-11. Decode BatchResults → build `MatchResultPayload` → Ed25519 + settle
   → three VALID_SPEND withdrawals.

Final assertion: Alice's BASE balance == 50, Bob's QUOTE == 5000.

The partial-fill scenario is documented in the same file (second
describe block) but gated on `RUN_DEVNET_PARTIAL_FILL=1`.

---

## 11. Devnet E2E — ER (MagicBlock Ephemeral Rollup) cycle

### 11.0 Architecture in one paragraph

Three market PDAs (`DarkCLOB`, `MatchingConfig`, `BatchResults`) are
**delegated** on L1 to the MagicBlock ER validator, `run_batch` runs
**inside the ER session**, then we CPI `ScheduleCommitAndUndelegate`
which commits the new state back to L1 and returns the PDAs to
`matching_engine` ownership. Settlement (`tee_forced_settle`) and
withdraws happen on L1 as usual.

`submit_order` currently still runs **on L1** in the test — see §11.5
for why and what's planned.

### 11.1 Prerequisites

1. Programs deployed (§9.1), including the new ER ixs:
   `delegate_dark_clob`, `delegate_matching_config`,
   `delegate_batch_results`, `commit_market_state`, `undelegate_market`,
   and the Pyth-alternative `init_mock_oracle`.
2. Setup test run (§8.2 / §10.1) — fresh market + wiped tree.
3. A funder keypair with ≥ 0.4 SOL (delegation creates 3 buffer /
   record / metadata PDAs per market, so the 0.3-SOL threshold from the
   L1 test isn't enough).
4. `ER_RPC_URL` defaults to `https://devnet.magicblock.app`; override
   via env if you have a private validator endpoint.

### 11.2 Run the ER trade flow

```sh
# Always run setup first (or whenever the shadow tree diverges):
RUN_DEVNET_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  ROOT_KEY_KEYPAIR=.devnet/keypairs/root_key.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/devnet-setup.test.ts )

# Then the ER flow:
RUN_ER_E2E=1 \
  ADMIN_KEYPAIR=.devnet/keypairs/admin.json \
  TEE_AUTHORITY_KEYPAIR=.devnet/keypairs/tee_authority.json \
  FUNDER_KEYPAIR=~/.config/solana/id.json \
  ( cd packages/sdk && ../../node_modules/.bin/vitest run tests/er-trade-flow.test.ts )
```

### 11.3 The 13 steps, with cluster routing

| # | Cluster | Step                                                                 |
|---|---------|----------------------------------------------------------------------|
| 1 | local   | Generate ER-suffixed Alice / Bob personas                            |
| 2 | L1      | Fund Alice + Bob (SystemProgram.transfer from funder)                |
| 3 | L1      | Mint BASE / QUOTE to payer ATAs                                      |
| 4 | L1      | `create_wallet` (VALID_WALLET_CREATE proof)                          |
| 5 | L1      | `deposit` → shadow tree sync                                         |
| 6 | L1      | `submit_order` x2 (CPIs `vault::lock_note`)                           |
| 7 | **L1**  | **`delegate_dark_clob` + `delegate_matching_config` + `delegate_batch_results`** (atomic) |
| 8 | **ER**  | **`run_batch`** — matches Alice vs Bob inside the rollup             |
| 9 | **ER**  | **`undelegate_market`** (CPIs `ScheduleCommitAndUndelegate`)          |
| 10| L1 poll | Wait for L1 BatchResults to reflect the ER commit (hash changes)     |
| 11| L1      | Build MatchResultPayload + TEE-sign canonical hash                   |
| 12| L1      | `tee_forced_settle` (Ed25519 + settle ix)                            |
| 13| L1      | VALID_SPEND withdraws — Alice receives BASE, Bob receives QUOTE      |

### 11.4 Personas are ER-independent

The ER test uses `alice-er-*` / `bob-er-*` keypairs so it doesn't
collide with the L1-only test's personas. You can run both tests
against the same devnet vault (after a setup wipe) without
`NoteAlreadyLocked` or `WalletEntry`-collision errors.

### 11.5 Deliberate shortcuts still in the ER flow (track as TODOs)

1. **`submit_order` is still on L1.** The order payload (`amount`,
   `price_limit`, `side`) is therefore visible in devnet tx logs.
   *Moving this into the ER session is the single biggest remaining
   work item for a true darkpool (see §13 below).*
2. **TEE is a local `Keypair`.** Real deployment pins the keypair
   inside a TDX/SEV enclave + remote-attestation handshake.
3. **TRADE_ROLE_\* test-only derivation.** `note_c` / `note_d`
   plaintexts are reconstructed off-chain via
   `SHA-256(domain_tag, match_id, role)`. In production the TEE ships
   them to the user via the PER session.
4. **`delegate_X` ixs don't take a validator preference.** MagicBlock
   default-picks a validator. Plumb a preferred-validator arg once
   governance owns the choice.
5. **No auto-commit scheduler.** The test commits manually via
   `undelegate_market`. In production the TEE would call
   `commit_market_state` (keeps delegation) every N slots so
   settlement can pick up matches without a full undelegate cycle.

---

## 12. Troubleshooting common failures

| Error                                                                 | Likely cause                                                                                  | Fix                                                                                       |
|-----------------------------------------------------------------------|------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `DeclaredProgramIdMismatch (0x1004)`                                   | Stale `.so` on devnet — program ID in source doesn't match deployed binary.                    | `touch` the program's `src/lib.rs`, `cargo build-sbf`, `bash scripts/deploy-devnet.sh`.    |
| `StaleMerkleRoot (6004 / 0x1774)` on withdraw                          | SDK's MerkleShadow diverged from on-chain tree (too many prior runs accumulated).              | Re-run `devnet-setup.test.ts` — it calls `reset_merkle_tree` (§8.2).                      |
| `ConservationViolation (6029 / 0x178d)` in run_batch                   | `note_amount` passed to `submit_order` doesn't match the deposited note's native currency.     | Pass `noteAmount = p.depositNote.amount` (QUOTE for BUY, BASE for SELL).                  |
| `PoseidonFailed (6030 / 0x178e)`                                       | A 32-byte input's top byte exceeds 0x30 → value ≥ BN254 Fr modulus.                            | Zero the top byte of the offending field (e.g. `protocolOwnerCommitment[0] = 0`).          |
| `OracleUnrecognisedLayout (6063)`                                      | Supplied Pyth account is the legacy Pythnet magic (0xa1b2c3d4) — our `read_oracle` accepts only Pull-v2 or our NYXMKPTH mock. | Let setup create a mock oracle (default), or supply a real Pyth Pull-v2 account.          |
| `AccountOwnedByWrongProgram` on `batch_results` after ER run           | Commit hasn't landed on L1 yet; tx raced the commit.                                           | Bump `waitForL1AccountChange` timeout, or ensure `undelegate_market` is confirmed before polling. |
| `AnchorError ConstraintSeeds (2006)` during `delegate_*`               | SDK account-meta wire order doesn't match the `#[delegate]` macro expansion.                   | Order MUST be `[payer, buffer, delegation_record, delegation_metadata, pda, owner_program, delegation_program, system_program]`. |
| `Simulation failed: insufficient funds`                                 | Funder balance below threshold (0.3 SOL L1 / 0.4 SOL ER).                                      | Set `FUNDER_KEYPAIR=<path-to-wallet-with-SOL>`.                                            |
| `InvalidProof (6000 / 0x1770)` on `create_wallet`                      | VALID_WALLET_CREATE public input ordering or Fr-pair convention mismatch.                      | Regenerate proof with the pair convention `[lo, hi]` (see `pubkeyToFrPair`).               |

---

## 13. What is NOT yet on devnet (v1 open work)

See the response block in chat for the full backlog. Highlights:

1. **Move `submit_order` into the ER session** so order intents stay
   private — currently public on L1.
2. Real TDX/SEV TEE + remote attestation (Phase 6).
3. Browser prover (`WebProverSuite`) replacing the snarkjs shell-out.
4. Partial-fill + re-lock scenario exercised on devnet (code paths
   exist; test harness stub-only).
5. Cancel-order via ER (currently L1-only; blocked on step 1).
6. Emergency `force_undelegate_on_l1` admin ix (pressure valve).
7. Real protocol-owner keypair for fee withdrawal (currently a
   synthetic tag — fee notes accumulate but can't be spent).
8. Continuous ER ↔ L1 commit scheduler inside the TEE loop.
9. Oracle refresh inside long-running ER sessions (clone-at-open only
   today).
