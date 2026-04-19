# Nyx Darkpool — developer command cheat sheet

All commands assume your working directory is the repo root:

```sh
cd /Users/arnabnandi/nyx-monorepo
```

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
# Full workspace, debug build
cargo build --workspace

# Single crate / program
cargo build -p darkpool-crypto
cargo build -p vault
cargo build -p vault --all-targets        # includes integration tests
cargo build -p matching_engine
cargo build -p matching_engine --all-targets
```

### Test

```sh
# Everything
cargo test --workspace

# Just the crypto primitives
cargo test -p darkpool-crypto

# Just the vault (merkle unit tests + ZK round-trips + create_wallet E2E)
cargo test -p vault

# One specific integration test by file name
cargo test -p vault --test merkle_host
cargo test -p vault --test zk_roundtrip
cargo test -p vault --test zk_spend_roundtrip
cargo test -p vault --test user_commitment_registration
cargo test -p matching_engine --test submit_order

# A single test by name (substring)
cargo test -p darkpool-crypto scope_aead_enforces_key_isolation
cargo test -p darkpool-crypto commitment_excludes_trading_key
```

### Lint / typecheck

```sh
# Fails on any warning
cargo clippy --workspace --all-targets -- -D warnings

# Formatting
cargo fmt --all            # apply
cargo fmt --all -- --check # verify only
```

---

## 2. On-chain (BPF / Solana) program

```sh
# Produces target/deploy/{vault,matching_engine}.so (required for litesvm tests)
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml

# Clean just one on-chain build
cargo clean --manifest-path programs/vault/Cargo.toml
cargo clean --manifest-path programs/matching_engine/Cargo.toml

# Show the compiled .so sizes
ls -lh target/deploy/vault.so target/deploy/matching_engine.so

# Anchor-friendly full build (runs cargo-build-sbf + emits IDL if declared).
# We don't use the IDL — our SDK hand-codes discriminators — but this is the
# canonical way to verify the Anchor macros still accept your code.
anchor build
```

---

## 3. TypeScript SDK

### Build / typecheck

```sh
# Fast typecheck only
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json --noEmit

# Full build (emits packages/sdk/dist)
cd packages/sdk && npm run build
```

### Test

```sh
# Full SDK test run
cd packages/sdk && ../../node_modules/.bin/vitest run

# A single file
cd packages/sdk && ../../node_modules/.bin/vitest run tests/keys-parity.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest run tests/poseidon-parity.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest run tests/user-commitment-parity.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest run tests/deposit-transport.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest run tests/withdraw-transport.test.ts
cd packages/sdk && ../../node_modules/.bin/vitest run tests/orders-submit.test.ts

# Watch mode (rerun on save)
cd packages/sdk && ../../node_modules/.bin/vitest
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

# Ad-hoc: run a proof from a JSON witness through snarkjs + verify via cargo
cargo test -p vault --test zk_roundtrip -- --nocapture
```

---

## 5. "Everything is green" full gate

Run this before every commit. If any one line fails, do not commit.

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

Expected counts today (Phase 4 complete):

| Layer | Count |
|-------|-------|
| Rust workspace tests  | 59 (27 crypto + 2 lib id + 6 merkle + 2 ZK + 1 wallet + 6 matching_engine lib + 4 submit_order + 11 run_batch) |
| TypeScript tests      | 51 (33 prior + 6 cancel-order + 4 batch-watcher + 8 inclusion-proof) |

## 9. Phase 3 — MagicBlock PER commands

### 9.1 Standalone / mock (no network)

```sh
# Run only the Phase 3 on-chain tests (litesvm + mock TEE server)
cargo test -p matching_engine --test submit_order -- --nocapture

# Run only the Phase 3 TS tests (mock TEE)
cd packages/sdk && ../../node_modules/.bin/vitest run tests/orders-submit.test.ts
```

### 9.2 Live devnet (RUN_PER_TESTS=1)

```sh
# one-time bootstrap:
bash scripts/setup-devnet.sh     # generates + funds .devnet/keypairs/*
bash scripts/deploy-devnet.sh    # deploys vault.so + matching_engine.so

# run the devnet E2E suite
cd packages/sdk && RUN_PER_TESTS=1 \
  ../../node_modules/.bin/vitest run tests/orders-submit.devnet.test.ts
```

### 9.3 Reference constants

| Thing                                       | Value                                          |
|---------------------------------------------|------------------------------------------------|
| Vault program id                            | AB8ZJYgG6jNzfzQAgHHC9DNuQF6tB48UYqCWuseZ59XW   |
| Matching-engine program id                  | G8MHBmzhfvRnhejot7XfeSFm3NC96uqm7VNduutM1J2K   |
| Permission program id (ER SDK 0.10.5 Rust)  | ACLseoPoyC3cBqoUtkbjZ4aDrkurZW86v19pXz2XQnp1   |
| Permission program id (ER SDK 0.6.5 TS)     | BTWAqWNBmF2TboMh3fxMJfgR16xGHYD7Kgr2dPwbRPBi   |
| TEE endpoint                                | https://tee.magicblock.app                     |
| Env file (gitignored)                       | packages/sdk/.env.devnet                       |
| Test keypair dir (gitignored)               | .devnet/keypairs/                              |

Note: the two permission program ids are different versions of the same
MagicBlock permission program. Our Rust on-chain program links `ACL...`;
the TS `permissionPdaFromAccount` helper targets `BTW...`. For correct PDA
derivation from TS, always derive with the `ACL...` id (see the
`derivePermissionPda` helper in `tests/orders-submit.devnet.test.ts`).

---

## 10. Phase 4 — batch auction + circuit breaker + cancel

Phase 4 extends the engine with periodic uniform-clearing-price batching,
Pyth-based circuit breaker, `cancel_order`, and the `BatchResults` match
ring. All new tests are local (litesvm + vitest mocks); no live TEE needed.

### 10.1 Run only the Phase-4 on-chain tests (litesvm)

```sh
# Pre-req: SBF binaries must be up to date.
cargo build-sbf --manifest-path programs/vault/Cargo.toml
cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml

# 6 lib unit tests (deviation math + merkle helpers)
cargo test -p matching_engine --lib -- --nocapture

# 11 integration tests (§23.4.2 + cancel flow)
cargo test -p matching_engine --test run_batch -- --nocapture

# 4 Phase-3 submit_order tests on new Phase-4 layouts (regression gate)
cargo test -p matching_engine --test submit_order -- --nocapture
```

### 10.2 Run only the Phase-4 TS glue tests

```sh
cd packages/sdk && ../../node_modules/.bin/vitest run \
  tests/cancel-order.test.ts \
  tests/batch-watcher.test.ts \
  tests/inclusion-proof.test.ts
```

### 10.3 Phase-4 devnet redeploy (after ABI change)

`init_market` now takes 8 fields (adds base_mint, quote_mint,
pyth_account, circuit_breaker_bps, tick_size, min_order_size). The
`orders-submit.devnet.test.ts` suite passes them with synthetic values —
`init_market` only persists, it doesn't call the oracle. To redeploy:

```sh
# Uploads programs/matching_engine/target/deploy/matching_engine.so
# against AB8ZJYg... + G8MH... (keypairs live in .devnet/keypairs/).
bash scripts/deploy-devnet.sh

# Then run the regression suite:
cd packages/sdk && RUN_PER_TESTS=1 \
  ../../node_modules/.bin/vitest run tests/orders-submit.devnet.test.ts
```

### 10.4 Shape quick-reference

| Field                        | Old (Phase 3) | New (Phase 4)     |
|------------------------------|---------------|-------------------|
| `InitMarketArgs` width       | 40 B          | 168 B             |
| `SubmitOrderArgs` width      | 113 B         | 122 B             |
| `OrderRecord` width          | 136 B         | 176 B             |
| DarkCLOB capacity            | 64 orders     | 48 orders         |
| New PDAs per market          | dark_clob,    | +batch_results    |
|                              |  matching_cfg |                   |

---

## 6. Useful ad-hoc probes

```sh
# Rebuild just the derive-keys helper (TS parity tests rely on it)
cargo build --example derive-keys -p darkpool-crypto
./target/debug/examples/derive-keys spending \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

# Rebuild the poseidon-hash helper (Poseidon parity tests use it)
cargo build --example poseidon-hash -p darkpool-crypto
./target/debug/examples/poseidon-hash 2 42 42

# Rebuild the user-commitment helper (user-commitment parity test uses it)
cargo build --example user-commitment -p darkpool-crypto

# View what cargo thinks about cross-platform deps
cargo tree -p darkpool-crypto --target aarch64-apple-darwin | head -30
cargo tree -p darkpool-crypto --target sbf-solana-solana | head -30

# Disassemble vault.so to sanity-check BPF code size after zero-copy refactor
cargo-build-sbf --manifest-path programs/vault/Cargo.toml --dump
```

---

## 7. Running a single litesvm test with full logs

```sh
RUST_LOG=debug RUST_BACKTRACE=1 \
  cargo test -p vault --test user_commitment_registration -- --nocapture
```

`--nocapture` is important: without it the `eprintln!("create_wallet logs:")`
block is hidden and any on-chain panic is silent.

---

## 8. Resetting state

```sh
# Nuke all target artifacts + node_modules
cargo clean
rm -rf node_modules packages/sdk/dist packages/sdk/node_modules circuits/build

# Or a lighter reset (keep deps installed, only rebuild code)
cargo clean -p vault -p darkpool-crypto
rm -rf packages/sdk/dist target/deploy/vault.so
```
