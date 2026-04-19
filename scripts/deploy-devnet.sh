#!/usr/bin/env bash
# Phase 3 devnet program deploy.
#
# Uses the local Solana CLI wallet as upgrade authority and fee payer.
# Deploys vault.so + matching_engine.so using the program-id keypairs in
# target/deploy/ so the deployed addresses match what's compiled in.
#
# Idempotent: subsequent runs upgrade the existing programs.
#
# Usage:
#   ./scripts/deploy-devnet.sh
#
# Prereqs:
#   - scripts/setup-devnet.sh has been run
#   - cargo build-sbf has produced target/deploy/{vault,matching_engine}.so
#   - solana CLI configured for devnet with a funded keypair

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VAULT_SO="target/deploy/vault.so"
ME_SO="target/deploy/matching_engine.so"
VAULT_KP="target/deploy/vault-keypair.json"
ME_KP="target/deploy/matching_engine-keypair.json"

for f in "$VAULT_SO" "$ME_SO" "$VAULT_KP" "$ME_KP"; do
  if [[ ! -f "$f" ]]; then
    echo "MISSING: $f"
    echo "run:"
    echo "  cargo build-sbf --manifest-path programs/vault/Cargo.toml"
    echo "  cargo build-sbf --manifest-path programs/matching_engine/Cargo.toml"
    exit 1
  fi
done

CONFIG_URL=$(solana config get json_rpc_url | awk '{print $NF}')
if [[ "$CONFIG_URL" != *"devnet"* ]]; then
  echo "ERROR: Solana CLI is not pointing at devnet."
  exit 1
fi

VAULT_ID=$(solana-keygen pubkey "$VAULT_KP")
ME_ID=$(solana-keygen pubkey "$ME_KP")

echo "Deploying to devnet (upgrade authority = local wallet)"
echo "  vault            program id: $VAULT_ID"
echo "  matching_engine  program id: $ME_ID"
echo

echo "-> vault"
solana program deploy "$VAULT_SO" \
  --program-id "$VAULT_KP" \
  --upgrade-authority "$HOME/.config/solana/id.json" \
  --commitment confirmed

echo "-> matching_engine"
solana program deploy "$ME_SO" \
  --program-id "$ME_KP" \
  --upgrade-authority "$HOME/.config/solana/id.json" \
  --commitment confirmed

echo
echo "verifying..."
solana program show "$VAULT_ID" --output json-compact | head -c 400; echo
solana program show "$ME_ID"    --output json-compact | head -c 400; echo

echo
echo "both programs deployed."
