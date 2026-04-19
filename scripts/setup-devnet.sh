#!/usr/bin/env bash
# Phase 3 devnet E2E bootstrap.
#
# Idempotent. Generates test keypairs into .devnet/keypairs/ (gitignored),
# funds them from the caller's local Solana CLI wallet, and prints the
# addresses + balances.
#
# Usage:
#   ./scripts/setup-devnet.sh
#
# Env:
#   TEST_ACCOUNT_LAMPORTS   default 0.1 SOL per test account

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KEYPAIR_DIR=".devnet/keypairs"
mkdir -p "$KEYPAIR_DIR"

FUND_SOL="${TEST_ACCOUNT_LAMPORTS:-0.1}"

CONFIG_URL=$(solana config get json_rpc_url | awk '{print $NF}')
echo "Solana CLI RPC: $CONFIG_URL"
if [[ "$CONFIG_URL" != *"devnet"* ]]; then
  echo "ERROR: Solana CLI is not pointing at devnet. Run:"
  echo "  solana config set --url https://api.devnet.solana.com"
  exit 1
fi

LOCAL_PAYER=$(solana address)
LOCAL_BAL=$(solana balance | awk '{print $1}')
echo "Local payer: $LOCAL_PAYER  (balance: $LOCAL_BAL SOL)"
echo

declare -a ACCOUNTS=("admin" "tee_authority" "root_key" "trader")

for name in "${ACCOUNTS[@]}"; do
  kp="$KEYPAIR_DIR/$name.json"
  if [[ ! -f "$kp" ]]; then
    echo "  generating $name keypair ..."
    solana-keygen new --no-bip39-passphrase --outfile "$kp" --silent
  fi
  addr=$(solana-keygen pubkey "$kp")
  bal=$(solana balance "$addr" 2>/dev/null | awk '{print $1}')
  bal=${bal:-0}
  printf "  %-14s %s  (%.4f SOL)\n" "$name" "$addr" "$bal"

  below_min=$(awk -v b="$bal" -v m="$FUND_SOL" 'BEGIN { print (b < m) ? 1 : 0 }')
  if [[ "$below_min" == "1" ]]; then
    echo "    -> funding with $FUND_SOL SOL"
    solana transfer "$addr" "$FUND_SOL" \
      --allow-unfunded-recipient \
      --keypair "$HOME/.config/solana/id.json" \
      --commitment confirmed \
      --output json > /dev/null
  fi
done

echo
echo "done. keypairs written to $KEYPAIR_DIR/"
echo "run scripts/deploy-devnet.sh next to push programs."
