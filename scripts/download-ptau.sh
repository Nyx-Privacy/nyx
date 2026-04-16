#!/usr/bin/env bash
# Download Hermez Powers of Tau ceremony files.
#
# valid_spend @ depth 20 has ~30k constraints -> pot15 (2^15) sufficient.
# valid_wallet_create is tiny (~1k constraints) -> pot12 also fine, but we use
# pot15 for everything to keep a single .ptau artifact.
#
# Reference: https://github.com/iden3/snarkjs#7-prepare-phase-2
set -euo pipefail

PTAU_DIR="$(cd "$(dirname "$0")" && pwd)/ptau"
mkdir -p "$PTAU_DIR"

# pot16 covers up to ~65k constraints — safe for both Phase 1 circuits.
PTAU_FILE="powersOfTau28_hez_final_16.ptau"
URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"

if [ -f "$PTAU_DIR/$PTAU_FILE" ]; then
    echo "[ptau] $PTAU_FILE already present at $PTAU_DIR"
    exit 0
fi

echo "[ptau] downloading $PTAU_FILE (~72 MB) ..."
curl -L --fail --progress-bar -o "$PTAU_DIR/$PTAU_FILE" "$URL"
echo "[ptau] done: $PTAU_DIR/$PTAU_FILE"

# Hash check (published SHA256 in Hermez repo; this is the final contribution).
EXPECTED="d38a81ce8ea66eabf9bda20a9abd1c4e7ac7a73fbe5b61e4c18ec2f06f6b9a6e"
# Note: the above is a placeholder — we don't enforce hash here because Hermez
# does not publish an official checksum file. Users should verify against a
# trusted source before production deployment.
echo "[ptau] WARNING: Phase 1 uses an unaudited ptau download. For mainnet launch,"
echo "[ptau]          replace with a locally-hosted ceremony file and pin SHA256."
