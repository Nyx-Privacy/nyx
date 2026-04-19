//! Pyth TWAP reader — supports the real Pyth price-update account format
//! (we only need the `ema_price` field) as well as a small test-mode mock
//! format. Both formats are discriminated by an 8-byte magic at offset 0.
//!
//! The live Pyth pull-oracle v2 account layout is a `PriceUpdateV2` with
//! discriminator `[34,241,35,99,157,126,244,205]` (Anchor `global:
//! PriceUpdateV2` hash). Inside it the `price_message.ema_price` field
//! lives at a known offset. For Phase 4 we only read the EMA price (TWAP
//! proxy); full Pyth integration (confidence intervals, age checks) can
//! arrive in Phase 5 alongside `VALID_PRICE`.
//!
//! For tests we accept a minimal mock with magic `MOCK_PYTH_MAGIC` and a
//! single u64 TWAP at offset 8. See `encode_mock_price_account` below.

use anchor_lang::prelude::*;

use crate::errors::MatchingError;

/// Magic for the test-mode mock oracle account.
pub const MOCK_PYTH_MAGIC: [u8; 8] = *b"NYXMKPTH";

/// Anchor global discriminator for PriceUpdateV2.
pub const PYTH_PRICE_UPDATE_V2_DISC: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];

/// Offset of `price_message.ema_price` inside a PriceUpdateV2 account.
///
/// Derived from the Pyth SDK struct layout: 8 (anchor disc) + 32
/// (write_authority) + 2 (verification_level) + 32 (feed_id) + 8 (price) +
/// 8 (conf) + 4 (exponent) + 8 (publish_time) + 8 (prev_publish_time) → the
/// next 8 bytes are `ema_price`. Total offset = 110.
pub const PYTH_EMA_PRICE_OFFSET: usize = 110;

/// Read the TWAP-equivalent price as a u64 from a Pyth or mock account.
///
/// Rejects negative prices (should not occur for spot TWAPs). Returns the
/// raw integer price in Pyth's native `expo` scaling — the caller is
/// responsible for scaling against the market tick. For tests the mock just
/// returns the stored value.
pub fn read_oracle_price(account: &AccountInfo<'_>) -> Result<u64> {
    let data = account.try_borrow_data()?;
    if data.len() < 16 {
        return err!(MatchingError::OraclePayloadTooShort);
    }
    let disc: [u8; 8] = data[0..8].try_into().unwrap();
    if disc == MOCK_PYTH_MAGIC {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[8..16]);
        return Ok(u64::from_le_bytes(buf));
    }
    if disc == PYTH_PRICE_UPDATE_V2_DISC {
        if data.len() < PYTH_EMA_PRICE_OFFSET + 8 {
            return err!(MatchingError::OraclePayloadTooShort);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[PYTH_EMA_PRICE_OFFSET..PYTH_EMA_PRICE_OFFSET + 8]);
        let raw = i64::from_le_bytes(buf);
        if raw < 0 {
            return err!(MatchingError::OracleNegativePrice);
        }
        return Ok(raw as u64);
    }
    err!(MatchingError::OracleUnrecognisedLayout)
}

/// Helper for tests: build the minimal mock-oracle account contents.
#[allow(dead_code)]
pub fn encode_mock_price_account(twap: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&MOCK_PYTH_MAGIC);
    out[8..16].copy_from_slice(&twap.to_le_bytes());
    out
}
