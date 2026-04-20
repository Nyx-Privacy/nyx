use anchor_lang::prelude::*;

#[error_code]
pub enum MatchingError {
    // ---- Authorization ----
    #[msg("Signer is not the configured Permission Group root key")]
    NotRootKey,
    #[msg("Trading key is not a member of the Permission Group")]
    UnauthorizedTradingKey,
    #[msg("Vault config PDA mismatch")]
    VaultConfigMismatch,
    #[msg("Signer is not the TEE authority")]
    NotTeeAuthority,
    #[msg("Only the order's original owner can cancel it")]
    NotOrderOwner,

    // ---- Order validation ----
    #[msg("Market on DarkCLOB does not match instruction")]
    MarketMismatch,
    #[msg("Order side must be 0 (bid) or 1 (ask)")]
    InvalidSide,
    #[msg("Order type must be 0 (LIMIT), 1 (IOC), or 2 (FOK)")]
    InvalidOrderType,
    #[msg("Order amount must be > 0")]
    ZeroAmount,
    #[msg("Order price_limit must be > 0")]
    ZeroPrice,
    #[msg("Order notional (amount * price_limit) exceeds note amount")]
    NotionalExceedsNoteValue,
    #[msg("Order notional computation overflowed u64")]
    NotionalOverflow,
    #[msg("Order amount is below configured min_order_size")]
    AmountBelowMinOrderSize,
    #[msg("Order expiry_slot is in the past")]
    ExpiryInPast,
    #[msg("Order with the supplied (trading_key, order_id) does not exist")]
    OrderNotFound,

    // ---- Note state ----
    #[msg("Note commitment is not present in the vault Merkle tree")]
    NoteNotInTree,
    #[msg("Note has already been consumed by settlement")]
    NoteAlreadyConsumed,
    #[msg("Note is already locked by another active order")]
    NoteAlreadyLocked,

    // ---- CLOB / batch capacity ----
    #[msg("DarkCLOB is at capacity")]
    OrderbookFull,
    #[msg("Too many matches in this batch for the BatchResults ring")]
    BatchResultsRingOverflow,

    // ---- Sequence / replay ----
    #[msg("Sequence counter overflow")]
    SeqOverflow,

    // ---- Oracle ----
    #[msg("Oracle account payload too short")]
    OraclePayloadTooShort,
    #[msg("Oracle returned a negative price")]
    OracleNegativePrice,
    #[msg("Oracle account has unrecognised discriminator")]
    OracleUnrecognisedLayout,
    #[msg("Oracle price was zero — unusable for circuit breaker")]
    OracleZeroPrice,
    #[msg("Oracle account does not match MatchingConfig.pyth_account")]
    OracleAccountMismatch,

    // ---- CPI failures ----
    #[msg("MagicBlock CPI (create/update/delegate permission) failed")]
    PermissionCpiFailed,
    #[msg("Vault lock_note CPI failed")]
    LockNoteCpiFailed,
    #[msg("Vault release_lock CPI failed")]
    ReleaseLockCpiFailed,

    // ---- Phase 5: change-note conservation / commitment ----
    #[msg("Conservation law violated: trade_leg + change_leg + fee_leg != note.amount")]
    ConservationViolation,
    #[msg("Poseidon commitment computation failed")]
    PoseidonFailed,
    #[msg("Order id must not be all-zero (reserved as RELOCK_ORDER_ID_NONE sentinel)")]
    InvalidOrderId,
    #[msg("Order expiry is within the settlement buffer; would be unsafe to match")]
    OrderTooCloseToExpiry,
    #[msg("Fee rate basis-points overflowed u64 when multiplied by notional")]
    FeeOverflow,
}
