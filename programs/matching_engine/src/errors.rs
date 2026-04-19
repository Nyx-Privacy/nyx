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

    // ---- Order validation ----
    #[msg("Market on DarkCLOB does not match instruction")]
    MarketMismatch,
    #[msg("Order side must be 0 (bid) or 1 (ask)")]
    InvalidSide,
    #[msg("Order amount must be > 0")]
    ZeroAmount,
    #[msg("Order price_limit must be > 0")]
    ZeroPrice,
    #[msg("Order notional (amount * price_limit) exceeds note amount")]
    NotionalExceedsNoteValue,
    #[msg("Order notional computation overflowed u64")]
    NotionalOverflow,

    // ---- Note state (mirrors vault::errors::VaultError for in-PER checks) ----
    #[msg("Note commitment is not present in the vault Merkle tree")]
    NoteNotInTree,
    #[msg("Note has already been consumed by settlement")]
    NoteAlreadyConsumed,
    #[msg("Note is already locked by another active order")]
    NoteAlreadyLocked,

    // ---- CLOB capacity ----
    #[msg("DarkCLOB is at capacity")]
    OrderbookFull,

    // ---- Sequence / replay ----
    #[msg("Sequence counter overflow")]
    SeqOverflow,

    // ---- CPI failures ----
    #[msg("MagicBlock CPI (create/update/delegate permission) failed")]
    PermissionCpiFailed,
    #[msg("Vault lock_note CPI failed")]
    LockNoteCpiFailed,
}
