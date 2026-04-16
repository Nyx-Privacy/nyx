pub mod initialize;
pub mod create_wallet;
pub mod deposit;
pub mod withdraw;
pub mod lock_note;
pub mod release_lock;
pub mod tee_forced_settle;

// Re-export every item from each instruction module, including the hidden
// `__client_accounts_*` modules Anchor's `#[derive(Accounts)]` macro generates.
// The program macro resolves them at `crate::<module>::__client_accounts_*`.
pub use initialize::*;
pub use create_wallet::*;
pub use deposit::*;
pub use withdraw::*;
pub use lock_note::*;
pub use release_lock::*;
pub use tee_forced_settle::*;
