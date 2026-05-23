//! Error type for `library`.

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by `library`.
///
/// Placeholder — real variants land alongside the logic that produces them.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A not-yet-implemented code path was exercised.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
