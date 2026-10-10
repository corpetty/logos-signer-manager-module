//! What the manager refuses, and why.

use logos_signer_interface::{ErrorCode, SignerError};

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// A refusal the caller is meant to read and act on.
    #[error("{0}")]
    Refused(String),
    /// The account's signer said no; its code tells the approver whether to ask again.
    #[error("{0}")]
    Signer(SignerError),
    #[error("signing error: {0}")]
    Signing(String),
}

impl ManagerError {
    /// The signer's code, when the signer refused: `wrong_secret` lets the person try again.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ManagerError::Signer(e) => Some(e.code),
            _ => None,
        }
    }
}

impl From<SignerError> for ManagerError {
    fn from(e: SignerError) -> Self {
        ManagerError::Signer(e)
    }
}

pub type Result<T> = std::result::Result<T, ManagerError>;

pub fn bad(msg: impl Into<String>) -> ManagerError {
    ManagerError::InvalidParams(msg.into())
}
