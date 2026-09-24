//! One user the node holds an NT hash for.

use authenticate::AuthenticateError;

/// One user the node holds an NT hash for.
#[derive(Clone)]
pub struct Account {
    user: String,
    domain: Option<String>,
    pub(crate) hash: [u8; 16],
}

impl Account {
    /// A user in any domain, by the NT hash: MD4 of the UTF-16LE password,
    /// thirty-two hexadecimal digits as a SAM or `secretsdump` prints it.
    ///
    /// # Errors
    ///
    /// Where the text is not thirty-two hexadecimal digits.
    pub fn from_hex(user: impl Into<String>, hash: &str) -> Result<Self, AuthenticateError> {
        let bytes: [u8; 16] = codec::hex::decode(hash.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| AuthenticateError::new("an NT hash is thirty-two hexadecimal digits"))?;
        Ok(Self {
            user: user.into(),
            domain: None,
            hash: bytes,
        })
    }

    /// Only where the client names this domain, compared without case.
    #[must_use]
    pub fn in_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub(crate) fn is(&self, user: &str, domain: &str) -> bool {
        self.user.to_uppercase() == user.to_uppercase()
            && self
                .domain
                .as_ref()
                .is_none_or(|held| held.to_uppercase() == domain.to_uppercase())
    }
}
