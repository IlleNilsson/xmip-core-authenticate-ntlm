#![forbid(unsafe_code)]

//! Authenticate by ntlm: verifies the `NTLMv2` response against the stored
//! hash.
//!
//! The first gate read the user out of a type 3 message and presented it as
//! the claim, with the whole message riding as the `ntlm.authenticate` proof.
//! This gate recomputes what MS-NLMP 3.3.2 says the client computed: from the
//! NT hash the node holds for the user, `NTOWFv2` is HMAC-MD5 over the
//! uppercased user and the domain as the client spelled it, and the
//! `NTProofStr` is HMAC-MD5 under that over the server challenge and the
//! client's blob. Where the recomputed proof is the one in the message, the
//! client knew the password.
//!
//! The server challenge is the node's own: whoever sent the type 2 message
//! tells this verifier with [`Verifier::issued`], and a challenge proves one
//! response and is then spent, so a captured type 3 replayed later meets no
//! outstanding challenge and is refused. Offline throughout (ADR-0045): the
//! hashes are configuration, and nothing is asked of a domain controller.
//!
//! What is not verified, and refused or ignored by name: an `NTLMv1` or LM
//! response is refused; the MIC, channel bindings and the target name inside
//! the blob are not checked; no session key is derived, because this gate
//! proves who and signs nothing.
//!
//! The message's user and domain are compared with the claim as the identify
//! capability's `UserPrincipalName` where both form one, so a claim of
//! `jane@partnerx` is the account a type 3 for `jane` in `PARTNERX` names,
//! and a different account is refused naming both (ADR-0054).

pub mod message;

pub use message::Authenticate;

use authenticate::{AuthenticateError, Authenticator, Presented};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use context::Verified;
use hmac::{Hmac, Mac};
use identify::UserPrincipalName;
use md5::Md5;
use std::sync::Mutex;
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the base64 type 3 message under.
pub const AUTHENTICATE_PROOF: &str = "ntlm.authenticate";

/// How many challenges may be outstanding before the oldest is forgotten.
const OUTSTANDING: usize = 1024;

/// One user the node holds an NT hash for.
#[derive(Clone)]
pub struct Account {
    user: String,
    domain: Option<String>,
    hash: [u8; 16],
}

impl Account {
    /// A user in any domain, by the NT hash: MD4 of the UTF-16LE password,
    /// thirty-two hexadecimal digits as a SAM or `secretsdump` prints it.
    ///
    /// # Errors
    ///
    /// Where the text is not thirty-two hexadecimal digits.
    pub fn from_hex(user: impl Into<String>, hash: &str) -> Result<Self, AuthenticateError> {
        let digits = hash.trim().as_bytes();
        let mut bytes = [0u8; 16];
        if digits.len() != 32 {
            return Err(AuthenticateError::new(
                "an NT hash is thirty-two hexadecimal digits",
            ));
        }
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
            *byte = core::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| {
                    AuthenticateError::new("an NT hash is thirty-two hexadecimal digits")
                })?;
        }
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

    fn is(&self, user: &str, domain: &str) -> bool {
        self.user.to_uppercase() == user.to_uppercase()
            && self
                .domain
                .as_ref()
                .is_none_or(|held| held.to_uppercase() == domain.to_uppercase())
    }
}

/// The ntlm authenticator: the accounts the node holds and the challenges it
/// has issued and not yet seen answered.
pub struct Verifier {
    accounts: Vec<Account>,
    challenges: Mutex<Vec<[u8; 8]>>,
}

impl Verifier {
    /// Verifies against these accounts, with no challenge outstanding.
    #[must_use]
    pub const fn new(accounts: Vec<Account>) -> Self {
        Self {
            accounts,
            challenges: Mutex::new(Vec::new()),
        }
    }

    /// Record a server challenge the node sent in a type 2 message. It proves
    /// one response and is then spent.
    pub fn issued(&self, challenge: [u8; 8]) {
        let mut outstanding = self
            .challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if outstanding.len() >= OUTSTANDING {
            outstanding.remove(0);
        }
        outstanding.push(challenge);
    }

    /// Spend the outstanding challenge the response proves under, if any.
    fn spend(&self, key: &[u8; 16], read: &Authenticate) -> bool {
        let mut outstanding = self
            .challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let found = outstanding.iter().position(|challenge| {
            let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC takes any key length");
            mac.update(challenge);
            mac.update(&read.blob);
            mac.verify_slice(&read.proof).is_ok()
        });
        found.map(|at| outstanding.remove(at)).is_some()
    }
}

/// `NTOWFv2`: HMAC-MD5 under the NT hash over uppercase(user) then the domain,
/// UTF-16LE. MS-NLMP 3.3.2.
fn ntowf_v2(hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(hash).expect("HMAC takes any key length");
    for unit in user
        .to_uppercase()
        .encode_utf16()
        .chain(domain.encode_utf16())
    {
        mac.update(&unit.to_le_bytes());
    }
    mac.finalize().into_bytes().into()
}

/// Whether the type 3 message names the account the claim does. Where the
/// message's user and domain form a user principal name, a claim that is one
/// and any `principal.user` evidence must be the same account; a claim that
/// is a bare user is the message's user exactly, as it always was.
fn claimed_by(read: &Authenticate, presented: &Presented) -> Result<(), AuthenticateError> {
    let message = UserPrincipalName::of(&read.user, &read.domain);
    let evidence = presented
        .evidence
        .iter()
        .find(|(name, _)| name == identify::principal::USER)
        .and_then(|(_, value)| UserPrincipalName::parse(value));
    let value = UserPrincipalName::parse(&presented.value);
    let Some(message) = message else {
        return exactly(read, presented);
    };
    if value.is_none() {
        exactly(read, presented)?;
    }
    match value
        .iter()
        .chain(&evidence)
        .find(|name| !name.is(&message))
    {
        Some(other) => Err(AuthenticateError::new(format!(
            "the type 3 message names '{message}' and the claim names '{other}': another account"
        ))),
        None => Ok(()),
    }
}

/// The comparison where no domain is present: the user, as written.
fn exactly(read: &Authenticate, presented: &Presented) -> Result<(), AuthenticateError> {
    if read.user == presented.value {
        return Ok(());
    }
    Err(AuthenticateError::new(
        "the type 3 message's user is not the claimed value",
    ))
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::ntlm()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies ntlm"
            )));
        }
        let encoded = presented.proof(AUTHENTICATE_PROOF).ok_or_else(|| {
            AuthenticateError::new(format!("no {AUTHENTICATE_PROOF} proof was presented"))
        })?;
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| AuthenticateError::new("the NTLM message is not base64"))?;
        let read = Authenticate::parse(&bytes)?;

        claimed_by(&read, presented)?;
        let account = self
            .accounts
            .iter()
            .find(|account| account.is(&read.user, &read.domain))
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "the node holds no NT hash for '{}' in domain '{}'",
                    read.user, read.domain
                ))
            })?;
        if self
            .challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            return Err(AuthenticateError::new(
                "the node has no server challenge outstanding: none issued, or already spent",
            ));
        }

        let key = ntowf_v2(&account.hash, &read.user, &read.domain);
        if self.spend(&key, &read) {
            Ok(Verified::Proven)
        } else {
            Err(AuthenticateError::new(
                "the NTLMv2 response does not prove under the stored hash \
                 and any outstanding challenge",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::{blob, type3, utf16};
    use md4::{Digest, Md4};

    const CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn nt_hash(password: &str) -> [u8; 16] {
        Md4::digest(utf16(password)).into()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").expect("a String takes writes");
            text
        })
    }

    /// What a client does with a password and the server's challenge.
    fn minted(user: &str, domain: &str, password: &str, challenge: [u8; 8]) -> String {
        let key = ntowf_v2(&nt_hash(password), user, domain);
        let mut mac = Hmac::<Md5>::new_from_slice(&key).expect("a key");
        mac.update(&challenge);
        mac.update(&blob());
        let mut response = mac.finalize().into_bytes().to_vec();
        response.extend_from_slice(&blob());
        STANDARD.encode(type3(user, domain, &response))
    }

    fn verifier() -> Verifier {
        let account = Account::from_hex("Alice", &hex(&nt_hash("correct horse"))).expect("hex");
        let verifier = Verifier::new(vec![account.in_domain("corp")]);
        verifier.issued(CHALLENGE);
        verifier
    }

    fn presented(user: &str, message: &str) -> Presented {
        Presented::passed(mechanism::ntlm(), user).with_proof(AUTHENTICATE_PROOF, message)
    }

    #[test]
    fn the_nt_hash_of_a_known_password_is_the_published_one() {
        // MS-NLMP 4.2.1: the password "Password" hashes to this.
        assert_eq!(
            hex(&nt_hash("Password")),
            "a4f49c406510bdcab6824ee7c30fd852"
        );
        // MS-NLMP 4.2.4.1.1: NTOWFv2 for User, Domain, Password.
        assert_eq!(
            hex(&ntowf_v2(&nt_hash("Password"), "User", "Domain")),
            "0c868a403bfd7a93a3001ef22ef02e3f"
        );
    }

    #[test]
    fn a_response_made_with_the_right_password_is_proven_and_spends_the_challenge() {
        let gate = verifier();
        let message = minted("alice", "CORP", "correct horse", CHALLENGE);

        let verified = gate.verify(&presented("alice", &message)).expect("proven");
        let replayed = gate
            .verify(&presented("alice", &message))
            .expect_err("spent");

        assert_eq!(verified, Verified::Proven);
        assert!(replayed.message.contains("no server challenge outstanding"));
    }

    #[test]
    fn a_response_made_with_another_password_is_refused_and_the_challenge_stays() {
        let verifier = verifier();
        let wrong = minted("alice", "CORP", "wrong horse", CHALLENGE);
        let right = minted("alice", "CORP", "correct horse", CHALLENGE);

        let failure = verifier
            .verify(&presented("alice", &wrong))
            .expect_err("refused");

        assert!(failure.message.contains("does not prove"));
        assert!(verifier.verify(&presented("alice", &right)).is_ok());
    }

    #[test]
    fn a_response_to_a_challenge_the_node_never_issued_is_refused() {
        let message = minted("alice", "CORP", "correct horse", [9; 8]);

        let failure = verifier()
            .verify(&presented("alice", &message))
            .expect_err("refused");

        assert!(failure.message.contains("does not prove"));
    }

    #[test]
    fn a_user_the_node_holds_no_hash_for_is_refused_by_name() {
        let message = minted("mallory", "CORP", "correct horse", CHALLENGE);

        let failure = verifier()
            .verify(&presented("mallory", &message))
            .expect_err("refused");

        assert!(failure.message.contains("no NT hash for 'mallory'"));
    }

    #[test]
    fn a_claim_that_is_not_the_messages_user_is_refused() {
        let message = minted("alice", "CORP", "correct horse", CHALLENGE);

        let failure = verifier()
            .verify(&presented("bob", &message))
            .expect_err("refused");

        assert!(failure.message.contains("not the claimed value"));
    }

    #[test]
    fn a_claim_by_user_principal_name_is_the_account_the_message_names_by_user_and_domain() {
        for claim in ["alice@corp", "CORP\\Alice"] {
            let gate = verifier();
            let message = minted("alice", "CORP", "correct horse", CHALLENGE);
            let verified = gate.verify(&presented(claim, &message)).expect("proven");
            assert_eq!(verified, Verified::Proven, "{claim}");
        }
        // The first gate's claim: the user as the value, the name as evidence.
        let message = minted("alice", "CORP", "correct horse", CHALLENGE);
        let filed =
            presented("alice", &message).with_evidence(identify::principal::USER, "alice@corp");
        assert_eq!(verifier().verify(&filed).expect("proven"), Verified::Proven);
    }

    #[test]
    fn a_claim_of_another_account_than_the_message_names_is_refused_naming_both() {
        let message = minted("alice", "CORP", "correct horse", CHALLENGE);
        let elsewhere = presented("alice@other", &message);
        let filed =
            presented("alice", &message).with_evidence(identify::principal::USER, "bob@corp");

        for (claim, other) in [(elsewhere, "'alice@other'"), (filed, "'bob@corp'")] {
            let failure = verifier().verify(&claim).expect_err("refused");
            assert!(
                failure.message.contains("'alice@corp'") && failure.message.contains(other),
                "{}",
                failure.message
            );
        }
    }

    #[test]
    fn another_mechanism_and_a_missing_proof_are_each_refused_by_name() {
        let other = Presented::passed(mechanism::kerberos(), "alice");
        let bare = Presented::passed(mechanism::ntlm(), "alice");

        let not_ours = verifier().verify(&other).expect_err("refused");
        let missing = verifier().verify(&bare).expect_err("refused");

        assert!(not_ours.message.contains("'kerberos' was presented"));
        assert!(missing.message.contains("ntlm.authenticate"));
    }

    #[test]
    fn an_nt_hash_that_is_not_hexadecimal_is_refused() {
        let failure = Account::from_hex("alice", "not-a-hash")
            .err()
            .expect("refused");

        assert!(failure.message.contains("thirty-two"));
    }
}
