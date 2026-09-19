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
//! A response that has proven is then held to two things its own bytes say,
//! as [MS-NLMP] 3.2.5.1.2 has a server do, and the proof covers both. Its
//! timestamp must lie within [`LIFETIME`] of the node's clock, thirty-six
//! hours unless said. And where the node says which service it is
//! ([`Verifier::expecting_target`]), the target name among the response's
//! attribute pairs must be that service, compared as the capability's
//! `ServicePrincipalName`: a client relayed from another server names that
//! server and is refused naming both, and a name the client flags as taken
//! from an untrusted source is no name, as the specification says (ADR-0054).
//!
//! It is held, too, to the exchange and the channel it belongs to
//! ([`binding`]): where the node says which channel it serves
//! ([`Verifier::bound_to_channel`]) the response must be bound to that one,
//! and where the client says its message carries a MIC and the transport
//! presents the two messages before it, the MIC must verify over all three.
//! [`Verifier::requiring_integrity`] refuses a response whose MIC cannot be
//! checked at all.
//!
//! What is not verified, and refused by name: an `NTLMv1` or LM response.
//! The session key is derived for the MIC and dropped; this gate proves who
//! and signs nothing.
//!
//! The message's user and domain are compared with the claim as the identify
//! capability's `UserPrincipalName` where both form one, so a claim of
//! `jane@partnerx` is the account a type 3 for `jane` in `PARTNERX` names,
//! and a different account is refused naming both (ADR-0054).

pub mod account;
pub mod binding;
pub mod message;

pub use account::Account;
pub use binding::{Binding, CHALLENGE_PROOF, ChannelBindings, Exchange, NEGOTIATE_PROOF};
pub use message::Authenticate;

use authenticate::{AuthenticateError, Authenticator, Presented};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use context::Verified;
use hmac::{Hmac, Mac};
use identify::ntlm::ClientChallenge;
use identify::{ServicePrincipalName, UserPrincipalName};
use md5::Md5;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the base64 type 3 message under.
pub const AUTHENTICATE_PROOF: &str = "ntlm.authenticate";

/// How many challenges may be outstanding before the oldest is forgotten.
const OUTSTANDING: usize = 1024;

/// How far a response's own timestamp may lie from the node's clock, in
/// seconds. [MS-NLMP] 3.2.5.1.2 has a server fail a response further off than
/// its `MaxLifetime` and leaves the number to the implementation; thirty-six
/// hours is what its product notes give for current Windows.
pub const LIFETIME: u64 = 36 * 60 * 60;

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The ntlm authenticator: the accounts the node holds, the challenges it
/// has issued and not yet seen answered, and what it holds a proven response
/// to — its age, and the service the client meant to reach.
pub struct Verifier {
    accounts: Vec<Account>,
    challenges: Mutex<Vec<[u8; 8]>>,
    target: Option<ServicePrincipalName>,
    lifetime: u64,
    clock: Clock,
    binding: Binding,
}

impl Verifier {
    /// Verifies against these accounts, with no challenge outstanding, any
    /// target, the specification's lifetime and the system clock.
    #[must_use]
    pub fn new(accounts: Vec<Account>) -> Self {
        Self {
            accounts,
            challenges: Mutex::new(Vec::new()),
            target: None,
            lifetime: LIFETIME,
            clock: Box::new(now),
            binding: Binding::default(),
        }
    }

    /// Hold the client to the channel this node serves on: the response must
    /// be bound to it, and one bound to another or to none is refused.
    #[must_use]
    pub fn bound_to_channel(mut self, channel: ChannelBindings) -> Self {
        self.binding.channel = Some(channel);
        self
    }

    /// Refuse a response whose MIC cannot be checked: the client says it
    /// carries none, or the transport presented no messages to check it over.
    #[must_use]
    pub const fn requiring_integrity(mut self) -> Self {
        self.binding.integrity = true;
        self
    }

    /// Hold the client to this service: the target name its response carries
    /// must be the same service (ADR-0054). A client relayed from another
    /// server names that server, and is refused here. A response that names
    /// no target, or flags its target as taken from an untrusted source —
    /// which [MS-NLMP] 3.2.5.1.2 has a server treat as none — is refused too.
    #[must_use]
    pub fn expecting_target(mut self, service: ServicePrincipalName) -> Self {
        self.target = Some(service);
        self
    }

    /// How far a response's timestamp may lie from the node's clock.
    #[must_use]
    pub const fn with_lifetime(mut self, seconds: u64) -> Self {
        self.lifetime = seconds;
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// What a response that has proven is still held to. The proof covers
    /// every byte read here, so by now these are the client's own words.
    fn held_to(&self, client: &ClientChallenge) -> Result<(), AuthenticateError> {
        let made = i64::try_from(client.made_at()).unwrap_or(i64::MAX);
        let apart = (self.clock)().abs_diff(made);

        if apart > self.lifetime {
            return Err(AuthenticateError::new(format!(
                "the response was made {apart} seconds from the node's clock, \
                 and the node takes none further off than {}",
                self.lifetime
            )));
        }

        let Some(expected) = &self.target else {
            return Ok(());
        };
        let Some(named) = client.supplied_target() else {
            let why = if client.untrusted {
                "names a target it took from an untrusted source"
            } else {
                "names no target"
            };
            return Err(AuthenticateError::new(format!(
                "the node expects the target '{expected}' and the response {why}"
            )));
        };

        match ServicePrincipalName::parse(named) {
            Some(service) if service.is(expected) => Ok(()),
            _ => Err(AuthenticateError::new(format!(
                "the response was made for '{named}' and this node is '{expected}'"
            ))),
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
    fn spend(&self, key: &[u8; 16], read: &Authenticate) -> Option<[u8; 8]> {
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
        found.map(|at| outstanding.remove(at))
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
        let Some(server_challenge) = self.spend(&key, &read) else {
            return Err(AuthenticateError::new(
                "the NTLMv2 response does not prove under the stored hash \
                 and any outstanding challenge",
            ));
        };
        let Some(client) = ClientChallenge::read(&read.blob)
            .map_err(|failure| AuthenticateError::new(failure.message))?
        else {
            return Ok(Verified::Proven);
        };

        self.held_to(&client)?;
        let negotiate = decoded(presented, NEGOTIATE_PROOF)?;
        let challenge = decoded(presented, CHALLENGE_PROOF)?;
        self.binding.check(
            &client,
            &Exchange {
                negotiate: negotiate.as_deref(),
                challenge: challenge.as_deref(),
                authenticate: &bytes,
                read: &read,
                response_key: &key,
                server_challenge,
            },
        )?;

        Ok(Verified::Proven)
    }
}

/// A message the transport presented as a proof, where it did.
fn decoded(presented: &Presented, name: &str) -> Result<Option<Vec<u8>>, AuthenticateError> {
    presented
        .proof(name)
        .map(|encoded| {
            STANDARD
                .decode(encoded.trim())
                .map_err(|_| AuthenticateError::new(format!("the {name} proof is not base64")))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::tests::{encrypted, sealed};
    use crate::message::tests::{blob, type3, type3_exchanging, utf16};
    use md4::{Digest, Md4};

    const CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const NOW: i64 = 1_800_000_000;

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
        minted_over(user, domain, password, challenge, &blob())
    }

    /// The same, over a blob of the test's choosing: its time, its target.
    fn minted_over(
        user: &str,
        domain: &str,
        password: &str,
        challenge: [u8; 8],
        blob: &[u8],
    ) -> String {
        let key = ntowf_v2(&nt_hash(password), user, domain);
        let mut mac = Hmac::<Md5>::new_from_slice(&key).expect("a key");
        mac.update(&challenge);
        mac.update(blob);
        let mut response = mac.finalize().into_bytes().to_vec();
        response.extend_from_slice(blob);
        STANDARD.encode(type3(user, domain, &response))
    }

    fn verifier() -> Verifier {
        let account = Account::from_hex("Alice", &hex(&nt_hash("correct horse"))).expect("hex");
        let verifier = Verifier::new(vec![account.in_domain("corp")]).with_clock(|| NOW);
        verifier.issued(CHALLENGE);
        verifier
    }

    #[test]
    fn a_proven_response_is_held_to_the_service_the_node_is() {
        // MS-NLMP 3.2.5.1.2 and ADR-0054: the target name is the client's own
        // word for which server it meant, and the proof covers it.
        let here = ServicePrincipalName::parse("HTTP/xmip.example").expect("a name");
        let made = |target: Option<&str>, flags: u32| {
            let blob = identify::ntlm::blob_for(NOW.unsigned_abs(), target, flags);
            minted_over("alice", "CORP", "correct horse", CHALLENGE, &blob)
        };

        let ours = made(Some("HTTP/XMIP.Example"), 0x2);
        let verified = verifier()
            .expecting_target(here.clone())
            .verify(&presented("alice", &ours))
            .expect("the same service, spelled another way");
        assert_eq!(verified, Verified::Proven);

        let relayed = made(Some("HTTP/other.example"), 0x2);
        let failure = verifier()
            .expecting_target(here.clone())
            .verify(&presented("alice", &relayed))
            .expect_err("another server's");
        assert!(failure.message.contains("HTTP/other.example"), "{failure}");
        assert!(failure.message.contains("HTTP/xmip.example"), "{failure}");

        let untrusted = made(Some("HTTP/xmip.example"), 0x2 | 0x4);
        let failure = verifier()
            .expecting_target(here.clone())
            .verify(&presented("alice", &untrusted))
            .expect_err("untrusted");
        assert!(failure.message.contains("untrusted source"), "{failure}");

        let silent = made(None, 0x2);
        let failure = verifier()
            .expecting_target(here)
            .verify(&presented("alice", &silent))
            .expect_err("no target");
        assert!(failure.message.contains("names no target"), "{failure}");
        assert!(verifier().verify(&presented("alice", &silent)).is_ok());
    }

    #[test]
    fn a_proven_response_made_too_long_ago_is_refused_saying_how_long() {
        let old = identify::ntlm::blob_for((NOW - 37 * 60 * 60).unsigned_abs(), None, 0);
        let stale = minted_over("alice", "CORP", "correct horse", CHALLENGE, &old);

        let failure = verifier()
            .verify(&presented("alice", &stale))
            .expect_err("stale");
        assert!(failure.message.contains("133200 seconds"), "{failure}");

        let kept = verifier().with_lifetime(48 * 60 * 60);
        assert!(kept.verify(&presented("alice", &stale)).is_ok());
    }

    fn presented(user: &str, message: &str) -> Presented {
        Presented::passed(mechanism::ntlm(), user).with_proof(AUTHENTICATE_PROOF, message)
    }

    /// The three messages of one exchange, as a Windows client makes them:
    /// key exchange negotiated, a MIC over all three, bound to `channel`.
    struct Spoken {
        negotiate: Vec<u8>,
        challenge: Vec<u8>,
        authenticate: Vec<u8>,
    }

    impl Spoken {
        fn over(channel: Option<[u8; 16]>) -> Self {
            let mut negotiate = b"NTLMSSP\0".to_vec();
            negotiate.extend_from_slice(&1u32.to_le_bytes());
            negotiate.extend_from_slice(&0xE208_8297u32.to_le_bytes());
            let mut challenge = b"NTLMSSP\0".to_vec();
            challenge.extend_from_slice(&2u32.to_le_bytes());
            challenge.extend_from_slice(&[0u8; 12]);
            challenge.extend_from_slice(&CHALLENGE);
            challenge.extend_from_slice(&[0u8; 8]);

            let blob = identify::ntlm::blob_bound(NOW.unsigned_abs(), None, 0x2, channel);
            let key = ntowf_v2(&nt_hash("correct horse"), "alice", "CORP");
            let mut mac = Hmac::<Md5>::new_from_slice(&key).expect("a key");
            mac.update(&CHALLENGE);
            mac.update(&blob);
            let proof = mac.finalize().into_bytes();
            let mut response = proof.to_vec();
            response.extend_from_slice(&blob);

            let mut mac = Hmac::<Md5>::new_from_slice(&key).expect("a key");
            mac.update(&proof);
            let base: [u8; 16] = mac.finalize().into_bytes().into();
            let random = [0x55u8; 16];
            let mut authenticate = type3_exchanging(
                "alice",
                "CORP",
                &response,
                0x4000_0000,
                &encrypted(&base, &random),
            );
            sealed(&random, &negotiate, &challenge, &mut authenticate);

            Self {
                negotiate,
                challenge,
                authenticate,
            }
        }

        fn presented(&self) -> Presented {
            presented("alice", &STANDARD.encode(&self.authenticate))
                .with_proof(NEGOTIATE_PROOF, STANDARD.encode(&self.negotiate))
                .with_proof(CHALLENGE_PROOF, STANDARD.encode(&self.challenge))
        }
    }

    #[test]
    fn an_exchange_whose_mic_and_channel_hold_is_proven_and_a_changed_message_is_not() {
        let channel = ChannelBindings::tls_server_end_point(&[0xAB; 32]);
        let strict = || {
            verifier()
                .bound_to_channel(ChannelBindings::tls_server_end_point(&[0xAB; 32]))
                .requiring_integrity()
        };

        let spoken = Spoken::over(Some(channel.hash()));
        let verified = strict().verify(&spoken.presented()).expect("it all holds");
        assert_eq!(verified, Verified::Proven);

        // Someone in the middle cleared a flag in the first message.
        let mut downgraded = Spoken::over(Some(channel.hash()));
        downgraded.negotiate[12] ^= 0x10;
        let failure = strict()
            .verify(&downgraded.presented())
            .expect_err("changed");
        assert!(failure.message.contains("MIC does not verify"), "{failure}");

        let mut another = Spoken::over(Some(channel.hash()));
        another.challenge[24] ^= 0xFF;
        let failure = strict().verify(&another.presented()).expect_err("another");
        assert!(failure.message.contains("not the one"), "{failure}");
    }

    #[test]
    fn a_response_bound_to_another_channel_or_to_none_is_refused_where_the_node_is_bound() {
        let bound = || verifier().bound_to_channel(ChannelBindings::tls_server_end_point(&[1; 32]));
        let elsewhere = ChannelBindings::tls_server_end_point(&[2; 32]);

        let relayed = Spoken::over(Some(elsewhere.hash()));
        let failure = bound().verify(&relayed.presented()).expect_err("relayed");
        assert!(failure.message.contains("another channel"), "{failure}");

        let unbound = Spoken::over(None);
        let failure = bound().verify(&unbound.presented()).expect_err("unbound");
        assert!(failure.message.contains("bound to none"), "{failure}");
        assert!(verifier().verify(&unbound.presented()).is_ok());
    }

    #[test]
    fn a_mic_that_cannot_be_checked_is_refused_only_where_the_node_requires_one() {
        let spoken = Spoken::over(None);
        let alone = presented("alice", &STANDARD.encode(&spoken.authenticate));

        assert!(verifier().verify(&alone).is_ok());
        let failure = verifier()
            .requiring_integrity()
            .verify(&alone)
            .expect_err("unchecked");
        assert!(failure.message.contains("ntlm.negotiate"), "{failure}");

        let silent = minted("alice", "CORP", "correct horse", CHALLENGE);
        let failure = verifier()
            .requiring_integrity()
            .verify(&presented("alice", &silent))
            .expect_err("no MIC");
        assert!(failure.message.contains("carries none"), "{failure}");
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
