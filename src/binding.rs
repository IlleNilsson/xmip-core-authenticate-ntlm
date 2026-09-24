//! What binds a proven response to this exchange and to this channel: the
//! MIC, and the channel bindings.
//!
//! **The MIC** ([MS-NLMP] 3.1.5.1.2, 3.2.5.1.2). A client that sets 0x2 in
//! its `MsvAvFlags` says its AUTHENTICATE message carries one, sixteen bytes
//! at offset 72 (`xmip-core-library-ntlm` knows where): HMAC-MD5 under the exported session key over the NEGOTIATE,
//! the CHALLENGE and the AUTHENTICATE message as sent, the MIC's own bytes
//! zero. It is what stops someone in the middle rewriting the flags the two
//! ends negotiated. The session key is derived as 3.3.2 and 3.4.5.1 say: the
//! session base key is HMAC-MD5 under the response key over the `NTProofStr`;
//! under `NTLMv2` that is the key exchange key; and where the client
//! negotiated key exchange (`0x4000_0000`) the exported key is what RC4 under
//! that key opens the `EncryptedRandomSessionKey` to. The key is derived for
//! the MIC and dropped: this gate still signs and seals nothing.
//!
//! **The channel** (3.1.5.1.2, RFC 5929). `MsvAvChannelBindings` is the MD5
//! of a `gss_channel_bindings_struct` whose addresses are empty and whose
//! application data is `tls-server-end-point:` and the hash of the server's
//! certificate. A response relayed from a TLS connection to someone else's
//! certificate carries that certificate's hash, and the proof covers it.
//!
//! Both need what only the transport holds. The channel is configuration,
//! the node's own certificate, and is told to the verifier. The first two
//! messages are this connection's, and ride as the proofs `ntlm.negotiate`
//! and `ntlm.challenge` (`identify::evidence`); where the transport presents
//! neither the MIC is not checked, unless the node requires it, and then the
//! response is refused.

use authenticate::AuthenticateError;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use ntlm::flags::NEGOTIATE_KEY_EXCH;
use ntlm::{Authenticate, Challenge, ClientChallenge, MIC_LENGTH, MIC_OFFSET};

/// The hash of a channel, as a client writes it into its response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBindings([u8; 16]);

impl ChannelBindings {
    /// The channel RFC 5929 section 4 names `tls-server-end-point`, from the
    /// hash of the node's certificate: SHA-256 of its DER where the
    /// certificate is signed with MD5 or SHA-1, the signature's own hash
    /// otherwise. The host hashes; this crate reads no certificate.
    #[must_use]
    pub fn tls_server_end_point(certificate_hash: &[u8]) -> Self {
        let mut data = b"tls-server-end-point:".to_vec();
        data.extend_from_slice(certificate_hash);
        Self::of_application_data(&data)
    }

    /// Any channel, by its application data: four zero words for the two
    /// empty addresses, the data's length, the data, and MD5 over it all.
    #[must_use]
    pub fn of_application_data(data: &[u8]) -> Self {
        let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let mut hash = Md5::new();
        hash.update([0u8; 16]);
        hash.update(length.to_le_bytes());
        hash.update(data);
        Self(hash.finalize().into())
    }

    /// The sixteen bytes a client bound to this channel writes.
    #[must_use]
    pub const fn hash(&self) -> [u8; 16] {
        self.0
    }
}

/// What a proven response is held to beyond its own words.
#[derive(Clone, Debug, Default)]
pub struct Binding {
    /// The channel the node serves on, where it holds clients to it.
    pub channel: Option<ChannelBindings>,
    /// Whether a response with no verifiable MIC is refused.
    pub integrity: bool,
}

/// One exchange, as the second gate holds it once the proof has verified.
pub struct Exchange<'a> {
    /// The NEGOTIATE message, where the transport presented it.
    pub negotiate: Option<&'a [u8]>,
    /// The CHALLENGE message, where the transport presented it.
    pub challenge: Option<&'a [u8]>,
    /// The AUTHENTICATE message as it arrived.
    pub authenticate: &'a [u8],
    /// The same, read.
    pub read: &'a Authenticate,
    /// `NTOWFv2` for the account: the response key.
    pub response_key: &'a [u8; 16],
    /// The server challenge the response proved under.
    pub server_challenge: [u8; 8],
}

impl Binding {
    /// Hold a proven response to the channel and to its MIC.
    ///
    /// # Errors
    ///
    /// Naming what did not hold.
    pub fn check(
        &self,
        client: &ClientChallenge,
        exchange: &Exchange<'_>,
    ) -> Result<(), AuthenticateError> {
        if let Some(expected) = &self.channel {
            match client.channel {
                Some(bound) if bound == expected.0 => {}
                Some(_) => {
                    return Err(AuthenticateError::new(
                        "the response is bound to another channel than the one this node \
                         serves: it was made for a connection to someone else",
                    ));
                }
                None => {
                    return Err(AuthenticateError::new(
                        "the node holds clients to its channel and the response is bound to none",
                    ));
                }
            }
        }

        let refuse = |why: &str| {
            if self.integrity {
                Err(AuthenticateError::new(format!(
                    "the node requires a MIC and {why}"
                )))
            } else {
                Ok(())
            }
        };
        if !client.integrity {
            return refuse("the response says its message carries none");
        }
        let (Some(negotiate), Some(challenge)) = (exchange.negotiate, exchange.challenge) else {
            return refuse(
                "the transport presented no ntlm.negotiate and ntlm.challenge to check it over",
            );
        };

        if Challenge::parse(challenge)?.server_challenge != exchange.server_challenge {
            return Err(AuthenticateError::new(
                "the CHALLENGE message presented is not the one the response proved under",
            ));
        }

        let (proof, _) = exchange.read.ntlmv2()?;
        let key = session_key(exchange.response_key, proof, exchange.read)?;
        verify_mic(&key, negotiate, challenge, exchange.authenticate)
    }
}

/// The exported session key: [MS-NLMP] 3.3.2 and 3.4.5.1.
///
/// # Errors
///
/// Where key exchange was negotiated and the encrypted key is not sixteen
/// bytes.
pub(crate) fn session_key(
    response_key: &[u8; 16],
    proof: &[u8; 16],
    read: &Authenticate,
) -> Result<[u8; 16], AuthenticateError> {
    let mut mac = Hmac::<Md5>::new_from_slice(response_key).expect("HMAC takes any key length");
    mac.update(proof);
    let base: [u8; 16] = mac.finalize().into_bytes().into();

    if read.flags & NEGOTIATE_KEY_EXCH == 0 {
        return Ok(base);
    }

    <[u8; 16]>::try_from(rc4(&base, &read.session_key)).map_err(|_| {
        AuthenticateError::new(
            "key exchange was negotiated and the EncryptedRandomSessionKey is not sixteen bytes",
        )
    })
}

/// The MIC over the three messages, compared in constant time.
fn verify_mic(
    key: &[u8; 16],
    negotiate: &[u8],
    challenge: &[u8],
    authenticate: &[u8],
) -> Result<(), AuthenticateError> {
    let Some(carried) = Authenticate::mic(authenticate) else {
        return Err(AuthenticateError::new(
            "the response says its message carries a MIC and the message is too short to",
        ));
    };

    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(negotiate);
    mac.update(challenge);
    mac.update(&authenticate[..MIC_OFFSET]);
    mac.update(&[0u8; MIC_LENGTH]);
    mac.update(&authenticate[MIC_OFFSET + MIC_LENGTH..]);

    mac.verify_slice(carried).map_err(|_| {
        AuthenticateError::new(
            "the MIC does not verify: a message of this exchange was changed on its way",
        )
    })
}

/// RC4, for the one use MS-NLMP has left for it here: opening sixteen bytes
/// of session key. Not a cipher this estate protects anything with.
fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state: [u8; 256] = core::array::from_fn(|at| u8::try_from(at).unwrap_or(0));
    let mut swap = 0u8;

    for at in 0..256 {
        swap = swap
            .wrapping_add(state[at])
            .wrapping_add(key[at % key.len()]);
        state.swap(at, usize::from(swap));
    }

    let (mut first, mut second) = (0u8, 0u8);
    data.iter()
        .map(|byte| {
            first = first.wrapping_add(1);
            second = second.wrapping_add(state[usize::from(first)]);
            state.swap(usize::from(first), usize::from(second));
            let at = state[usize::from(first)].wrapping_add(state[usize::from(second)]);
            byte ^ state[usize::from(at)]
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What a client computes and writes at offset 72.
    pub(crate) fn sealed(
        key: &[u8; 16],
        negotiate: &[u8],
        challenge: &[u8],
        authenticate: &mut [u8],
    ) {
        let mut mac = Hmac::<Md5>::new_from_slice(key).expect("a key");
        mac.update(negotiate);
        mac.update(challenge);
        mac.update(authenticate);
        let mic: [u8; 16] = mac.finalize().into_bytes().into();
        authenticate[MIC_OFFSET..MIC_OFFSET + MIC_LENGTH].copy_from_slice(&mic);
    }

    pub(crate) fn encrypted(base: &[u8; 16], random: &[u8; 16]) -> Vec<u8> {
        rc4(base, random)
    }

    #[test]
    fn rc4_is_the_keystream_rfc_6229_gives_for_a_forty_bit_key() {
        let stream = rc4(&[1, 2, 3, 4, 5], &[0u8; 8]);

        assert_eq!(stream, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27]);
    }

    #[test]
    fn the_session_key_is_the_one_ms_nlmp_4_2_4_works_through() {
        // User "User", domain "Domain", password "Password": section 4.2.4.
        let response_key = [
            0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
            0x2e, 0x3f,
        ];
        let proof = [
            0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
            0x6a, 0x1c,
        ];
        let base = [
            0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9,
            0x5c, 0xa3,
        ];
        let encrypted = vec![
            0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90, 0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9,
            0xd0, 0x3e,
        ];
        let mut read = Authenticate {
            user: "User".to_string(),
            domain: "Domain".to_string(),
            workstation: String::new(),
            flags: 0,
            lm_response: Vec::new(),
            nt_response: proof.to_vec(),
            session_key: Vec::new(),
        };

        assert_eq!(
            session_key(&response_key, &proof, &read).expect("a key"),
            base
        );

        read.flags = NEGOTIATE_KEY_EXCH;
        read.session_key = encrypted;
        assert_eq!(
            session_key(&response_key, &proof, &read).expect("a key"),
            [0x55; 16]
        );

        read.session_key.truncate(8);
        let failure = session_key(&response_key, &proof, &read).expect_err("short");
        assert!(failure.message.contains("sixteen bytes"), "{failure}");
    }

    #[test]
    fn a_channel_is_the_md5_of_empty_addresses_and_the_application_data() {
        let bound = ChannelBindings::tls_server_end_point(&[0xAB; 32]);
        let mut structure = vec![0u8; 16];
        structure.extend_from_slice(&53u32.to_le_bytes());
        structure.extend_from_slice(b"tls-server-end-point:");
        structure.extend_from_slice(&[0xAB; 32]);
        let expected: [u8; 16] = Md5::digest(&structure).into();

        assert_eq!(bound.hash(), expected);
        assert_ne!(
            bound,
            ChannelBindings::tls_server_end_point(&[0xAC; 32]),
            "another certificate is another channel"
        );
    }
}
