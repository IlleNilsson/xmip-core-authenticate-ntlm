//! The AUTHENTICATE message, read for what the second gate checks.
//!
//! MS-NLMP 2.2.1.3 lays a type 3 message out as a fixed header of
//! `Len, MaxLen, BufferOffset` fields pointing into a payload: the LM
//! response at 12, the NT response at 20, the domain at 28, the user at 36,
//! the workstation at 44 and the negotiated flags at 60. An `NTLMv2` NT
//! response is sixteen bytes of `NTProofStr` followed by the client's blob
//! (2.2.2.8), whose first two bytes are both one; a response of exactly
//! twenty-four bytes is `NTLMv1` and is named as such so the refusal can say so.

use authenticate::AuthenticateError;

const SIGNATURE: &[u8] = b"NTLMSSP\0";
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const NT_RESPONSE_FIELDS: usize = 20;
const DOMAIN_FIELDS: usize = 28;
const USER_FIELDS: usize = 36;
const FLAGS: usize = 60;
const PROOF_LENGTH: usize = 16;

/// What a type 3 message carries that the response is computed from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticate {
    /// The `UserName` field, as the client spelled it.
    pub user: String,
    /// The `DomainName` field, as the client spelled it; it enters the hash
    /// exactly so.
    pub domain: String,
    /// The first sixteen bytes of the NT response: the `NTProofStr`.
    pub proof: [u8; PROOF_LENGTH],
    /// The rest of the NT response: the client's blob, which the proof covers.
    pub blob: Vec<u8>,
}

impl Authenticate {
    /// Read a type 3 message.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an NTLMSSP AUTHENTICATE message, a field
    /// points outside the message, or the NT response is not `NTLMv2`.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthenticateError> {
        if !bytes.starts_with(SIGNATURE) {
            return Err(AuthenticateError::new(
                "the NTLM message has no NTLMSSP signature",
            ));
        }
        if u32_at(bytes, 8) != Some(3) {
            return Err(AuthenticateError::new(
                "the NTLM message is not an AUTHENTICATE (type 3) message",
            ));
        }
        let flags = u32_at(bytes, FLAGS).ok_or_else(|| {
            AuthenticateError::new("the NTLM AUTHENTICATE message is truncated before its flags")
        })?;
        let unicode = flags & NEGOTIATE_UNICODE != 0;

        let response = field(bytes, NT_RESPONSE_FIELDS, "NtChallengeResponse")?;
        if response.len() == 24 {
            return Err(AuthenticateError::new(
                "the NT response is NTLMv1 and this node verifies NTLMv2 only",
            ));
        }
        let Some((proof, blob)) = response.split_first_chunk::<PROOF_LENGTH>() else {
            return Err(AuthenticateError::new(
                "the NTLM AUTHENTICATE message carries no NTLMv2 response",
            ));
        };
        if !blob.starts_with(&[1, 1]) || blob.len() < 28 {
            return Err(AuthenticateError::new(
                "the NT response's blob is not an NTLMv2 client challenge",
            ));
        }

        Ok(Self {
            user: text(field(bytes, USER_FIELDS, "UserName")?, unicode, "UserName")?,
            domain: text(
                field(bytes, DOMAIN_FIELDS, "DomainName")?,
                unicode,
                "DomainName",
            )?,
            proof: *proof,
            blob: blob.to_vec(),
        })
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// One `Len, MaxLen, BufferOffset` field, and the bytes it points at.
fn field<'a>(bytes: &'a [u8], at: usize, name: &str) -> Result<&'a [u8], AuthenticateError> {
    let (Some(length), Some(offset)) = (u16_at(bytes, at), u32_at(bytes, at + 4)) else {
        return Err(AuthenticateError::new(format!(
            "the NTLM AUTHENTICATE message is truncated before its {name} field"
        )));
    };
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    bytes
        .get(offset..offset.saturating_add(usize::from(length)))
        .ok_or_else(|| {
            AuthenticateError::new(format!(
                "the NTLM AUTHENTICATE message's {name} points outside the message"
            ))
        })
}

fn text(payload: &[u8], unicode: bool, name: &str) -> Result<String, AuthenticateError> {
    if unicode {
        let units: Vec<u16> = payload
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)
            .map_err(|_| AuthenticateError::new(format!("the NTLM {name} is not UTF-16")))
    } else {
        Ok(payload.iter().map(|byte| char::from(*byte)).collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A Unicode type 3 with the given NT response: MS-NLMP 2.2.1.3.
    pub(crate) fn type3(user: &str, domain: &str, response: &[u8]) -> Vec<u8> {
        let payloads = [
            vec![0; 24],
            response.to_vec(),
            utf16(domain),
            utf16(user),
            utf16("WORKSTATION"),
            Vec::new(),
        ];
        let mut message = SIGNATURE.to_vec();
        message.extend_from_slice(&3u32.to_le_bytes());
        let mut offset = 64u32;
        for payload in &payloads {
            let length = u16::try_from(payload.len()).expect("a short field");
            message.extend_from_slice(&length.to_le_bytes());
            message.extend_from_slice(&length.to_le_bytes());
            message.extend_from_slice(&offset.to_le_bytes());
            offset += u32::from(length);
        }
        message.extend_from_slice(&NEGOTIATE_UNICODE.to_le_bytes());
        for payload in &payloads {
            message.extend_from_slice(payload);
        }
        message
    }

    pub(crate) fn blob() -> Vec<u8> {
        let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&[0x11; 8]);
        blob.extend_from_slice(&[0xaa; 8]);
        blob.extend_from_slice(&[0; 8]);
        blob
    }

    #[test]
    fn a_type_3_is_read_into_its_names_its_proof_and_its_blob() {
        let mut response = vec![7u8; 16];
        response.extend_from_slice(&blob());

        let read = Authenticate::parse(&type3("alice", "CORP", &response)).expect("read");

        assert_eq!(read.user, "alice");
        assert_eq!(read.domain, "CORP");
        assert_eq!(read.proof, [7u8; 16]);
        assert_eq!(read.blob, blob());
    }

    #[test]
    fn an_ntlmv1_response_is_refused_by_name() {
        let failure = Authenticate::parse(&type3("alice", "CORP", &[0; 24])).expect_err("v1");

        assert!(failure.message.contains("NTLMv1"));
    }

    #[test]
    fn a_challenge_message_is_not_an_authenticate() {
        let mut message = SIGNATURE.to_vec();
        message.extend_from_slice(&2u32.to_le_bytes());

        let failure = Authenticate::parse(&message).expect_err("type 2");

        assert!(failure.message.contains("type 3"));
    }

    #[test]
    fn a_field_pointing_outside_the_message_is_refused_by_its_name() {
        let mut message = type3("alice", "CORP", &[0; 44]);
        message.truncate(70);

        let failure = Authenticate::parse(&message).expect_err("truncated");

        assert!(failure.message.contains("points outside"));
    }
}
