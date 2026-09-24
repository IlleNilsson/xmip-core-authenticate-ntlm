# xmip-core-authenticate-ntlm

Authenticate by ntlm: verifies the `NTLMv2` response against the stored hash. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It recomputes the `NTProofStr` of a type 3 message from the NT hash the node
holds for the user and a server challenge the node issued, and spends the
challenge when it proves. The message is read by the identify capability's
`identify::ntlm::Authenticate`, the reader the first gate uses too. A proven response is then held to its own
timestamp, within thirty-six hours of the node's clock unless said, and,
where the node says which service it is, to the target name the client wrote,
compared as a service principal name ([MS-NLMP] 3.2.5.1.2, ADR-0054).

It is held to its exchange and its channel too. Where the node says which
channel it serves, the hash of its certificate as RFC 5929 names
`tls-server-end-point`, a response bound to another channel or to none is
refused. Where the client says its message carries a MIC and the transport
presents the handshake's first two messages as the proofs `ntlm.negotiate`
and `ntlm.challenge`, the MIC must verify over all three; a node that
requires integrity refuses a response whose MIC cannot be checked. It does
not verify `NTLMv1` or LM responses, and the session key it derives for the
MIC is dropped: this gate signs and seals nothing.

No transport of the estate runs the NTLM handshake yet, so none writes the
two properties; until one does, the MIC is checked only by a host that
presents them itself.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
