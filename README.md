# xmip-core-authenticate-ntlm

Authenticate by ntlm: verifies the `NTLMv2` response against the stored hash. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It recomputes the `NTProofStr` of a type 3 message from the NT hash the node
holds for the user and a server challenge the node issued, and spends the
challenge when it proves. It does not verify `NTLMv1` or LM responses, the MIC or
channel bindings, and it does not derive a session key; each is refused or
left alone by name in the crate documentation.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
