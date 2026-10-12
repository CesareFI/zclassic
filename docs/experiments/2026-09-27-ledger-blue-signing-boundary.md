<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue transparent signing boundary

Local time: 2026-09-27T05:41:53-04:00

UTC: 2026-09-27T09:41:53Z

## Question

Can the C23 wallet consume only a touchscreen-confirmed ZIP-243 input digest,
check the signing public key against the Blue-derived account hash, and return
a canonical low-S secp256k1 ECDSA signature without exposing an untested
signing command to the physical device?

## Result

Two portable C23 modules now compile for both host and ARM. The DER module
rejects malformed lengths, negative or nonminimal integers, zero or
out-of-range secp256k1 values, and trailing bytes. It normalizes high-S
signatures in place. Host tests verify 32 real OpenSSL secp256k1 signatures
after normalization and exercise 10,000 deterministic malformed inputs under
sanitizers.

The signing boundary consumes the next ordered digest only after the review
confirmation latch is armed. It invokes the signer once, checks the returned
compressed public key's HASH160 against the verified input's external or
internal Blue-derived account hash, normalizes DER, and returns input index,
path, public key, and signature. A failure clears the response and aborts the
review. A host test signs a synthetic digest with a real OpenSSL key and
independently verifies the returned signature. Missing approval and a wrong
input index never call the signer; signer refusal, malformed DER, and a
mismatched account hash produce no response payload.

Clang 22.1.6 Debug with AddressSanitizer and UndefinedBehaviorSanitizer and
GCC 16.1.1 Release each passed 29/29 local tests. Two independently patched
Ledger Blue SDK trees at revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`
with Clang 22.1.6 and ARM GCC 16.2.0
compiled the new source and produced identical `.text` SHA-256
`079b0606e90c3bf55f9c28d8faa3546b7e866fda7bb61801865762a0f5ec8de0`.
The device image remains Wallet 0.2.13 with 33,536 bytes of `.text`, 5,296
bytes of `.bss`, and zero `.data`. CPU: AMD Ryzen 7 PRO 8840U with Radeon
780M Graphics. Test date: 2026-09-27.

## Limit

The signer modules are compiled but unreachable in the device image, so its
identical `.text` does not prove signing works on Blue. The callback that
derives a private key and calls the SDK's ECDSA syscall is still missing.
There is no signing APDU, host transaction assembly, device signature test,
or measured active-signing stack path. The existing 752-byte stack gate
covers only the read-only app. The Blue must also pass physical USB,
touchscreen, EXIT, and recovery tests before any signing command is enabled.
