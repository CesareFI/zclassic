# zclassic23/sha3

Allocation-free scalar FIPS-202 SHA3-256, SHA3-512, SHAKE128 and SHAKE256 for
C23. Streaming SHA3 layouts and symbols are the ones used by the ZClassic23
monolith. SHAKE one-shots validate pointer/length pairs and support arbitrary
caller-bounded multi-block output.

This package depends only on the exact `zclassic23/base` package root recorded
in its external dependency lock. Batched x4/AVX-512 acceleration remains owned
by `core/modules/crypto` and uses this scalar package as its byte-parity oracle.

`sha3/shake_wrap.h` provides the fixed published SHAKE256-Wrap construction
(Daemen et al., *Shaking up authenticated encryption*, EuroS&P 2025): key 32,
tag 64, rho 128, capacity 512, full 24-round Keccak-f[1600]. Plaintext and AD
are independently bounded at 4096 bytes. State, AD, input and the entire output
capacity must be disjoint valid storage. Open verifies in private storage;
refusal leaves output and state unchanged, and temporary state/plaintext are
cleansed. State destruction wipes the complete object.

The `shake_wrap` registered test freezes 392 fresh/chained reference digest
vectors from unmodified XKCP commit `4affab454735d54e78156880b3b44e38dcbf765c`,
computed by a separate system-OpenSSL SHA256 oracle over ciphertext and tag.
The vector file SHA256 is
`4f87d3630cdcfacb4e4dac6de39b3bcd1c1b3a19011d5c2e94e53931e7df3fb5`.
No XKCP runtime code or OpenSSL dependency is imported into this module.

This is a primitive, not a qualified transport. Callers must supply unique
initial AD containing a session nonce per independent stream under a key and
separate directional contexts. It provides no handshake, provisioning, replay
policy or forward secrecy. Classical margins are not a 256-bit quantum claim;
a source-level fixed-time comparison is not compiled-machine timing evidence.
