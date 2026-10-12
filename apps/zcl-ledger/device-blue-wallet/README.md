<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Wallet candidate for Ledger Blue

Version 0.3.46 defers USB-reset erasure while a payment command is inside
an SDK hash or signing callback. It invalidates the in-flight result and
erases the review when the command returns. A reset during the first payment
command or the signer callback returns no signature and leaves no approval.
An approval timeout during signing follows the same deferred cleanup path.
Release and sanitized Debug suites each passed 63 of 63 tests. Two clean
builds against separate copies of the pinned SDK produced identical
54,272-byte `.text` SHA-256
`d005d4fa9d4a77cf1781c6cf566d7932e2468d32d0b8f6f11acb60110ffe28fb`
and Intel HEX SHA-256
`dbc29199ed92ba88144ff0d130bc7da6c062634b76929a44989089e0c5270a46`.
`.data` is zero and `.bss` is 5,120 bytes. The largest modeled payment
frame is 1,128 bytes plus a 512-byte margin within the 2,048-byte stack
reserve; BOLOS frames are excluded. The current image remains blocked from
installation until physical validation. The
[in-flight interrupt experiment](../../../docs/experiments/2026-09-29-ledger-blue-payment-inflight-interrupt.md)
records the failure, correction, and physical transport boundary.
Source after that image drops an earlier approval at boot, before
derivation reuses the payment workspace. That boot reset is not in the
pinned 0.3.46 bytes. The
[laptop payment-fact experiment](../../../docs/experiments/2026-09-29-ledger-blue-laptop-payment-facts.md)
records the host binding and the unchanged image pin.

Version 0.3.45 binds the final SIGN ZCL page to the verified input digest
records and full unsigned-wire commitment before the page is drawn. The
touchscreen callback rechecks that binding, and every signing request
rechecks it after approval. A changed digest or commitment aborts and erases
the review. The image is byte-pinned for offline identification, while
installation remains blocked pending physical validation.

Version 0.3.44 returns the device's SHA-256 commitment to the full unsigned
transaction after its three review passes. The host compares all 32 bytes
with its frozen review wire before uploading previous transactions or
requesting signing. A corrupted commitment aborts and erases review state.
This image is not installer-whitelisted or physically tested.

Version 0.3.43 validates APDU request, reply, and reply-length storage
before any rejection can write through those pointers. A red regression
showed that an aliased reply could erase the device account hash while
leaving account readiness set; the corrected path rejects that layout
without altering the account hash. The ARM stack gate measures the new
storage-check frame. This image is not installer-whitelisted or physically
tested.

Version 0.3.42 also checks input records inside the signer callback, after
the current digest is consumed and before any signature can be returned.
A simulated callback change to the next input digest now rejects and erases
the first signature reply. The ARM stack gate includes the new signer and
record-hash frames. This build is not installer-whitelisted or physically
tested.

Version 0.3.41 rejects signing if a stored input digest or derivation path
changes after final touchscreen approval. The app hashes all fixed input
records when approval is granted, checks that hash before every signing
APDU, and refreshes it after each valid nonfinal signature. Device-state
fault injections before the first and second signatures abort without
calling the signer and erase the input records and APDU reply. Release and
sanitized Debug tests each passed 60/60; the ARM build uses 51,968 bytes of
`.text`, zero `.data`, and 5,120 bytes of `.bss`. The new image is not
installer-whitelisted or physically tested.

Version 0.3.40 binds the final SIGN ZCL tap to the amounts, input path label,
branch ID, lock time, and expiry height displayed on the final payment page.
The callback aborts if current payment facts no longer match those labels.
The final page stores a copy of the drawn facts in its unused address slot,
so a coordinated change to payment state and label text also aborts. Six
fault-injection cases test changes after display. The Blue stack gate
now requires and measures the signing approval callback; its modeled path
uses 872 bytes, within the 2,048-byte stack reservation and 512-byte margin.
The image has 51,712 bytes of `.text`, zero `.data`, and 5,120 bytes of
`.bss`. Two clean pinned-SDK builds matched `.text` SHA-256
`6b4eed2f4c8c2f61206de3e269c26c9eb6ee00a4939200768694f27c761dc94b`
and Intel HEX SHA-256
`23d9d029473dc8faf4b656cfc2023696e1f2b21e82c76b92821bfb882cf593b8`.
Release and sanitized Debug each passed 60 of 60 tests. The
[final approval experiment](../../../docs/experiments/2026-09-29-ledger-blue-final-approval-binding.md)
records the red test, correction, stack gate, and limits. The image is not
installer-whitelisted or physically tested.

Version 0.3.39 rejects CONTINUE if the pending transparent output no longer
matches the amount, address, output index, and account label drawn on the Blue.
A host fault-injection test changed the amount after display: the old callback
accepted it, while the corrected callback aborts and clears review state.
The corrected Blue image uses 50,176 bytes of `.text`, zero `.data`, and
5,120 bytes of `.bss`; the modeled output-touch path uses 888 bytes plus a
512-byte margin inside the 2,048-byte stack reservation. BOLOS frames are
excluded. Two clean pinned-SDK builds produced identical `.text` SHA-256
`a299fb189939f0ca06b3aaf29bcd3fadb0f1f21df69f283f84fa798b70f0381e`
and Intel HEX SHA-256
`52c8e5869bbdd6de72e3793a30f95d9a2c414adfc8f94c3ad0f32111829ff80b`.
Release and sanitized Debug suites each passed 60 of 60 tests. The
[output review experiment](../../../docs/experiments/2026-09-29-ledger-blue-output-screen-binding.md)
records the reproduced failure, correction, measurements, and limits. The
image is not installer-whitelisted or physically tested.

Version 0.3.38 rejects signer output storage that overlaps the reviewed
digest, account hashes, or another output before clearing or writing caller
buffers. The prior signer could clear an aliased digest before ECDSA. The
failing host regression and corrected guard are recorded in the
[signer storage experiment](../../../docs/experiments/2026-09-29-ledger-blue-signer-storage-alias.md).
Two clean pinned-SDK builds produced identical 49,920-byte `.text` SHA-256
`d4e09ab78c46425dae05b60e65816ac0e235a576d5f3764dda82ea9ac77fe1b9`
and Intel HEX SHA-256
`71103f0963f788440370379224a7631669a0cfb3b206fc170640c5f91737f62d`.
`.bss` remains 5,120 bytes, including the 2,048-byte stack reservation.
The image is not installer-whitelisted or physically tested.

Version 0.3.37 binds each payment tap to the button and page where the
finger first touched. The integrated app-loop test rejects a drag from NO
SIGN onto SIGN ZCL, a release without a touch, and a release after a page
redraw; normal taps still work. The prior app accepted the drag as signing
approval. Touch state shares the existing review generation word, and the
amount text buffer now holds exactly the largest valid ZCL amount. The
uninstalled image has 49,408 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`. The largest modeled payment path uses 1,120 bytes plus a 512-byte
margin within the 2,048-byte stack reserve; BOLOS frames are excluded. Two
clean builds against separately patched copies of the pinned SDK matched
`.text` SHA-256
`3e889f26e72153ceae6b9717041cd39962f2057d6d7c23175c3730befa4f0392`
and Intel HEX SHA-256
`bc27eccc3e77dda8d74421bef3b36f4d6dde57d179cd81c8e58cf7df9435c474`.
The installer does not whitelist this image, and physical gesture timing
is unverified. The
[payment touch experiment](../../../docs/experiments/2026-09-29-ledger-blue-payment-touch-binding.md)
records the failing case and measurements.

Version 0.3.36 erases the shared APDU buffer and signer workspace when a
transparent signing approval expires or the idle session locks. A simulated
two-input payment now tests USB reset and timeout after its first signature:
both events clear the remaining approval and reject the second signing
request. The previous timeout left shared APDU bytes in memory; the new test
failed against that version. The uninstalled image has 48,896 bytes of
`.text`, zero `.data`, and 5,120 bytes of `.bss`. Its largest modeled payment
path uses 1,120 bytes plus a 512-byte margin within the 2,048-byte stack
reserve; BOLOS frames are excluded. Two clean builds against separately
patched copies of the pinned SDK produced identical `.text` SHA-256
`2697dd041804b927d70a18d2c575197bf1170d7d85692cad4facc70f862f769e`
and Intel HEX SHA-256
`d00a18c2f24ffd9704000fc1fb6c3a329997cc2e4fceae96b8dd78d0f1d898e9`.
The installer does not whitelist this image, and it has not run on a
physical Blue. The
[timeout-erasure experiment](../../../docs/experiments/2026-09-29-ledger-blue-timeout-apdu-erasure.md)
records the failing assertion, corrected behavior, and measurements.

Version 0.3.35 rechecks the input total, output total, own-output total, and
fee before each approved transparent input signature. A changed total after
the owner's SIGN ZCL touch now rejects the signing APDU without calling the
signer and erases the review. The same check applies between signatures of a
two-input payment. The uninstalled image has 48,896 bytes of `.text`, zero
`.data`, and 5,120 bytes of `.bss`. The largest modeled payment upload path
uses 1,120 bytes; the required 512-byte margin fits within the 2,048-byte
stack reserve. BOLOS frames are excluded. Its `.text` SHA-256 is
`9a36ffba3476445777541db37630a98b4211ae8d27324c17841b837c9c845767`;
Intel HEX SHA-256 is
`d570ee8d22b410882e723a0032ed5b6e31eff8973d7d7d0a930f2edbe9498d49`.
Two clean source builds using separately patched copies of the pinned Blue
SDK produced matching images. The installer does not yet whitelist this
image, and it has not run on a physical Blue. The
[post-approval totals experiment](../../../docs/experiments/2026-09-28-ledger-blue-post-approval-totals.md)
records the regression, tests, and build measurements.

Version 0.3.34 makes an acknowledged host abort erase the payment controller's
temporary SHA-256 and BLAKE2b contexts, fee and amount text, input-path text,
and final approval state. The previous payment APDU erased its transaction
record but left these controller workspaces until another cleanup path ran.
The uninstalled image has 48,640 bytes of `.text`, zero `.data`, and 5,120
bytes of `.bss`. Its largest modeled payment upload path uses 1,120 bytes;
the required 512-byte margin fits within the 2,048-byte stack reserve.
BOLOS frames are excluded. Its `.text` SHA-256 is
`f5d365676398970e03dc30215cdd2089a300a11752e0883d4e1389eaa9d94b01`;
Intel HEX SHA-256 is
`6d52dca9a2a73857d39f6864ffe6c6defbca974059bbf213edfc0ac445bfac24`.
The [host-abort experiment](../../../docs/experiments/2026-09-28-ledger-blue-host-abort-workspace.md)
records the tests and same-toolchain reproduction. Physical installation
remains blocked.

Version 0.3.33 repeats CHAIN UNCHECKED on the final SIGN ZCL page. The Blue
accepts a known mainnet branch ID but has no verified live chain tip, so the
branch text alone must not imply that the payment is current. The page keeps
the payment amounts, input path, branch, expiry, lock time, and HOST MAY
BROADCAST warning. The decoded 320 × 480 simulator image was inspected and
its RGB pixels pinned. The uninstalled image has 48,640 bytes of `.text`,
zero `.data`, and 5,120 bytes of `.bss`; the largest modeled app path is
1,112 bytes plus a 512-byte margin within the 2,048-byte stack reservation.
BOLOS frames are excluded. Its `.text` SHA-256 is
`d8fffe2ffff7594c4696c365120afa25f40ca540f76a430f581ca64984c7d9cc`;
Intel HEX SHA-256 is
`4ae6b754a8e01204fd45f96a19f1f316535c1c4183d66e055d04b142e05799f0`.
The [final chain-warning experiment](../../../docs/experiments/2026-09-28-ledger-blue-final-chain-warning.md)
records the tests and reproducibility check. The physical install block
remains in place.

Version 0.3.32 labels output totals by what the Blue can verify. Only an
exact match to its fixed external `0/0` or internal `1/0` P2PKH key appears
under MATCHES YOUR KEY. Every other output, including P2SH, appears under
OWNER NOT VERIFIED. The same labels appear on the final signing screen and
the host simulator. A P2SH output may belong to the user; the Blue does not
know its redeem script. The decoded 320 × 480 simulator pixels for both
screens are pinned and the images were inspected. The uninstalled image has
48,640 bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`; the largest
modeled app path is 1,112 bytes plus a 512-byte margin within the 2,048-byte
stack reservation. BOLOS frames are excluded. Its `.text` SHA-256 is
`21a760706c0020a0526acc59bd7bb6bf4550aeae51bef1a15a0071d1c8d05d56`;
Intel HEX SHA-256 is
`da290ac33809b20fff8ed77b113b2f4f07a262860c4dffbb4c61c651d6dd53d5`.
The [ownership wording experiment](../../../docs/experiments/2026-09-28-ledger-blue-ownership-wording.md)
records the tests and reproducibility check. The physical install block
remains in place.

The host authenticated assembler snapshots the reviewed unsigned wire,
signature records, expected digests, paths, and ownership hashes before
running verification callbacks. It rejects changes during those callbacks
and assembles from the snapshot, so the final wire cannot use a later caller
mutation. The host allocation is 3,120 bytes plus the unsigned wire on the
measured Clang 22.1.6 build, capped at 2,100,272 bytes. This host-only change
does not alter the uninstalled Wallet 0.3.31 image. The
[callback-mutation experiment](../../../docs/experiments/2026-09-28-ledger-blue-assembly-callback-snapshot.md)
records the regression and tests.

Version 0.3.31 rejects a negative private-key initialization result from
the Blue SDK even if the returned key structure has plausible curve and
length fields. Both receive-address startup and touchscreen-approved
signing fail closed and erase key material in the injected failure tests.
The uninstalled image has 48,640 bytes of `.text`, zero `.data`, and 5,120
bytes of `.bss`; the largest modeled app path remains 1,112 bytes plus a
512-byte margin within the 2,048-byte stack reservation. BOLOS frames are
excluded. Its `.text` SHA-256 is
`7a209cd2f7cddd002f03e88e3771896d9bb439b061e3dcefcb94b929b7281659`;
Intel HEX SHA-256 is
`199ca087bd62d4e6d336cdc287e5bd2d922ced474bd6480764e8e16932fdd7f3`.
The [SDK result experiment](../../../docs/experiments/2026-09-28-ledger-blue-private-key-init-result.md)
records the tests and reproducibility check. The physical install block
remains in place.

Version 0.3.30 rejects a USB exchange receive count larger than the
260-byte shared APDU buffer before parsing an instruction. It aborts a
payment review, clears the buffer, and returns a length error. The
startup shell forges counts of 261 and 65,535 for a valid-looking payment
request and confirms neither reaches the payment handler. The uninstalled
image has 48,648 bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`;
the largest named app path uses 1,112 bytes plus a 512-byte margin inside
the 2,048-byte stack reservation. BOLOS frames are excluded. Its `.text`
SHA-256 is
`c7a6b617c215e7c48545abcf52ef191164238b7ef7db06fb2504c34f79f7fc64`;
Intel HEX SHA-256 is
`e065334b3d83f6dd41507060a3f0c55937e323c4edfa2e011973f067ba4f9ef6`.
The [receive-length experiment](../../../docs/experiments/2026-09-28-ledger-blue-receive-length-bound.md)
records the tests and limits. The physical install block remains in place.

Version 0.3.29 erases unused bytes in the shared USB APDU buffer after
short identity, address, and payment replies, and erases the whole buffer
on rejection. An over-capacity success claim aborts the review and returns
an error. The startup shell checks every transmitted reply tail and a
signature followed by a short identity reply. The uninstalled image has
48,648 bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`; the
largest named app path uses 1,112 bytes plus a 512-byte margin inside the
2,048-byte stack reservation. BOLOS frames are excluded. Its `.text`
SHA-256 is
`798c41d6eeeed3e07d9a69f5ab0dcab7af3d6300ae5a772c8be7ba5aca01dee2`;
Intel HEX SHA-256 is
`a83faa79285b72b056acfd6e047b29f5d51bbc7e3aba857f47dbe4614882b689`.
The [short-reply experiment](../../../docs/experiments/2026-09-28-ledger-blue-short-reply-erasure.md)
records the tests and limits. The physical install block remains in place.

Version 0.3.28 erases the reviewed transaction, per-input digests, hash
contexts, and amount/path text immediately when the owner taps NO SIGN.
It shows REVIEW COMPLETE from a separate flag after erasure. Simulated
stale touch callbacks and a later signing APDU cannot restore approval.
The uninstalled image has 48,392 bytes of `.text`, zero `.data`, and
5,120 bytes of `.bss`; the largest named app path uses 1,088 bytes plus
a 512-byte margin inside the 2,048-byte stack reservation. BOLOS frames
are excluded. Its `.text` SHA-256 is
`4822fe3e134ae5cd91897ea577010e02ba64d69ea3ca21dd950493da331884b1`;
Intel HEX SHA-256 is
`20210efb759dfb0555b87456aaa8f0e501fbd951f18c8582a2859a3e226689a4`.
The [NO SIGN erasure experiment](../../../docs/experiments/2026-09-28-ledger-blue-no-sign-erasure.md)
records the tests and limits. The physical install block remains in place.

Version 0.3.27 removes the device's unenforceable NO BROADCAST claim. The
final signing page and post-approval screens say HOST MAY BROADCAST: after
the Blue releases a valid signature, it cannot control a host's broadcast
decision. The earlier fee and totals screens still warn CHAIN UNCHECKED and
BRANCH UNCHECKED. The final 320 × 480 screen was inspected and its decoded
RGB pixels pinned. The uninstalled image has 48,384 bytes of `.text`, zero
`.data`, and 5,120 bytes of `.bss`; the largest named app path uses 1,088
bytes plus a 512-byte margin inside the 2,048-byte stack reservation. BOLOS
frames are excluded. Its `.text` SHA-256 is
`f666c315509bb7430d100b098f10f2800dc9b8656ddafc3019caa86fcb267307`;
Intel HEX SHA-256 is
`edfc053bc48445765718281190070ee966c334cf18dcfdff08820276bba10422`.
The [broadcast copy experiment](../../../docs/experiments/2026-09-28-ledger-blue-broadcast-copy.md)
records the tests and limits. The physical install block remains in place.

Version 0.3.26 separates the final SIGN ZCL touch target from the preceding
NEXT target. A repeated touch at NEXT reaches NO SIGN on the final page and
cannot authorize a signature. The 320 × 480 simulator image was inspected;
the host UI test checks the touch rectangles and the repeated-touch route.
The uninstalled image has 48,384 bytes of `.text`, zero `.data`, and 5,120
bytes of `.bss`. The largest named app path uses 1,088 bytes plus a 512-byte
margin inside the 2,048-byte stack reservation; BOLOS frames are excluded.
Its `.text` SHA-256 is
`9dcc85cb0e6d845e34b2e75f7c9132af73852c5f36c0483b1dc7b0702293a00c`;
Intel HEX SHA-256 is
`410bda25b689daef31e759110bf0b9d798087159bbe19cee1fab4e28b3709d63`.
A second source tree and pinned SDK copy produced byte-identical image
bytes. The [repeated-touch experiment](../../../docs/experiments/2026-09-28-ledger-blue-repeat-tap-signing.md)
records the tests and limits. The physical install block remains in place.

Version 0.3.25 revokes the derived account when PIN validation ends during
review, signing, or idle display. Revocation clears both account hashes,
receive public key, and displayed address, then keeps address and payment
commands rejected until the app is reopened. Normal EXIT and exception
teardown also erase the account data. A host test reproduces a successful
address reply after PIN validation returned to the still-open 0.3.24 app;
the corrected loop returns only `0x6985`. The Cortex-M0 emulator verifies
the account data is clear after EXIT. The uninstalled image has 48,384
bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`. The largest named
app path uses 1,088 bytes plus a 512-byte margin within the 2,048-byte
stack reservation; BOLOS frames are excluded. Its `.text` SHA-256 is
`38ff70405802ab6084e8baa7df8e6e3b86c8f82755f7ba11fb1eaf819b8807c8`;
Intel HEX SHA-256 is
`e154a247cc7bff6655ad82d888432bc166d7159f72f86f3ce05362fd7bb37279`.
A separate source snapshot and SDK copy produced byte-identical image bytes.
The image has not run on a physical Blue. The
[revocation experiment](../../../docs/experiments/2026-09-28-ledger-blue-account-revocation.md)
records the test and limits.

Version 0.3.24 refuses read-only address and payment APDUs if PIN validation
ends before arrival or while the command runs. It returns `0x6985`, erases
the shared request and reply buffer, and redraws DEVICE LOCKED. A read-only
identity query remains available; it also redraws the locked screen. The host SDK
tests reproduce the prior 35-byte public-key response after simulated PIN
loss at both boundaries. The uninstalled image has 47,360 bytes of `.text`,
zero `.data`, and 5,120 bytes of `.bss`. The largest named app path uses
1,088 bytes plus a 512-byte margin within the 2,048-byte stack reservation;
BOLOS frames are excluded. Its `.text` SHA-256 is
`ab3f13f40926ce0a5689b31ae3fc07366ee41583a1e76e3b6a39c449cd0cf0e1`;
Intel HEX SHA-256 is
`f0cf390f315983faf741b3967cc1a647639372d8c4a100ddad2f81950d8a0507`.
A separate source snapshot and SDK copy produced byte-identical image bytes.
The image has not run on a physical Blue. The
[locked APDU experiment](../../../docs/experiments/2026-09-28-ledger-blue-locked-apdu.md)
records the test and limits.

Version 0.3.23 shows DEVICE LOCKED with a working EXIT button when PIN
validation ends during startup or an active payment review. The app loop now
routes rejected payment replies, USB reset or suspend, and review timeout to
that screen rather than showing the receive address. The SDK-stub loop test
injects each transition; the original rejected-payment test failed against
the prior screen route. The uninstalled image has 47,104 bytes of `.text`,
zero `.data`, and 5,120 bytes of `.bss`. The largest named app path uses
1,080 bytes plus a 512-byte margin within the 2,048-byte stack reservation;
BOLOS frames are excluded. Its `.text` SHA-256 is
`866fa4d214f7c35d97afd23c121a161a65bbd64f2bfad5c4cf18093b9e2270a3`;
Intel HEX SHA-256 is
`183b3b58803042bc87a8d0244a1bc59b38acde9cea85c77e2f0ac0c247cdd4b2`.
A separate source snapshot and SDK copy produced byte-identical image bytes.
The image has not run on a physical Blue. The
[lock-screen experiment](../../../docs/experiments/2026-09-28-ledger-blue-lock-screen.md)
records the test and limits.

Version 0.3.22 ends an active payment review if PIN validation is lost before
a USB payment command, during its signer, while clearing the signing timer,
at final completion cleanup, or before a redraw. The SIGN ZCL tap cannot
approve while locked. Each PIN-rejected command erases its reply, cancels the
approval timer, and clears the review. The host SDK test injects each
transition. The uninstalled image has
47,360 bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`. Its largest
named app path uses 1,096 bytes plus a 512-byte margin within the 2,048-byte
stack reservation; BOLOS frames are excluded. Its `.text` SHA-256 is
`178d0e3ece26df54418377c7877bbf3e6a495b68db072fe6718ac18d1417a35a`;
Intel HEX SHA-256 is
`d9d00b88d1c921a9d2af2ffa71050dd99a3cf36dcdf0a8c07cbc0124149b1ad2`.
A separate source snapshot and SDK copy produced byte-identical image bytes.
The image has not run on a physical Blue. The
[runtime PIN-loss experiment](../../../docs/experiments/2026-09-28-ledger-blue-runtime-pin-loss.md)
records the failure injection and limits.

Version 0.3.21 rejects receive-account startup if Blue PIN validation ends
while the internal public key or account hash is being produced. It also
erases the boot key workspace if a BOLOS exception exits the app. The startup
test reproduced a ready receive screen after validation ended during internal
keypair generation; both injected loss points now lead to ADDRESS UNAVAILABLE,
with account hashes unset and boot key material erased. The uninstalled image
has 46,848 bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`. The
largest named app path uses 1,096 bytes plus a 512-byte margin within the
2,048-byte stack reservation; BOLOS frames are excluded. Its `.text` SHA-256
is `3b1feff3fabb89afad229227e9ecbe699f6cbb4a5975c299c04d1a5e50c44248`;
Intel HEX SHA-256 is
`6ce96fc61dd51da2b4eb9318a2d8d78eb86571a18ce27d37fefd9a18b7dcfa8b`.
A separate source snapshot and SDK copy produced byte-identical image bytes.
The image has not run on a physical Blue. The
[startup PIN-loss experiment](../../../docs/experiments/2026-09-28-ledger-blue-startup-pin-loss.md)
records the fault injection and limits.

Version 0.3.20 rechecks Blue PIN validation after key derivation, before
ECDSA, and after the signing syscall. If validation ends, the signer returns
no signature, clears the reported length and output buffers, and erases its
private-key workspace. The SDK-stub test injects PIN loss during public-key
generation, public-key hashing, and ECDSA. The pinned image has 46,592 bytes
of `.text`, zero `.data`, and 5,120 bytes of `.bss`. The largest checked app
path uses 1,096 bytes plus a 512-byte margin within the 2,048-byte stack
reservation; BOLOS frames are excluded. Its `.text` SHA-256 is
`fc896779cf948385742b737dc3188f2479207be06f92a78a13d02fff00c79548`;
Intel HEX SHA-256 is
`8a203ebfeb0aaf7ae6ac4b2f5aa581e94c8e1cd384e0a429d9fe3642618d3858`.
The image is uninstalled and has not run on a physical Blue. The
[PIN-loss experiment](../../../docs/experiments/2026-09-28-ledger-blue-pin-loss-signing.md)
records the failure injection and build limits.

Version 0.3.19 clears the unused bytes of every successful read-only payment
APDU reply and clears the full reply buffer on a rejected command. This also
erases the old request bytes when Blue uses one shared USB buffer for request
and reply. The host regression first failed with those bytes still present;
the corrected portable and device-loop tests pass. The full Release and
sanitized Debug suites each passed 57/57. The pinned image has
46,592 bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`. The largest
named payment path uses 1,080 bytes of the 1,536-byte stack budget after its
512-byte margin. Its `.text` SHA-256 is
`d77d5cbb661f5cecfad4cd789c61b8afedfbbf73d56d1a4157acd6b3426b1571`;
Intel HEX SHA-256 is
`b0c606dda78b440975c71bb352ed64ac9856656ba8029712e5727e5f582e6674`.
A separate source snapshot and independently patched SDK copy produced
byte-identical `.text` and Intel HEX files with the same ARM toolchain.
The image is uninstalled and has not run on a physical Blue. The
[reply cleanup experiment](../../../docs/experiments/2026-09-28-ledger-blue-payment-reply-cleanup.md)
records the test and memory boundaries.

Version 0.3.18 checks the read-only payment APDU storage contract before
writing a reply length or parsing host bytes. It rejects a reply length
inside the reply or request, a request or reply inside mutable review state,
and a reply over device-derived account hashes. Rejection ends the review;
the normal shared Blue request/reply buffer remains supported. The old
direct handler returned success with an aliased reply length; its regression
test now requires failure before dispatch. Release and sanitized Debug each
passed 57/57 tests. The pinned image has 46,592 bytes of `.text`, zero
`.data`, and 5,120 bytes of `.bss`; the largest named payment path uses
1,064 bytes of the 1,536-byte usable stack. Its `.text` SHA-256 is
`fd00ff055f0a2f7f6a714d1098af5e2ba687407a9ae77eb375590a7186e0a539`;
Intel HEX SHA-256 is
`4614155309e1128269311a9bcc14c3d8ef191fe66a7d6f9ddde1459c7834136b`.
A second source checkout and separately patched SDK copy produced matching
`.text` bytes and Intel HEX hash.
The image is uninstalled and has not run on a physical Blue. The
[APDU storage experiment](../../../docs/experiments/2026-09-28-ledger-blue-payment-apdu-storage.md)
records the failure and measured limits.

Version 0.3.17 rejects a signing reply-length pointer placed inside the
signature reply, transaction review, account hashes, or request. It also
rejects requests or replies inside mutable review or account storage.
The request and reply may still share the Blue's APDU buffer. Tests verify
that each invalid layout fails before the signer runs or consumes approval.
The pinned image has 45,568 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`. The largest named path remains the 1,064-byte payment upload;
the largest signing path uses 1,056 bytes, with a 512-byte stack margin.
Its `.text` SHA-256 is
`d04e9accb8c94443b20d4f81f8ac722318294c926cf094c5f4623b5bf77d3442`;
Intel HEX SHA-256 is
`522241c3b2c6ae5eb7ef9a09ac35d9e06f90526e0fb6956632a3d6ecdaecfdeb`.
The candidate is uninstalled and has not run on a physical Blue.
The [signing buffer experiment](../../../docs/experiments/2026-09-28-ledger-blue-sign-buffer-isolation.md)
records the rejected aliases and image measurements.

Version 0.3.16 erases the shared APDU buffer if a signing command throws
after producing a partial reply, if reply transmission fails, when EXIT is
tapped, and during final app teardown. The host SDK shell injects a throw
after a mock signature and a send failure with a pending signature. It checks
that no signature bytes survive in the buffer. The pinned image has 44,288
bytes of `.text`, zero `.data`, and 5,120 bytes of `.bss`. The largest checked
payment path uses 1,064 bytes plus a 512-byte stack margin. Its `.text`
SHA-256 is
`b5824ee5f0801bc4c147ec2584bb38e0495b8cc3e20173a6c8de92fba0e9edc2`;
Intel HEX SHA-256 is
`d9f0429807303f5fcad5ba48204dbe95bc2edad74337b27e1647379fd6cd8be9`.
Release and sanitized Debug each passed 57/57 tests. The candidate is
uninstalled and has not run on a physical Blue.
The [exception cleanup experiment](../../../docs/experiments/2026-09-28-ledger-blue-exception-reply-erasure.md)
records the injected failure and byte-matched independent image build.

Version 0.3.15 erases the full payment workspace, hash contexts, and formatted
payment text after the last touchscreen-approved transparent signature. The
signature reply and a transaction-free “SIGNATURES READY” screen remain
available. The host SDK test checks exact reply bytes, state erasure, and the
two-input boundary. It is uninstalled and has not run on a physical Blue.
Release and sanitized Debug each passed 57/57 Blue tests. The pinned SDK
image has 44,032 bytes of `.text`, 5,120 bytes of `.bss`, and no initialized
`.data`; the largest checked payment upload path uses 1,064 bytes plus a
512-byte stack margin. Its `.text` SHA-256 is
`95b97aeae1f58ec4f1864c1e3197c971a6f0fc1036f932d1d4bca6ead14ea5a0`;
Intel HEX SHA-256 is
`877ad350f04827e437b11323b323bd41891429ebfbab213e5286f01d23f94e71`.
A second source checkout and separately patched copy of the pinned SDK
produced matching `.text` and Intel HEX bytes.

Version 0.3.14 rejects upload bytes overlapping its transaction replay or
payment review state before parsing or hashing. An overlap erases the review;
the tests inject bytes that would otherwise be valid at that position of the
transaction and verify that a fresh review still works. It is uninstalled
and has not run on a physical Blue. Release and sanitized Debug each passed
57/57 Blue tests. The pinned SDK image has 44,032 bytes of `.text`, 5,120
bytes of `.bss`, and no initialized `.data`; the largest checked payment
upload path uses 1,064 bytes plus a 512-byte stack margin. Its `.text`
SHA-256 is
`9d71b563acbb12eba0a434627f7584a98cc81010fac12b4f0fad2f7fb82d37d7`;
Intel HEX SHA-256 is
`14ce37c3d481a14d18dc4b0ca72b3506aa8dfc612fcfc7867fccdc3c968ef5d5`.
A second source checkout and separately patched copy of the pinned SDK
produced matching `.text` and Intel HEX bytes.

Version 0.3.13 rejects replay result buffers that overlap each other, the
captured transaction state, or the script input before hashing or writing a
digest. A bound input digest also rejects output that would overwrite the
replay's captured hashes, outpoint, or script. The host tests exercise those
aliases and a valid digest after rejected requests. The pinned SDK image has
44,032 bytes of `.text`, 5,120 bytes of `.bss`, and no initialized `.data`;
the largest checked payment upload and previous-finish paths use 1,048 bytes
plus a 512-byte stack margin. A second source checkout and separately patched
SDK produced matching `.text` SHA-256
`4c03fa4e1944c9182f4839e2b8ea26fc4befe6ad86f957ab649077e6aa664d08`
and Intel HEX SHA-256
`622e08b08afa08529ee11d5e2371eed7576528e79c29244676419010daa8a595`.
It is uninstalled and has not run on a physical Blue.

Version 0.3.12 erases the completed transparent payment review immediately
after preparing the final signature reply. A separate screen flag keeps
“SIGNATURES READY” visible without retaining the transaction, input digests,
or fee in app RAM. The host SDK test checks the entire erased payment state
and still rejects a second signing command. Its linked image has 43,264 bytes
of `.text`, 5,120 bytes of `.bss`, and no initialized `.data`; the checked
largest payment upload path uses 1,048 bytes plus a 512-byte stack margin.
Two source checkouts and separately patched copies of the pinned SDK produced
the same `.text` SHA-256
`acf4614d8355512d2fdb1f1805d96163a6851537c726120d4cadd13ef08d5c08`
and Intel HEX SHA-256
`984634ff4d1b47ac6d7d5b013c93bbec7c75a1be93c73ffc5d4fdfc739afb658`.
This image is uninstalled and has not run on a physical Blue.

Version 0.3.11 shows the device-classified amount returning to its own fixed
addresses on the final signing page, alongside the amount to other addresses
and the calculated fee. The page recomputes these values from the completed
device review state before exposing SIGN ZCL. Its 320 × 480 simulator snapshot is
pinned by a pixel digest. The image remains uninstalled.

Version 0.3.10 explicitly erases payment replay state, per-input digests,
hash workspaces, and payment text on abort. A rejected output-page touch now
ends the entire review and clears its transient workspaces. The host and SDK
tests check the abort paths and linked image. This version has not run on a
physical Blue and remains blocked from installation.

Version 0.3.9 erases the shared APDU buffer after a rejected payment command,
including when the account address is unavailable. The host SDK shell tests
malformed signing and non-signing commands with aliased input and reply
buffers. This candidate remains blocked from installation pending full gates
and physical validation.

Version 0.3.8 aborts a pending command if USB reset or suspend occurs during
device processing, wipes the APDU buffer on either event, and refuses to
release a signature if the session changed inside the signing callback or
the approval-timer callback. Host tests inject both interleavings and a reset
immediately before a queued signature reply; the reply contains no signature.
The candidate remains blocked by the installer and has not run on a physical
Blue. The [USB interruption experiment](../../../docs/experiments/2026-09-28-ledger-blue-usb-sign-interruption.md)
records the image and test evidence.

Version 0.3.7 enables the pinned Blue SDK's stack canary and requires that
flag at compile time. Two clean builds from independent pinned SDK trees
produced the same 41,216-byte `.text` image, SHA-256
`64839dd399415af205fcf0c02a9ca4f5283c45d0e6103df3747759847c4bc0fd`.
The [canary experiment](../../../docs/experiments/2026-09-27-ledger-blue-wallet-037-canary.md)
records the linked instruction check and its limits. This image is not
admitted by the installer and has not run on a physical Blue.

The isolated `candidate/blue_zip32_seed_device.c` adapter checks PIN state
before and after requesting a hardened BOLOS BIP32 node for a
Ledger-specific Sapling root. A host syscall-shim regression revokes the PIN
during derivation and verifies that neither a key nor scratch state survives.
The separate `candidate/blue_sapling_entropy_device.c` adapter fills 80 bytes
from the Blue CSPRNG only while PIN validation remains valid. It erases its
output on a failed or all-zero RNG result or PIN loss. Host, Cortex-M0, and
Cortex-M3 tests cover the adapter; it is not linked into the Wallet app.
It is compiled with the pinned Blue SDK and tested with a host syscall shim,
but is not linked into the Wallet image. No Sapling key or signing APDU is
available in Wallet 0.3.6. This mapping is not the standard ZIP32 root of a
wallet seed; recovery software would need the same documented mapping.

Version 0.3.6 runs the real app startup and EXIT controller in a C23 host
SDK shell. The shell checks the receive address, derivation failure screens,
secret-workspace wiping, USB reset and suspend, approval timeout, and EXIT
event. The EXIT test now routes a synthetic finger-release coordinate through
the shown touchable element bounds and checks that a touch outside the button
does nothing. It scripts valid and malformed APDUs through the app main loop and
injects receive, send, and post-reply display exceptions. It enforces one
reply per request and injects USB reset and suspend during a scripted visible
payment reply. The payment route uses a stub; this shell does not exercise
signing. It found that a failed internal derivation left formatted address
lines in RAM; the app now clears them before showing the error screen.
Two separately patched SDK builds produced identical 40,960-byte `.text`
images, SHA-256
`435b6f03a62e99daa668b85c71e895f7b64ad7a056b575367c5bf2af460e09c3`.
The host shell does not run BOLOS or physical USB and touch. This image has
not been installed and is not admitted by the installer.
The [startup experiment](../../../docs/experiments/2026-09-27-ledger-blue-wallet-036-startup.md)
records the test coverage and limits.
The [stack-path audit](../../../docs/experiments/2026-09-27-ledger-blue-wallet-036-stack-audit.md)
corrects the named-frame gate to include `main` on payment and signing calls.
The largest measured named path is 1,056 bytes; BOLOS frames remain excluded.
The [Cortex-M3 startup test](../../../docs/experiments/2026-09-27-ledger-blue-wallet-036-m3-startup.md)
runs `main.c`, both receive APDUs, and EXIT with deterministic firmware-call
stubs. Its stack watermark is 976 bytes in the tested path; it does not run
BOLOS or the linked Wallet image.
The [Cortex-M0 EXIT packet test](../../../docs/experiments/2026-09-27-ledger-blue-wallet-m0-touch.md)
checks an outside touch and a center-button release while the ARM harness
waits for another APDU. It also checks that USB reset and suspend abort two
stubbed payment displays and restore the receive screen after their replies.
Its 992-byte stack watermark applies only to those test routes; the payment
parser and signer are stubbed.

Version 0.3.5 shares RAM between mutually exclusive boot derivation and
payment state, and between output text and previous-transaction parsing.
It keeps the 16-input limit and requires 1,024 bytes of SRAM above `.bss`.
Two separately patched Blue SDK builds produced identical 40,960-byte
`.text` images with SHA-256
`d99812f8ed00e4accc3466efe1eb400b756a38677a84175897785a031e2db448`.
The app has not been installed or opened on a physical Blue. Version 0.3.4
froze on opening and was deleted; its exact image is blocked by the installer.

Version 0.3.4 checks the device-derived public key against the selected
account's startup-derived HASH160 before ECDSA runs. A missing account
binding, failed hash, or mismatched key clears the reply without signing.
Version 0.3.3 cleared a rejected payment request before returning to the
receive screen after the APDU reply. Earlier candidates could abort the
review but still mark the payment view visible.

Version 0.3.0 routes the one-byte-index INS `29` signing command after a
separate final touchscreen `SIGN ZCL` tap. The Blue displays the amount to
other addresses, fee, derivation path, and explicit `CHAIN UNCHECKED` and
`BRANCH UNCHECKED` warnings before that tap. A `NO SIGN` tap completes the
read-only review without arming signing. The approved latch is single-use per
input, ordered, and bound to the Blue-derived ZIP-243 digest and its verified
previous output. The command returns the index, path, compressed public key,
and canonical low-S DER signature. The host must verify the signature and
assemble the transparent transaction separately. The app never broadcasts.
Version 0.3.0 has passed SDK-shim touchscreen tests and two independent SDK
builds. It has not been installed or tested on a physical Blue. Its protocol
identity is version `0C`, capabilities `1F`; version `0B`/`0F` remains the
read-only identity. Sapling spends, shielded multisig, ZSLP, and P2SH
redemption are not supported by this candidate. Do not use it with funds.
The existing host review command accepts both protocol identities and never
sends INS `29`; on version 0.3.0 the owner chooses `NO SIGN` to finish that
read-only workflow.

## Read-only predecessor

Version 0.2.18 derives
`m/44'/147'/0'/0/0` on the Blue after PIN validation, retains only the
compressed public key, and displays its ZCL mainnet P2PKH address across
three large-text lines. The host reads the public key through INS `02`,
validates that point on secp256k1, and independently computes the address.
The owner must compare all 35 characters with the Blue display before using
the address. The app also derives the public hash for
`m/44'/147'/0'/1/0` and identifies an exact output match as `OWN INTERNAL
1/0`. The output label uses a larger 22-pixel font. It does not call that
output change because chain state and account policy are not proven. EXIT
returns to the home screen.

The same app now has read-only transaction review commands. It accepts an
unsigned, all-transparent v4 transaction in three complete passes, pauses
at each P2PKH or P2SH output, displays the exact amount and all 35 address
characters, and requires a touchscreen CONTINUE tap before the next chunk.
EXIT cancels and returns home. After the three-pass review, Z23 uploads each
complete previous transaction in input order. The app checks SHA-256d against
its captured outpoint, selects the indexed P2PKH output, requires its HASH160
to equal one of the two Blue-derived public-key hashes, derives all input
amounts, and displays the fee calculated from those inputs and the reviewed
outputs. For each bound input it also returns a device-computed ZIP-243
SIGHASH_ALL digest using that previous output's exact script and amount, the
reviewed spending wire, and the supplied branch ID. Z23 compares each digest
with its independent host calculation. The Blue rejects a branch ID absent
from Z23's mainnet consensus table, but cannot verify which known branch is
active at the current height, nor chain inclusion, UTXO status, or maturity.
The fixed-path hash match does not establish a complete wallet ownership policy.
There is no USB output acknowledgement, payment signature,
private-key export, path selection, Sapling spend, multisig, or token command.
The portable C23 [signing-boundary experiment](../../../docs/experiments/2026-09-27-ledger-blue-signing-boundary.md)
compiles against the Blue SDK and passes host signature tests, but the
read-only app does not call it or expose a signing APDU.
The fee page shows the Blue-derived account prefix `m/44'/147'/0'`, the
verified input path or both paths, `CHAIN UNCHECKED`, `BRANCH UNCHECKED`,
and `NO SIGNING`. Its TOTALS button shows device-derived output value to
other addresses, value to the two fixed Blue addresses, and the fee. P2SH
outputs remain in the other-address total even if their script hash equals
a public-key hash. BACK returns to the fee page. These totals appear only
after full transaction replay and input binding. Version 0.2.1 reached the
Blue: its receive
screen and EXIT worked, and all 35 address characters matched the host result
`t1RAmKL4KFauUXGswvMvk66aS5UL33ck1Uz`. A synthetic transaction review
then stopped USB replies and left EXIT unresponsive. The owner restarted the
Blue; Z23 deleted Wallet, Sign Test, and Probe and verified an empty catalog.
The 0.2.0 and 0.2.1 review images are excluded from the installer. Version
0.2.2 deferred screen redraw until after the APDU reply. Version 0.2.3 also
keeps the transmit and redraw outside the request exception handler, so a
post-reply display exception cannot schedule a second response. A receive
exception before a complete APDU now unwinds to the outer app handler.
Version 0.2.4 labels an exact P2PKH hash match to the
Blue-derived fixed account as “THIS ACCOUNT,” other P2PKH outputs as “OTHER
ADDRESS,” and P2SH outputs as “P2SH ADDRESS.” It does not infer ownership of
P2SH or call an output change without verified inputs and account context.
Version 0.2.12 enlarged the fee and totals labels and touch-control text.
The host UI test compiles the actual wallet screen code with SDK shims,
checks that its labels fit the Blue viewport, follows TOTALS, BACK, and EXIT,
and verifies that invalid output accounting ends review. Version 0.2.13
adds CONFIRM on the totals page and a read-only REVIEW CONFIRMED screen. The
tap arms a one-use, ordered digest latch after every previous output and the
fee have been verified. Verified digests reuse the completed outpoint slots,
so the input limit remains 16 without increasing `.bss`. No APDU can consume
the confirmation latch or request a signature. INS `28` still returns each
computed digest before confirmation for host comparison. Version 0.2.13
remains uninstalled. Version 0.2.14 compiles a fixed-path SDK signing
callback and wipes its private state during command, USB, and exit cleanup.
The callback has no reachable APDU, is removed from the linked image, and
has not signed on this Blue. A host SDK shim tests both fixed paths, locked
PIN rejection, malformed SDK results, zeroed replies, and private-state
erasure.
Version 0.2.15 separates read-only REVIEW CONFIRMED from signing approval.
The Blue's CONFIRM button cannot arm the digest latch or authorize the
unrouted signing command. A separate signing approval flow would be required
before any payment signer could be enabled.
Version 0.2.16 labels the read-only totals action DONE, labels its final
page REVIEW COMPLETE, and displays the unchecked chain and branch warnings
on separate 22-pixel lines. The simulator verifies that every label fits
the Blue viewport. This image has not been installed on a physical Blue.
Version 0.2.17 ignores duplicate DONE taps and delayed BACK or TOTALS taps
after the review completes. The SDK-shim touchscreen test confirms that the
completion page remains visible and no signing approval is set. This image
has not been installed on a physical Blue.
Version 0.2.18 also ignores repeated CONTINUE taps after an output
has been acknowledged and delayed CONTINUE taps after EXIT. The SDK-shim
test checks the output address lines, account label, value, acknowledgement
count, and resulting screen. This revision has not been installed on a
physical Blue.
Its output screen source and standalone preview produce identical 320 × 480
RGB pixels in the SDK shim for a device-formatted account output; this does
not establish physical framebuffer identity.
Do not receive funds or sign payments with it.

## Build

Use Ledger's open-source Blue SDK at revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with the reviewed
[`C23 SDK patch`](../toolchain/blue-secure-sdk-2.1-c23.patch). Apply that
patch to a clean SDK checkout. Use Clang 22.1.6 and ARM GCC 16.2.0:

```sh
git -C /path/to/blue-secure-sdk checkout 3c710b4c62ad847599a2deb0932a50dd1ae4bdff
git -C /path/to/blue-secure-sdk apply /path/to/z23/apps/zcl-ledger/toolchain/blue-secure-sdk-2.1-c23.patch
make -C apps/zcl-ledger/device-blue-wallet \
  BOLOS_SDK=/path/to/blue-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
arm-none-eabi-objcopy -O binary --only-section=.text \
  apps/zcl-ledger/device-blue-wallet/bin/app.elf /tmp/zcl-wallet.bin
sha256sum /tmp/zcl-wallet.bin
```

The build rejects initialized `.data`, keeps at least 1,024 bytes of app SRAM
after `.bss`, and checks named derivation, upload, formatting, replay, and
touch paths against the 2,048-byte stack reservation with a separate
512-byte margin. Before loading SDK make definitions, even for `clean`, it
checks the pinned SDK revision, exact reviewed patch diff, and absence of
staged changes or untracked SDK files. The linked
0.2.14 image has 33,792 bytes of `.text`, 5,472
bytes of `.bss`, and zero `.data`. Its `.bss` includes the linker-reserved
stack; 672 bytes remain after that section in the 6,144-byte app SRAM
region. The largest named C path sums to 752 bytes, excluding BOLOS firmware
frames. Two independent builds using patched SDK trees produced `.text`
SHA-256 `067744e45fbad645850dd7a8cf8cdfb1f1b4b8ede585d4c57c61fa5f962788b7`.
Version 0.2.15 produced 33,792 bytes of `.text`, 5,472 bytes of `.bss`,
zero `.data`, and identical `.text` SHA-256
`7cefe528eeee5407edd40306951bb604f467ef526619828f246a2fe519ebf3e6`
in two independently patched SDK trees. Its largest named C stack path
remains 752 bytes, excluding BOLOS frames.
Version 0.2.16 produced 33,792 bytes of `.text`, 5,472 bytes of `.bss`,
zero `.data`, and identical `.text` SHA-256
`2c6000584ccd6826c5ea92133bad0ab0dd3926afbc3015c9f8ab868a77f38fb6`
in two independently patched SDK trees. Its largest named C stack path
remains 752 bytes, excluding BOLOS frames.
Version 0.2.17 produced 34,048 bytes of `.text`, 5,472 bytes of `.bss`,
zero `.data`, and `.text` SHA-256
`386c39a9861431501e57c22fbb312a087f7623362a60800b6b602e229ff288bd`
in two independent patched SDK builds. Its largest named C stack path remains
752 bytes, excluding BOLOS frames.
Version 0.2.18 produced 34,048 bytes of `.text`, 5,472 bytes of `.bss`,
zero `.data`, and `.text` SHA-256
`a2b78a3add93ca47177e2307c5c2ef50348240c2a8aff5d0bac37686425afd7a`
in builds against two independent patched SDK trees. Its largest named C
stack path remains 752 bytes, excluding BOLOS frames.
The stack gate also checks four currently unreachable signing paths through
the strict command parser. Their largest named C path is 728 bytes; the gate
rejected a deliberate 1,600-byte signer-frame substitution. A separate
forced-link experiment included the signing parser, boundary, and SDK
callback without adding a routed APDU. It used 37,376
bytes of `.text` and 5,472 bytes of `.bss`, with identical `.text` across
two independent SDK builds. These figures do not measure BOLOS firmware
frames or physical signing behavior.
The [signing callback experiment](../../../docs/experiments/2026-09-27-ledger-blue-signing-callback.md)
records the tests and limits.
The [signing footprint experiment](../../../docs/experiments/2026-09-27-ledger-blue-signing-footprint.md)
records the forced-link and stack-gate results.
The installer previously accepted the independently reproduced 0.3.4
`.text` image with SHA-256
`e6c158621a68bbf30ae92a7223fe151aa9d57fd184466b0c6537c0cf39c5bf6a`.
That image is now blocked after its physical startup freeze.
Version 0.3.1 resets the payment view when a new review begins, so an
earlier signing page cannot remain selected for the new transaction.
Version 0.3.2 expires an unconsumed final touchscreen approval after 30
seconds on the SDK ticker. USB reset and suspend also abort the review.
Device-side USB, screen, EXIT, and recovery checks are pending.
The host-tested candidate INS `29` requires exactly one input-index byte and
returns one verified-path public key and normalized ECDSA signature only
after touchscreen approval. Wallet 0.2.14 does not route this command.
The separate C23 host reply verifier checks exact response framing, expected
input index and path, public-key HASH160, canonical low-S DER, and a
caller-verified signature over the device-derived ZIP-243 digest before any
signature bytes can enter transaction assembly. Wallet 0.2.18 still does not
route INS `29`.
The C23 host assembler can place a verified P2PKH reply into each empty
transparent input script, preserving the reviewed outputs and requiring the
expected input index and ZIP-243 digest for every signature. This assembly
path is host-tested only. A C23 host collector now requires the version 12
signing identity, waits for a final approval callback, requests INS `29` in
input order, verifies each returned signature, and clears every collected
signature on failure. The fixture-only CLI calls this collector after final
touchscreen approval and assembles the result in memory. It has no save or
broadcast path and has not been run on the physical Blue.

## USB protocol

All APDUs use CLA `A5`, P1/P2 zero, and an exact one-byte `Lc`.

| INS | Reply before `9000` |
| --- | --- |
| `01` | `ZCL`, protocol version `0C`, receive, review, previous-wire, digest, and signing-candidate capability `1F` |
| `02` | 33-byte compressed public key when the address is ready |
| `20` | Begin read-only replay: 12-byte length, input index, known mainnet branch ID; unknown IDs fail closed |
| `21` | Feed one chunk; reply reports pass and pending output |
| `22` | Advance replay pass; reply reports pass and output count |
| `23` | Finish complete replay; reply reports output count and 32-byte full-wire SHA-256 |
| `24` | Cancel review |
| `25` | Query six nonsecret review-state bytes |
| `26` | Begin the next previous wire with a four-byte little-endian length |
| `27` | Feed previous-wire bytes; exact SHA-256d and structure are checked at finish |
| `28` | Finish the previous wire only if its P2PKH hash equals a Blue-derived external or internal hash; reply contains bound count, input count, fee-ready flag, eight-byte fee, and 32-byte input ZIP-243 digest |
| `29` | Sign the next ordered input only after the final `SIGN ZCL` touch; reply contains input index, path, compressed public key, DER length, and low-S DER signature |

INS `02` returns `6985` if derivation or address formatting fails. A review
upload chunk must stop on the exact output boundary. Only the touchscreen
CONTINUE callback acknowledges that output; USB cannot do so. Previous-wire
commands are accepted only after all outputs and the complete spending wire
have been reviewed. Any malformed command invalidates the review. USB reset
or suspend also cancels an idle review and returns to the receive screen. No
read-only command signs or approves a payment. INS `29` requires separate
touchscreen signing approval in version 0.3.0.
After hardware validation, run
`zcl-ledger receive-address --json /dev/hidrawN` while the app is open and
compare the returned address with all characters on the Blue screen.
