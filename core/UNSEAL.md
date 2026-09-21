# core/ UNSEAL log — append-only owner ritual record

The top-level `core/` tree is the **sealed consensus core**: the predicates and
static, height-keyed parameter tables that decide whether a block/tx is valid.
Its byte-integrity is pinned by `core/MANIFEST.sha3` (a SHA3-256 manifest, see
`tools/core_seal.c`) and enforced by the `check-core-seal` lint gate.

**Sealed ≠ frozen.** Consensus-parity fixes still ship routinely — they just may
not go through the autonomous fast path. A deliberate change to a sealed file
requires the unseal ritual below; only the unattended/agent fast-path is
structurally refused.

## The unseal ritual

```
make core-unseal REASON="why this consensus-core change is needed"
#   → appends a dated entry to this file (old ROOT hash + reason)
#   → writes .core-unseal-token (gitignored) that `make core-seal-check`
#     honors for exactly one commit
# ... make the sealed-core edit ...
make core-seal        # re-freeze the manifest (also consumes the token)
make lint && make test_parallel   # must land green, incl. test_consensus_parity
git commit            # the reseal + the edit land together
```

The token authorizes the seal check to tolerate drift for the single commit that
introduces the change; `make core-seal` re-freezes and removes it. No agent can
mint this token as a normal source edit — it is an owner-run make target (v1.1
upgrades this to an ed25519 owner signature so consent cannot be forged).

`check-core-seal` is in **WARN/ratchet** mode until core-split wave W5, when a
later lane flips it HARD.

---

## Log

<!-- UNSEAL-ENTRIES (newest appended below; append-only, never edit past entries) -->

- 2026-07-15T19:23:20Z — REASON: re-bake corrupt SHA3 checkpoint constants, owner-approved plan wave2 W2-1
  old ROOT: 6d07d92fd9a468edd93e6f17c8825149b38e190f7df8569f077b9f0bd2b15abe
  by: owner unseal ritual (make core-unseal)

- 2026-07-18T02:31:25Z — REASON: bake shielded ROM keystone @3056758 (two-builder-verified, lane draft)
  old ROOT: 9a7e1d6a264827ccad27333695bd80557449ea7a6e75789b91c860e927b486cd
  by: owner unseal ritual (make core-unseal)

- 2026-07-18T03:06:01Z — REASON: record two-builder gate PASS in keystone provenance comment
  old ROOT: 9b922e9fcad73991469b4cef4941119f3a3e0a2eb3ab7e997478e99f2356ea94
  by: owner unseal ritual (make core-unseal)

- 2026-07-25T02:04:04Z — REASON: C23 __VA_OPT__ conversion: replace the GNU comma-swallowing ', ##__VA_ARGS__' extension at the two core/consensus sites so the tree compiles under a second compiler. Preprocessor-only, line-count preserving; proven by byte-identical stripped binary + consensus parity group.
  old ROOT: 016af0ada9b91d737137332fc6f800d18d0f60ece5533a13ddc7fff347236f84
  by: owner unseal ritual (make core-unseal)

- 2026-08-12T23:12:15Z — REASON: Bound reindex UTXO cache memory and account validation cache growth
  old ROOT: 0b33151affcd213878211c48cffdc4d959b1bbb03cccc9ff4051c8bc0c7257ca
  by: owner unseal ritual (make core-unseal)

- 2026-08-26T04:13:44Z — REASON: seed bootstrap: the only hardcoded onion seed was down (5/5 no-descriptor from two independent Tor clients, re-confirmed by the integrator); replace with a re-verified first-party seed, drop clearnet seeds booked at the testnet port and one dead address
  old ROOT: 140f4b8914457b24b9ae9d412b58bc961032a736718672fe4475ee4fb5f1c1e6
  by: owner unseal ritual (make core-unseal)

- 2026-09-01T11:02:53Z — REASON: Owner-requested physical architecture migration; move unchanged consensus sources into their single authority and regenerate path-bound seal metadata
  old ROOT: a1533630bda2379889f9db262f81cd6e265ad474f642a1ee7d1de9523ac3b1aa
  by: owner unseal ritual (make core-unseal)

- 2026-09-01T13:23:45Z — REASON: Integrate verified origin/main chainstate snapshot changes after the physical architecture migration; preserve upstream behavior and refresh the path-bound seal
  old ROOT: fc01b45b7d14af9160cb5a93293ec17385cdcdbc7a1539042784452188bc2a57
  by: owner unseal ritual (make core-unseal)

- 2026-09-01T15:03:44Z — REASON: Add ARMv8.2 FEAT_SHA512 acceleration with fail-closed portable differential parity; optimize execution without changing SHA-512 output or consensus predicates
  old ROOT: d43b2c5210cce4204ba55336027cdab44326b493a5238cd79edd606a80a07f03
  by: owner unseal ritual (make core-unseal)

- 2026-09-02T09:42:14Z — REASON: refreeze for net/download split, sync perf and Windows headless sync commits already on main (3c459730c 7dcf7c838 bf230b881 edc64cdc6 36b72395d); owner authorization 2026-09-02
  old ROOT: 55641c2b6f2b8588a9e377400b6d8ff603c4e42a59d2f3bbe6fac42aeb9ee4d9
  by: owner unseal ritual (make core-unseal)

- 2026-09-02T11:40:58Z — REASON: Bound owner-requested post-Bubbles Equihash mining cancellation without changing solution generation or validity
  old ROOT: eb2d4c960bff0c1b46f3991aa030d7bc01de00b599edb41a65ea657953a0388d
  by: owner unseal ritual (make core-unseal)

- 2026-09-02T13:33:48Z — REASON: Separate locally validated block-piece serving from fail-closed UTXO snapshot export authority; no consensus predicate change; owner requested fast Z23 block serving on 2026-09-02
  old ROOT: 797012844b6ac9b663475a39f8097a8218491da16ff58e2a613cf3256c73ba3a
  by: owner unseal ritual (make core-unseal)

- 2026-09-03T04:46:03Z — REASON: Optimize the owner-requested 3M-block Windows block-swarm scheduler without changing consensus or block validity
  old ROOT: 8b8b8313fd5089603921022dba89c0477bbc440d5c9bd9bae1dcfa21d2cd2a8b
  by: owner unseal ritual (make core-unseal)

- 2026-09-05T17:23:18Z — REASON: disarm the ALPN challenge once validated so renewal needs no restart
  old ROOT: d603fa3418cbfb7ad75154d2cfcb1ba38c3f104c3d415c7026a98abca75a3446
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T03:37:19Z — REASON: Reseal after fast-sync state-offer additions to core/modules/net (24b6b4be3, 09f04fe20, 22684b47c)
  old ROOT: d70cca70fed110bfb5183c84c3ec10c6788628d051a5d927271a3a1b36024166
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T19:29:27Z — REASON: reseal https_server_install.c land
  old ROOT: 45b721d0466f435e5d7c3c3f59fb61a8aad6a7c485aa6677fbcddb69b31fdf99
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T14:11:00Z — REASON: checkpoint-bound state offers never go stale (owner-authorized 2026-09-06 14:05Z, fast sync)
  old ROOT: 30e82cac24cf9fb5f44c2e8de1af6d7fec714eae51c7a827e7809f35ba648a54
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T21:22:07Z — REASON: reseal after the /install.sh site route landed in core/modules/net (train 44 pick z23install d572fce02)
  old ROOT: 6abf47d15167be4d6f33502201d0cc10f3ea9441a14140be15eb9288932b30a8
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T13:52:50Z — REASON: Serve zclassicd beta6 NODE_BOOTSTRAP fast-sync in-band on the P2P port (owner-authorized 2026-09-10: legacy users stuck in multi-day IBD because both compiled bootstrap peers now answer with z23, which never advertised the bit)
  old ROOT: 8cb852f047f29eef74b6744c5be9e1dfb2c01838dadabce7a5e10ea4f5a69b7f
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T15:08:38Z — REASON: legacy MagicBean getblocks: send inv immediately and announce only HAVE_DATA bodies
  old ROOT: 8cb852f047f29eef74b6744c5be9e1dfb2c01838dadabce7a5e10ea4f5a69b7f
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T15:58:55Z — REASON: Split the beta6 fast-bootstrap seam and the BIP37 filter refusals out of msgprocessor.c into msg_beta6_bootstrap.c and msg_bloom_filter.c so the shrink-only legacy file returns under its 3031-line ceiling; dispatch rows, semantics and behaviour unchanged (owner-authorized beta6 sealed edit of 2026-09-10)
  old ROOT: e4fd36edb426d883959c7130a384435e72cdbdb66b5db2afb55b6c6a7fdf0482
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T19:55:26Z — REASON: Linear replay of MagicBean getblocks immediate-inv onto origin/main after GitHub rejected merge commits; no consensus predicate change
  old ROOT: e7852a59d4b3bfa47dffae9b2ffe012b6895416061a42b995b8945d99fd49bf7
  by: owner unseal ritual (make core-unseal)

- 2026-09-11T00:45:19Z — REASON: Move the getheaders serve budget and deferred replay into core/modules/net/src/msg_getheaders_defer.c so msg_headers.c returns under its shrink-only 2370-line baseline (landing seq 4 failed check-file-size-ceiling at 2506); pure move, no behaviour change; two refute rounds already passed on the logic; owner authority grant 2026-09-10 22:4xZ
  old ROOT: 2213de3b6c315a9e909389540be2319917c6d5a75c8186afdd04ad141b049fb4
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T18:51:41Z — REASON: C3: eliminate O(batch*queue) duplicate-forward scan while preserving exact download policy and accounting
  old ROOT: 190e3ac75aed53b58b4cc19b6c82bb720fca826bea5080ff075f5e00cc39df1b
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T19:25:23Z — REASON: C3 repair follow-through: move the download qset membership set into core/modules/net/src/download_qset.c so the shrink-only file-size and complexity ratchets stay satisfied; no behavior change
  old ROOT: d65d7f3bcfb45cfdf21d683e48997ee2a695fa8c119e677891a53b1a0ff3e01d
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T19:26:15Z — REASON: re-seal to include the newly tracked download_qset.c/.h from the C3 qset split; same tree content
  old ROOT: 52cb6823b358e979e5db21caf7a0332d2bb70f1e2edd1dc9c1d36f7dc184ec84
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T20:51:17Z — REASON: slice3: dedup P2P block intake ring by hash before slot alloc (1024-slot starvation)
  old ROOT: cd9b049fca58ade90a06d989285ad0ee63f8f7f1b66ed6ac91935a4aed4e5fab
  by: owner unseal ritual (make core-unseal)

- 2026-09-14T02:25:42Z — REASON: ACTIVE1 dl received-pending tombstone in core/modules/net download accounting (already reviewed+tested f6705235fd)
  old ROOT: a13489b1ee0f1a5d4fcbfb0f1d05e497c81ce3fb616782580daa305eb1ecc9ab
  by: owner unseal ritual (make core-unseal)

- 2026-09-14T10:53:01Z — REASON: c5-dynhost-post-client
  old ROOT: fffed5da03d6bce0933d89209fc4ba2ad7077b9c1d94452f0d173ca426014017
  by: owner unseal ritual (make core-unseal)

- 2026-09-14T21:14:03Z — REASON: difficulty_from_bits used Bitcoin's -29 shift base instead of ZClassic powLimit compact exponent 0x1f; historical-block RPC/explorer difficulty rendered 256^2 off (min-diff bits 0x1f07ffff showed 65536.0, legacy 1.0). Display-only math (RPC/explorer/netsplit ratios), not a consensus predicate. Owner unseal grant 2026-09-14 in reply to explicit request.
  old ROOT: 4bf80625c80f0352d8bfb38bee64ff0a94c73045272f64f528fd53f5be6474c9
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T14:39:03Z — REASON: Preserve fresh received-pending block-download tombstones across scheduler table rehash; duplicate-request avoidance only, no consensus or validation semantics change
  old ROOT: c3090fae6b449bd80dc449c365caa0d452a626402d0deb8c8a77c66f6eafcdf7
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T14:46:03Z — REASON: Preserve fresh received-pending block-download dedup guards across colliding scheduler inserts and size the non-consensus in-flight table from occupied entries; no validation semantics change
  old ROOT: ca171143339632e133b67beff708675e0eefcb5d4bc9f9bd3ba4971ac0e8c27d
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T14:54:33Z — REASON: Refactor received-pending slot activation after complexity gate feedback; behavior unchanged from the authorized scheduler fix
  old ROOT: db077704a65881601c8d8164ed4ee5f247daa7fc0c560ad38792ac53d58bf14b
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T15:33:24Z — REASON: Compact expired received-pending block-download guards before scheduler table growth; memory efficiency only, no consensus or validation semantics change
  old ROOT: 835a70d676498526d9587f574365b817ce6ee3c7d6addfa7a81ed78f93f018a2
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T16:49:03Z — REASON: Fail open received-body download dedup guards after a backward wall-clock step; scheduler reliability only, no consensus or validation semantics change
  old ROOT: 45880d284e79329b13b2a456a5eb58e0995305903fdb0e2705c6167242284823
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T17:00:46Z — REASON: Fail open stale block-download requests after a backward wall-clock step; scheduler reliability only, no consensus or validation semantics change
  old ROOT: 14fae82ed65487e2ebc868bd21607d43e99b4268ac2214760c0c66d4837c30a4
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T17:36:09Z — REASON: Fail open block-download peer-avoid cooldowns after a backward wall-clock step; scheduler reliability only, no consensus or validation semantics change
  old ROOT: 0c33e7ea16680e8ad9bf598fa5e803c4134a7dc379427f4deb31fae9f778d5e7
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T20:09:47Z — REASON: Ignore impossible block-delivery latency samples after a backward wall-clock step; peer scheduling telemetry only, no consensus or validation semantics change
  old ROOT: 888c92f7362b79913e880e16a574e47057230e2b41582b997388a9a2a606ebea
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T20:21:22Z — REASON: Refactor the authorized delivery-sample rollback guard under the shrink-only download.c line ceiling; behavior unchanged
  old ROOT: d66e5ba5d6fc917eb6a837ff4ee5cf64cc3bcb4f7e607a988e50c9bbd95e4130
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T21:02:12Z — REASON: Make block-download diagnostics fail open impossible peer cooldowns after wall-clock rollback, matching scheduler behavior; reporting only, no consensus or validation change
  old ROOT: d0ad9ffd5140a8a04e90d1965d4c2aa196b73a890bb58240cdd6dfc1521b9f89
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T21:12:53Z — REASON: Centralize the authorized peer-avoid rollback predicate so scheduler diagnostics cannot drift; refactor only, no behavior, consensus, or validation change
  old ROOT: f9e027060acd4899406ca3263044c39a07c96fc5c12354ad3e672e6753e9adb3
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T21:47:07Z — REASON: Fail closed unsolicited-block scoring grace after wall-clock rollback; defensive peer policy only, no block or transaction validation change
  old ROOT: 80ec71f31b28b2564e54622abf335911f6387d59ddaa7dab863c12dd4a40a117
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T22:00:41Z — REASON: Factor the authorized clock-rollback scoring predicate to satisfy the shrink-only complexity ratchet; behavior unchanged
  old ROOT: e28c7c0bfced2d15dd5cf26a039ccb42456b5b52bf85f52d26ecfe80ce32ffea
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T22:07:29Z — REASON: Reject rollback-aged compact block transaction responses so timeout recovery cannot accept stale peer state
  old ROOT: 5ed0d8fe936e1b80ce90de5b499a9aa5bc888c3ce42f9846b0cf39330ef4555b
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T22:38:23Z — REASON: Fail open operator addnode retry cooldown after backward wall-clock step; peer recovery policy only, no consensus or validation semantics change
  old ROOT: 31ad12c36805890fcda85f2915b9825484bda7db1490f9e5c5146cdc8e798404
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T22:53:37Z — REASON: Refactor the authorized addnode rollback cooldown predicate under the cyclomatic-complexity ratchet; behavior unchanged
  old ROOT: cdba42013891a4f47c47f224f1968bc8520d117d25ac38b56ba87c90d9cd39ec
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T22:54:44Z — REASON: Move the authorized addnode rollback helper out of shrink-only connman.c; behavior unchanged
  old ROOT: 2387ebd1362820a1ae0483b21546b27bdfc5aeb4d4526ffc180d4d12fd4c4250
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T23:33:32Z — REASON: Fail open addrman and discovered-peer retry cooldowns after backward wall-clock step; peer recovery policy only, no consensus or validation semantics change
  old ROOT: 1bac0cf627f15267c65592dec584be7008a3ac3b7ee2f5acca2ed6fcc55f7cf3
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T23:46:43Z — REASON: Expose the authorized rollback-safe retry predicate to its focused regression; test seam only
  old ROOT: a4cd17ee7372643dc164648803d23776ab447a227a5f8b91c2b4b70e5b8c9432
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T23:55:58Z — REASON: Move the authorized test seam out of shrink-only connman.c; behavior unchanged
  old ROOT: 94903b7df9fd25c96934d63249f42d8a74266b0d27a805428dae5458b418f64c
  by: owner unseal ritual (make core-unseal)

- 2026-09-18T23:57:30Z — REASON: Remove one blank line from the authorized retry-policy edit to preserve the shrink-only connman.c ceiling
  old ROOT: ed28f7cdc821fe32c4a6c96185eee7a580769c5b067fb030bd1cbf3a2d0583a0
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T00:42:22Z — REASON: Fail open addrman selection and dead-entry cooldowns after backward wall-clock step; peer scheduling policy only, no consensus or validation semantics change
  old ROOT: b4706d661db69e751b185a3556d312faaf7ff60466676d08eedbb458275f6086
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T02:28:59Z — REASON: Use the existing monotonic peer connection stamp for TCP-connect and version-handshake deadlines so backward wall-clock steps cannot strand outbound slots; networking policy only, no consensus or validation change
  old ROOT: 5112c261b8fb144a9ed22779fe430a883ee2d20d752501ecf79f0dba4bfa2667
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T02:49:45Z — REASON: Use monotonic elapsed time for compact-block response scheduling so wall-clock corrections cannot discard fresh blocktxn responses; networking policy only, no consensus or validation change
  old ROOT: 0c2a7215781b897b98e65298041f1101b73c0920d6d0ec19a684995f375324d1
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T03:06:18Z — REASON: Use monotonic elapsed time for legacy block-download request deadlines and peer cooldowns so wall-clock corrections cannot mass-timeout or strand healthy IBD windows; networking scheduling only, no consensus or validation change
  old ROOT: 2a8f076f98e37325191560c0db6b42d4727acb133682cebd0522a5987e7a09bd
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T03:55:47Z — REASON: Use monotonic elapsed time for per-peer addr flood windows so wall-clock corrections cannot falsely disconnect healthy peers; defensive networking only, no consensus or validation change
  old ROOT: 835256bb1efae997fe65bca13fa19abf1a5827f5c6b0fe20820909289e5d60e7
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T03:57:44Z — REASON: Repair the platform time compatibility include for the authorized addr-window monotonic timer change; behavior unchanged
  old ROOT: ffd23cf9f1a6a413b031666e3a26372b1323cda276fd144c8574da9e1b44a3af
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T04:18:30Z — REASON: Use monotonic elapsed time for automatic banlist write debounce so wall-clock corrections cannot strand dirty defensive-networking state; persistence scheduling only, no consensus or validation change
  old ROOT: 2a918dc7bb8a6b8812b0984d8b765bf21aaa6142bca57ce28730f6e7fb5c989e
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T04:30:28Z — REASON: Keep the authorized banlist debounce change within the enforced legacy file-size ceiling; behavior unchanged
  old ROOT: 1cf7a537a4f680b578596cb2a57f3ea70f405a8f5cb2159ffd08d2ac98c0edaf
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T04:44:02Z — REASON: Use the existing monotonic peer connection stamp for disconnect lifetime diagnostics so wall-clock corrections cannot erase session-age evidence; reporting only, no consensus or validation change
  old ROOT: bdc75f4db95afc89999a68da83363fa6306b29dd0c8827acfce32eaf52557e9d
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T04:58:42Z — REASON: Use monotonic elapsed time for outstanding peer ping statistics, matching the existing monotonic ping origin; reporting only, no consensus or validation change
  old ROOT: 32febd85aaee858c15f74cb94fc6886d35a384b3781345684a4db7d8f68357b1
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T05:07:42Z — REASON: Keep the authorized peer ping statistics clock correction within the enforced legacy file-size ceiling; behavior unchanged
  old ROOT: e81d519e5e775997f1316d8714afabecd088ccddbb4a3981cf0d6f34695e45f0
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T05:40:42Z — REASON: Use monotonic elapsed time for WebSocket client heartbeat and idle deadlines so civil clock corrections cannot suppress cleanup or disconnect healthy subscribers; networking liveness only, no consensus or validation change
  old ROOT: 2c8297a00927988f5ec9fcd32710dbf969a8e03499fdad60679531484a0d0c4e
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T07:09:39Z — REASON: Use monotonic time for peer-status logging cadence; no consensus behavior changes
  old ROOT: d14eef4dc07e5a3181a92cd6ce7dcbe96cc3bc018d36b961b77776ed3a339cd8
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T07:26:17Z — REASON: Add tested monotonic peer-status cadence; no consensus behavior changes
  old ROOT: 40f4e10492da5f4597362af98ea784e9d880f797df598fd36a0fc484eec6330a
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T07:29:00Z — REASON: Reduce peer-status cadence change within complexity and file-size ratchets
  old ROOT: 72269f6af256a245a86979d120ecfd369bf4ae3e3ed127e7d58bdab1d09f8f25
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T07:29:53Z — REASON: Keep connman within shrink-only file-size ratchet
  old ROOT: ed0e504d7723f1394df31ca1bb6da91e55f9023f2f6a154470d41fb8f298de34
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T08:02:24Z — REASON: Use monotonic elapsed time for peer lifecycle handshake and reconnect diagnostics so civil clock corrections cannot corrupt incident scoring; reporting only, no consensus or validation change
  old ROOT: 4c8bd3796ba512e2bcb33b843cffc693e0a8557443aba389cc40812b5177a725
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T08:11:10Z — REASON: Keep the authorized peer lifecycle monotonic telemetry change within the shrink-only file-size ceiling; behavior unchanged
  old ROOT: 3adc35e0768fdce323618a6d7f86ab45df6760d101feed0b8b92fac6359b5ce2
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T08:12:28Z — REASON: Remove one blank line from the authorized peer lifecycle telemetry edit to preserve the shrink-only file-size ceiling
  old ROOT: 41836ea6f2b315111de74534615cf386e8c7091d44ba3dccdf93ff4a429a871a
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T08:43:24Z — REASON: Schedule periodic addrman durability from monotonic time so wall-clock rollback cannot postpone peer persistence; networking reliability only, no consensus or validation change
  old ROOT: e4c199d594cfd4a7668e04d4cf6269734496753361c8cbd01bff05a743501bcd
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T11:36:09Z — REASON: Use elapsed monotonic time for non-consensus Dandelion embargo deadlines; transaction validation and consensus are unchanged
  old ROOT: 03ba369c1c50416dd5591ce6a1284acb7a2ab174d7efd80fcd49ce1c96c236d7
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T13:32:32Z — REASON: Use elapsed monotonic time for non-consensus fast-sync chunk and block-piece timeout reassignment; block and transaction validation remain unchanged
  old ROOT: 6943bc3fbda56684708f8061a6b20548e40581aeee84317018ecd28ba34a9b53
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T14:07:21Z — REASON: Use elapsed monotonic time for non-consensus per-peer fast-sync request deadlines; block and transaction validation remain unchanged
  old ROOT: 8df20e3b8aeb330cbb585f1a1ef5717d748ffa920afc8839207f3f3b25c4a480
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T14:59:13Z — REASON: Use elapsed monotonic time for non-consensus received-block dedup guards; block and transaction validation remain unchanged
  old ROOT: 6bf77db5fd63df31627bb299bd63b681ee22d5567927c5280a9adf3f0f9cf956
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T15:11:23Z — REASON: Use monotonic elapsed time for block-download throughput reporting so wall-clock corrections cannot distort IBD diagnostics; observability only, no consensus or validation change
  old ROOT: 4a99e9a43019a51409f734667ec538589628a2c1c5ed40459d2a8bd82facce54
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T15:32:42Z — REASON: Use monotonic elapsed time for non-consensus peer-floor alert grace and duration so wall-clock rollback cannot suppress degraded-peer recovery evidence; no consensus or validation change
  old ROOT: c7b69a8124a3017d04f4e967665bfaf3ca0c1e48890cde53930e964bc0b1ecc0
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T15:42:14Z — REASON: Refactor the authorized monotonic peer-floor timer call after the shrink-only file-size gate; behavior unchanged, no consensus or validation change
  old ROOT: 99002524bcc275d4d7eb67a67e2631d1365cca1652e54b43a319763cc01a9134
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T07:32:16Z — REASON: Bound block-swarm requests to each anchored peer manifest; peer scheduling only, no consensus semantics
  old ROOT: 8b3df2f79fe3743f4819760874225bd83405cfb8a1d66abcfee338c926f9f426
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T08:50:42Z — REASON: Use monotonic elapsed time for block-swarm restart cooldown; scheduling only, no consensus or validation change
  old ROOT: 17cb70b6fc1e3b9ea97044740a345b6155dbebe057fd8552915c76882d1991a7
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T10:05:08Z — REASON: Use monotonic elapsed time for block-swarm silent-stall ownership; scheduling only, no consensus or validation change
  old ROOT: 60db33754e930e0ab95ad7728c8dea30bd34b1a653f4599f5c8dd8f316b70490
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T10:21:30Z — REASON: Prevent stale block-swarm pipeline owners from requeueing reassigned work; scheduling only, no consensus or validation change
  old ROOT: 6a1393d9f20a11657fdb77482655cb0df8e579512d275ec2d34b4925c7514be8
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T12:00:54Z — REASON: Bound new block-swarm assignments per send tick for multi-peer fairness; scheduling only, no consensus or validation change
  old ROOT: 7fc95bf918b162332253e1707dd4acc6f41b48d4c8fcab7732588ba45a8e26e2
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T12:03:57Z — REASON: Refactor block-swarm timeout cleanup to keep fairness scheduling complexity below its ratchet; no semantic change
  old ROOT: a90d743461a0b3c08d9883557be9d3f3375c5ec055f62d984677f03d0bc49897
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T16:36:13Z — REASON: Reclaim stale block-swarm peer pipeline slots after verified late delivery; request scheduling only, no consensus or validation semantics change
  old ROOT: c2314e49c138d1eb24f5832f99b1e7f9580f525d89da859bab59a590a3c049c5
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T22:03:51Z — REASON: Prevent a timed-out block-swarm peer from immediately reclaiming its own expired work; request scheduling only, no consensus or validation semantic change
  old ROOT: 80d63e0d727d661a13b88f10ece4c2d70eb973cded0e7067730bdbbfc0820397
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T22:27:06Z — REASON: Make snapshot chunk and block-piece timeout arithmetic overflow-safe under monotonic anomalies; scheduling only, no consensus or validation semantic change
  old ROOT: 2891ed7d79f668f769b46504bdbcbead88a2d6cc9587a5c4c1a0ee6c5f16eafd
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T22:51:03Z — REASON: Keep block-swarm availability counts bounded when an untrusted peer repeats or replaces its bitmap; scheduling only, no consensus or validation semantic change
  old ROOT: 2daff4bdfc7bbbc054d843d0c4093d435b492eca1b43550c31de12a558d59021
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T23:15:57Z — REASON: Withdraw a disconnected peer bitmap from block-swarm availability exactly once alongside piece requeue; scheduling only, no consensus or validation semantic change
  old ROOT: 28236f4e061dcadd1f09a5468794b32abfac9059d1907c694147a8ed2338197e
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T23:40:30Z — REASON: Close active-swarm generation race in disconnect and bitmap replacement by deciding ownership under the swarm mutex; scheduling only, no consensus or validation semantic change
  old ROOT: 48c14e43ce83c60259d6a4ebff58e7c61a298a828878fb7a7507dfefb8d906f1
  by: owner unseal ritual (make core-unseal)

- 2026-09-20T23:49:34Z — REASON: Reject malformed block manifests with overflow-safe 64-bit height-span arithmetic before allocation; wire validation only, no consensus semantic change
  old ROOT: 3a80ba0e49ec648fd6c30e17c6f67e27d6c27e01382e38d7d56fc2bb58e9e871
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T00:16:31Z — REASON: Immediately requeue an owned snapshot chunk after malformed or partial peer delivery; scheduling recovery only, no consensus or validation semantic change
  old ROOT: 181e293a86861ab4105177fbbdac0aadaa1368194ceda1fd74b3148e061e16fc
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T00:24:14Z — REASON: Refactor malformed snapshot response recovery to preserve the cyclomatic-complexity ratchet; scheduling only, no consensus or validation semantic change
  old ROOT: 6524a8b4011dde023838d76f7ed4e4c0ba9f202ed14a8b70e3463f54af02a963
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T00:42:39Z — REASON: Immediately requeue snapshot swarm chunks owned by a disconnected peer; scheduling recovery only, no consensus or validation semantic change
  old ROOT: 0925ea8ff0c0145779f3f3b4b951daf054ef9e2044da90653f413fbe55e9632f
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T01:04:13Z — REASON: Prevent stale peer-local snapshot timeout cleanup from revoking a chunk already reassigned to a healthy peer; scheduling only, no consensus semantic change
  old ROOT: 2faa6ee45a426d8364e37b6fb4a8b6d360f2bf94479e829fd0224a373cc213b8
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T01:18:47Z — REASON: Reject unsolicited or duplicate snapshot chunks unless the sender still owns the in-flight request; accounting and scheduling safety only, no consensus semantic change
  old ROOT: 62c0020008418c14d95c41bcdfc898e6fc6f28e1dca3addc1616ba6355f8bfa1
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T01:21:22Z — REASON: Refactor snapshot chunk ownership enforcement into bounded helpers to preserve the cyclomatic-complexity ratchet; no semantic or consensus change
  old ROOT: 9501a1223bdc514822a8c6f3a9650b9468badcbbee5a7e430b0c40a08425bcb1
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T01:36:10Z — REASON: Use overflow-safe monotonic elapsed-time evaluation for peer-local snapshot timeout cleanup; scheduling only, no consensus semantic change
  old ROOT: 8360d8d72c9f7ebd1ccaccf434265f3d9fb828248e1b6c5a40331e4c4a93492d
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T03:10:56Z — REASON: Add test-only snapshot swarm state seams for direct framed zchunkdata adversarial regression coverage; no production behavior or consensus semantic change
  old ROOT: ac003e6cd7671e32b1884b6c2287f9999ebceefeb36b7f97a4197579278bbe11
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T03:27:26Z — REASON: Admit secondary snapshot sources only when their verified manifest exactly matches the active swarm, with race-free mutex serialization; scheduling safety only, no consensus semantic change
  old ROOT: 43f2dbf04364140eb36f20d2f024b532255d5f62819d58ce6b2d349de6633422
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T03:33:08Z — REASON: Add deterministic test access for exact snapshot manifest source admission and reconnect failover; no production or consensus semantic change
  old ROOT: f951fe27e4d1bd6a7f10f42ff970c85fe65d9e5fdba06f522d29d67597450af6
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T03:48:56Z — REASON: Compare every snapshot manifest identity field when admitting secondary sources; future-safe scheduler validation only, no consensus semantic change
  old ROOT: 3b28758fd41b449173bc79fe480cb40a386800af6aaa3f0c9599af4ab9f353c8
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T03:51:07Z — REASON: Refactor exact snapshot manifest identity comparison below the complexity cap; no behavioral or consensus semantic change
  old ROOT: f77c2d480a4a324ca29c46cd59242e2d4efca303fe98adc85d2ef664827689c1
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T03:52:27Z — REASON: Remove a redundant manifest-size guard rejected as always true on supported 64-bit builds; no behavioral or consensus semantic change
  old ROOT: 1d8cc5413ffef088c00be9a50458353c5c58c1ba95dc078ae45048ed34eb6acd
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T04:04:12Z — REASON: Remove the manifest-admission test seam after replacing it with direct framed zmanifest regression coverage; no production or consensus semantic change
  old ROOT: fc1ac272f7dbf68a12f1c2158d730d3fd1517b00508399042751c8409b5a716f
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T04:20:11Z — REASON: Bound repeated per-peer zmanifest parsing work per active snapshot generation while allowing one corrective retry; networking resource defense only, no consensus semantic change
  old ROOT: 7fed10447c1fdd6dd2fe0c84208f9fd62a8668af6d7b0506e8e421d3090889eb
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T04:22:02Z — REASON: Keep zmanifest attempt admission outside the large wire dispatcher complexity pin; refactor only, no consensus semantic change
  old ROOT: 5f146cceb9ceb83721d078c7b1ce960e6f36786e16f0f9d577a3fc7d61308f24
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T04:38:35Z — REASON: Bound repeated per-peer block-swarm manifest parsing per swarm generation; networking resource defense only, no consensus semantic change
  old ROOT: e7959745e93cf66586b84343b491dd14ca873c7519efbc5d6dea83fd3171f8f1
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T04:56:19Z — REASON: Admit block-swarm sources only when their validated manifest exactly matches the active swarm, with serialized initialization; scheduling safety only, no consensus semantic change
  old ROOT: 25f8856ae12c97d1e980c289cd4eab11133a75034902c0002c01f071ca3a175a
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T05:17:04Z — REASON: Bind block-swarm source eligibility and availability bitmaps to the exact active generation; scheduler safety only, no consensus semantic change
  old ROOT: eccaebe1effc20ecf42bffa6630ca69f9ed90363a1f00fc583151223b8c5e275
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T05:21:58Z — REASON: Update block-swarm fairness fixtures through a generation-aware test admission seam; no production or consensus semantic change
  old ROOT: 88ac87c0fe20b3f97fe7aa1feaad03d73740ccdfce26d25cbde5fc21db397b6b
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T05:40:37Z — REASON: Bind block-swarm bitmap advertisements to an admitted manifest generation and exact piece span; scheduling only, consensus unchanged
  old ROOT: 2fa02c75067bac59e2c0116bd901fe7e8f807742d0b2798b04b50d4ea283ac0b
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T05:57:50Z — REASON: Bound block-swarm disconnect cleanup to the peer pipeline and revoke detached peer admission; scheduling only, consensus unchanged
  old ROOT: 359f21ab5c93b59f72c169e9d9437a3acfe2eb81f3a0d403dd32b84cad53ac96
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T06:15:54Z — REASON: Revoke snapshot-swarm admission on disconnect and require exact generation for scheduling; request coordination only, consensus unchanged
  old ROOT: 2c7d339897978e358afbb101236a52a81679865d1fbd2f53631cb5715483820d
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T06:23:35Z — REASON: Reject block-piece bodies not owned by the admitted peer pipeline before parsing; transport scheduling only, consensus unchanged
  old ROOT: 574b7ac4056a179ccaf6c10fe4c24b98ce71cfdacc68cc3aa6af8faa0a8d9cfb
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T06:46:28Z — REASON: Bind block-piece credit to the exact swarm generation across unlocked body submission; request accounting only, consensus unchanged
  old ROOT: a2609d3f108a0a253c8da6da2510caebc67e507703170d6592b3cf91309e649c
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T06:55:07Z — REASON: Observe per-peer block-swarm requests, deliveries, timeouts, and delivery latency for measured scheduler diagnosis; diagnostics only, no consensus or validation change
  old ROOT: 6cc7e7112ec0532ec7124637162fc510042376b693ae9551be172e3d658def2a
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T07:07:19Z — REASON: Refactor block-swarm ownership credit into a bounded helper after complexity ratchet feedback; no behavior, consensus, or validation change
  old ROOT: dbe24d98044c4eb3c2bbd563c5f63e1669559222824ce254c5407d2b177345a8
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T07:14:38Z — REASON: Move the block-swarm credit helper below its file-local state declarations after a clean sanitizer compile exposed declaration order; refactor only, no behavior, consensus, or validation change
  old ROOT: 72e8e7ac118c013b8e2d0f5875fe8076b395b306c8b1f7ade29602ef1e314fd7
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T07:36:43Z — REASON: Reserve block-swarm forward-window capacity from inbound-first send ordering so healthy outbound peers cannot be starved; transport scheduling only, consensus and validation unchanged
  old ROOT: b1d19b6f144ecf8ff56b2286c42333231ab118a2349fcad0f85c28655947f1cd
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T07:50:14Z — REASON: Reject stale block-piece responses before body parsing when global timeout or reassignment has revoked peer ownership; transport resource accounting only, consensus and validation unchanged
  old ROOT: 0c428e3cd4f8f45b134c59aa777563ede43521dcd7d8423bef2e538727119edd
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T08:05:22Z — REASON: Reclaim globally owned block-swarm pieces and source availability across peer reconnect churn; transport scheduling only, consensus and validation unchanged
  old ROOT: 9ff9481a45bafda06bb37e76f7065208dbb93a3be8e2e1302e5ee19be1f25e6e
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T08:19:40Z — REASON: Preserve per-peer timeout ownership attribution by reconciling only the owning pipeline before reassignment; transport telemetry and scheduling only, consensus unchanged
  old ROOT: 74b4745f2970992be3c4fd5df634256fc8ab6d7e2b18f1bba5c1e93403d7d7b2
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T08:26:11Z — REASON: Prevent a timed-out snapshot chunk owner from immediately reclaiming work while retaining bounded orphan cleanup; transport scheduling only, consensus unchanged
  old ROOT: de56e48b624a944f2a2f344fbbad8bf56d999667d23cc13b640a65e43a31ab82
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T08:28:57Z — REASON: Refactor snapshot owner-timeout handling below the cyclomatic-complexity ratchet without changing transport behavior or consensus
  old ROOT: ae43277e7f177a9b92cf867aaefa9d2753a845a0670c7154345c2884c427a25f
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T08:33:45Z — REASON: Integrate previously validated header range empty, terminal, disconnect, continuation, progress, and stable-target recovery onto the current networking branch; transport scheduling only, consensus unchanged
  old ROOT: ffbe008855edc80638d13a9a116428c7d0a654a321cd4310cc32c60ae0e99bcc
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T08:48:09Z — REASON: Reclaim snapshot chunks from authoritative swarm ownership on peer disconnect; transport scheduling only, consensus unchanged
  old ROOT: 6de072a9b3bfa619119445726598654447fe7a898cc82b2623645c54f4106e11
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:07:17Z — REASON: Bound snapshot chunk assignment scans with a retry-aware next-needed hint; transport efficiency only, consensus unchanged
  old ROOT: 14c6492f015c8e84440796c01d37097f3150adbb1cc457fe417ae9e6338e9e24
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:15:05Z — REASON: Prevent untrusted snapshot hash mismatches from exhausting global chunk retries; validation unchanged, transport liveness only
  old ROOT: 8fd77bf6c7c20c119347aac5c821f0dcb18279b8b748a5a4ab61e00023424f93
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:20:23Z — REASON: Release block-swarm ownership immediately after malformed or truncated owned zblkdata; transport recovery only, consensus unchanged
  old ROOT: 43e9512fb836915da91f9ccdef65f26367f52925392693b36ca342402f60fe2f
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:31:42Z — REASON: Roll back block-swarm ownership when a request cannot enter the bounded send queue; transport scheduling only, consensus unchanged
  old ROOT: c5a5943c46f71116ab0b7b3e1e69f9ad9b87de49dd47c79b8daca20657fdf442
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:38:46Z — REASON: Release snapshot chunk ownership when its request cannot enter the bounded send queue; transport scheduling only, consensus unchanged
  old ROOT: 24737b9af6cd205f57a4de84ee6399f6ea3cf9a93bb0722c2631ecf5b9a1c82c
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:44:25Z — REASON: Release header-range ownership when bounded getheaders enqueue fails; transport scheduling only, consensus unchanged
  old ROOT: e3af2a02f939e6b8a21fd943a70974bd6d8cf504543dbc38eb28c06e7f786d9f
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T09:52:13Z — REASON: Restore checkpoint and header-repair retry eligibility after bounded getheaders enqueue failure; transport liveness only, consensus unchanged
  old ROOT: 272b995ba06b90c715944e7f90f36197255e8e47c0363b12645eb3520b782783
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:03:30Z — REASON: release legacy block ownership when getdata cannot be queued
  old ROOT: 3bbab9f94e70282e6cf084d5ed81b7b835ecb807de74e6cfbe63af88c3bb029d
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:07:43Z — REASON: extract bounded getdata enqueue settlement helper for complexity ratchet
  old ROOT: 428edbb879f8df77d179ad38b33157b943af9e9b75d3a06e0bf8eb1a2d066ac5
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:17:44Z — REASON: release snapshot negotiation when its followup cannot reach the selected peer
  old ROOT: 9b3a3d8ba8af5bfab4b163bf35c62c3f43650f7ac303143a4a93fa4af45c07ff
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:25:58Z — REASON: notify snapshot negotiation after peer removal outside connman peer-list lock
  old ROOT: 72d07388032f18dca178c1216d3f78cad910ac4bac4953d65c9e71b5df3c0a54
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:41:40Z — REASON: refactor peer-finalization callback out of connman reactor complexity
  old ROOT: 01f01e6e246c6986e217570e541d417646811bb29ed23eb53452740726fe4e8f
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:47:21Z — REASON: use monotonic cadence for snapshot and block swarm progress diagnostics
  old ROOT: accd354f0932f88515769c6f706530b97579ae7dc55e5522e037b0ff5d80b29b
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T10:52:27Z — REASON: qualify peer-finalization callback through actual connman socket reactor
  old ROOT: e0f14cd5214b8d566b71dded5da7b6b22a223a7ac19aa1a48b46d69df5183c6c
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T11:14:24Z — REASON: reserve snapshot chunk capacity for outbound sources
  old ROOT: f7cf47a87fd359cd4b8d9a48735134076559057af4d0c0388b4307473f483232
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T11:24:46Z — REASON: reserve legacy block download capacity for outbound peers
  old ROOT: 442d75e381f016cdf5ddd45f2c49ab82db65a628765eddd3a44c0b7c3987861d
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T11:37:52Z — REASON: propagate getheaders enqueue result so failed requests remain retryable
  old ROOT: de433d1462fb92629fd7f0f86f5341a5d1590aba7e17bb82a992acaca74b1a2d
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T11:47:39Z — REASON: make inbound header-stall fallback produce an explicit request action
  old ROOT: f770b6603bbb3de54511085222239c20b75dfb1ec2847e88037719079404f145
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T11:53:58Z — REASON: stamp rejected-header probe rate limit only after successful request enqueue
  old ROOT: c282304f36fe0b56d9ceb1be51effbd26e181ae22f0c1dde02cc7cdcfe59a63e
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T12:10:18Z — REASON: Advance outbound handshake state only after the version frame enters the bounded send queue; no consensus or wire semantic change
  old ROOT: 6cba006a8f34439f880b2b46e5a2c516d272c038e3753b063b19150eed43d5ca
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T12:14:02Z — REASON: Refactor version enqueue result handling below the existing send-loop complexity ratchet; no behavior or consensus change
  old ROOT: ca98374bd5129a13fcc390228e48f2e247b4641a9a2ccc12d9ecf73185b941eb
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T12:34:09Z — REASON: Record keepalive nonce and pong deadline only after the ping frame enters the bounded send queue; no consensus or wire semantic change
  old ROOT: d9a9c1eaa5dee9fd125792aac7c00a110748a263c4dfb1a025bf3bbe9d49c0b0
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T12:53:35Z — REASON: Mark outbound peer discovery requested only after getaddr enters the bounded send queue; no consensus or wire semantic change
  old ROOT: 4c7f66674bdd0b007b10c1fe71f96bd483ec37a1fedc716a2982d442bf925cb6
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T12:59:46Z — REASON: Preserve post-handshake mempool retry when the bounded send queue refuses the request; no consensus or wire semantic change
  old ROOT: 3b424a56f09d88c014d167ee3d33acebdbd40e2bc26371c20d973d86ceb3f8df
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T14:44:08Z — REASON: Bound snapshot chunk reacquisition by a reconnecting endpoint so stable compatible peers get an immediate reassignment opportunity.
  old ROOT: a7cf767c120bb7ba23fc7d42085bf85e7a7a2a1f8f209fc4e1ee51e3de9daedf
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T15:03:48Z — REASON: Give an already-admitted snapshot source an immediate reassignment opportunity after another source times out.
  old ROOT: 5afd3b1d83bca54918c95a5d899b021916e0d0193ac6defff1c9709fca4b5b5a
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T15:09:30Z — REASON: Preserve one bounded healthy-peer reassignment opportunity after a block-swarm source times out.
  old ROOT: 36a9c0ddcd1c5fe35fe041e39c042e1e59d55d319b75cf75c86d94f1fd5ef623
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T15:31:13Z — REASON: Preserve snapshot and block manifest retry state when bounded peer send queues reject the frame.
  old ROOT: 2c3a414d8ea5b2f6ca1506cd911d1f73d5f4a670e26c471626f6c47195017e3c
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T15:51:44Z — REASON: Consume snapshot reconnect yields one endpoint at a time under multi-source churn.
  old ROOT: 4a8e4c03e45e49c5bf9a063ffcc7581670ca007a1af1850ce1ba6188c44ace46
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T15:59:02Z — REASON: Preserve snapshot offer retry state when bounded peer queues reject advertisements.
  old ROOT: c11e814f13d19a434940304aa87269e434fa780b3f116db9361799762b295a43
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T16:07:57Z — REASON: Preserve snapshot serving cursor and completion state when bounded queues reject data or end frames.
  old ROOT: 3b505205f3aeeb339e5fd96f00bcfe021d4cfa5b770352f7e84959ab877def29
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T16:39:13Z — REASON: Preserve snapshot reconnect yield until zchunkreq enqueue succeeds
  old ROOT: eeb2ccc16f68be6f7f5e3537183c7eaf43a5a4d9a9a961617a09794844f69f8b
  by: owner unseal ritual (make core-unseal)

- 2026-09-21T16:56:54Z — REASON: Maintain bounded inbound block-download occupancy counter
  old ROOT: d94f1adac5689216cfc1e0683b5a1a39933d94de1edb86972517cc7e03e9d7cc
  by: owner unseal ritual (make core-unseal)
