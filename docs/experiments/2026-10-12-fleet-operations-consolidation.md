<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet operating documentation consolidation

Source base: `05b4239f065255d53cb24f33f7b430691f07d7c9`.
Observed at 2026-10-12T23:34:11Z (2026-10-12T19:34:11-04:00).

The change gives operators one fleet policy reference while retaining separate
owners for development procedure, current priorities and platform evidence.
AGENTS.md changes from 23,043 to 14,982 bytes, measured with `wc -c`.
Historical macOS evidence and source-baseline provenance move to their
respective runbooks; the entry point links them.

Source and native catalog inspection distinguish the existing Linux confined
mesh terminal from the separate package runner. OpenSSH integration,
protected macOS terminal execution and complete guest routes remain
unqualified. The monitoring contract distinguishes live datadir headroom,
cached worker reports and bounded signed mesh status refreshes. It does not
claim complete development-volume collection.

The ML-KEM README now identifies its zssh caller without claiming a deployed
SSH endpoint. Package documentation participates in content identity;
`make docs-zcode-package-registry` re-derived the affected root and reached
a clean fixpoint over 97 package manifests. No registry root was edited by hand.

Initial documentation checks detected and prompted repair of one relative
link. The package-anatomy gate passed directly over 80 packages after its
prerequisites were available. A subsequent lint attempt correctly rejected
the changed module's stale registry root; canonical regeneration resolved
that drift. These observations do not replace final exact-candidate gates.

Reproduction: through `devbuild --wait`, run `make -j28 lint-fast
check-doc-claims check-doc-accuracy check-markdown-links`, followed by the
native exact candidate/base publication proof. Full deployment, end-to-end
fleet collection, native OpenSSH and guest SSH are not established by this
documentation change.
