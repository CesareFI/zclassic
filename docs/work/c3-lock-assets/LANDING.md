# Landing checklist

1. Fetch `origin/main` and prove candidate ancestry. Requalify after a rebase.
2. Confirm the diff contains only the qset class cache, contention regression,
   catalog registration, and exact impact mapping.
3. Confirm Core is resealed and lint, affected exact groups, and the public
   binary build pass on frozen bytes.
4. Confirm B review and C measurement bind the same commit, source root,
   recipe, dependency/toolchain closure, and artifacts.
5. Confirm rollout HOLD exists and no deployment or restart service is enabled.
6. Verify the native land queue and remote-base ancestry; submit the exact SHA.
7. Observe the lander's GREEN receipt and ready SHA. Queue acknowledgement is
   not publication.
8. Publish through the authorized path, fetch `origin/main`, and verify the
   exact remote commit and tree.
