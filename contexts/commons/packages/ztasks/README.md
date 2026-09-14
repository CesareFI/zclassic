# ztasks

Reusable bounded C23 task state, extracted from the native task-app reference.
The same code is consumed by its resident workers and host. It validates task
titles and IDs, preserves revisions and write IDs, and encodes a canonical
schema for persistence and process-generation handoff. Failed decoding leaves
the previous value intact. No database, process, network or wallet authority
belongs to this package.

The package test proves byte-identical reload and refuses empty titles,
duplicate IDs, unknown schema and noncanonical state without losing edits.
The host supplies add/edit/delete, filtering, presentation and durable writes.

The app journey lives in `tests/harness/fixtures/instant_app`: it consumes this
package and existing Z23 presentation. That process adapter is test-only until
exact opened-image admission is supplied. Package reproduction does not turn
pathname execution into exact execution, establish GUI interaction, or grant
permission to install an application.
