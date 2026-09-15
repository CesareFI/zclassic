# ztasks

Reusable bounded C23 task state, extracted from the native task-app reference.
The same code is consumed by its resident workers and host. It validates task
titles and IDs, preserves revisions and write IDs, and encodes a canonical
schema for persistence and process-generation handoff. Failed decoding leaves
the previous value intact. No database, process, network or wallet authority
belongs to this package.

The package test proves byte-identical reload and refuses empty titles,
duplicate IDs, unknown schema and noncanonical state without losing edits.
The host supplies add/edit/complete/delete, undo, presentation and durable writes.

## Local task editor

Choose a private directory for your task data, then open a new task or the first
saved task with the native host:

```sh
z23 app tasks --datadir="$HOME/Tasks" --action=new
z23 app tasks --datadir="$HOME/Tasks" --action=open
```

`open` also accepts `task_id` to select a saved task. The current window edits one
task. Save keeps it open; Close saves the latest valid draft before closing.
Saving runs on an owned worker. Saving, Saved and Save failed describe the durable
save state; a failed save retains the draft. Tab and Shift-Tab move focus between
the title and actions. Titles currently use up to 95 Basic Latin characters and
the reused state codec bounds a document to 32 tasks.

Headless `app tasks` actions are `list`, `add`, `edit`, `complete`, `reopen`,
`delete` and `undo`. Changes require `expected_revision` from the last read;
stale edits refuse. Undo survives restarting the host. These operations remain
available while the task-list window and its complete/delete/undo controls are
being built.

`tests/harness/src/test_task_document.c` exercises persistence, failed commits,
busy storage, newer typing during a save, native form pixels and keyboard focus.
Real macOS desktop interaction remains OPEN pending desktop access. App update
preview, acceptance and rollback compatibility are not yet qualified by this
task editor. Package reproduction alone does not establish GUI interaction or
grant permission to install or execute an application.
