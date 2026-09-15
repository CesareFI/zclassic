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

Choose a private directory for your task data, then open a new task or the task
list with the native host:

```sh
task_datadir="$HOME/Tasks"
z23 app tasks new "$task_datadir"
z23 app tasks open "$task_datadir"
```

`open` shows the task list; `task_id` opens one saved task directly. The list
offers New task, Edit, Complete/Reopen, and More with Delete and durable Undo.
Arrows, Home/End and Page Up/Down move the selection and scroll it into view.
Tab/Shift-Tab move between the list and action buttons; Enter edits the selected
task, Space toggles completion, Delete removes it, and Cmd/Ctrl+Z undoes the last
durable change. Cmd/Ctrl+N opens a new task. Selected rows have a visible focus
border. The list displays eight rows at a time and retains selection while a
save completes.

Save keeps the editor open; Back to tasks saves the latest valid draft before
returning to the list. Closing the editor window saves before exiting the app.
Saving runs on an owned worker. Saving, Saved and Save failed describe the durable
save state; a failed save retains the draft. Tab and Shift-Tab move focus between
the title and actions. Titles currently use up to 95 Basic Latin characters and
the reused state codec bounds a document to 32 tasks.

Headless `app tasks` actions are `list`, `add`, `edit`, `complete`, `reopen`,
`delete` and `undo`. Changes require `expected_revision` from the last read;
stale edits refuse. Undo survives restarting the host. These operations remain
available for automation and headless use.

`tests/harness/src/test_task_document.c` exercises persistence, failed commits,
busy storage, newer typing during a save, native form/list pixels, keyboard focus,
list navigation during a save, deletion/undo, restart and conflicting writers.
Real macOS desktop interaction remains OPEN pending desktop access. App update
preview, acceptance and rollback compatibility are not yet qualified by this
task editor. Package reproduction alone does not establish GUI interaction or
grant permission to install or execute an application.

### Program changes and user data

The host stores task data independently of the current and previous program
identities. Returning to a previous program must preserve the current document,
including its durable undo history. It must never restore the data that existed
when that program was last used.

For host integration, `task_document_capture` observes the app name, canonical
current state and undo state. After a confined candidate has demonstrated that
it understands those exact bytes, use the checked resident activation or
rollback API with a trusted host guard. The guard binds the candidate's complete
identity and calls `task_document_check_current` inside the resident switch's
write transaction. An intervening edit refuses the switch and asks for a fresh
preview. The transaction contains no candidate execution or worker wait, so
slow preview work happens before it and does not hold the data lock.

These APIs supply atomic admission, not compatibility or execution permission.
A schema number, a checkpoint, or a matching digest does not prove a candidate
understands the data. Confined preview execution and its user-facing acceptance
flow are still pending. The existing unguarded resident APIs remain for stateless
consumers; data-bearing apps must use the checked path. Real Mac desktop
acceptance is also still open.
