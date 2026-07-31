# Testing an agent-guard rule

Five traps found on 2026-07-31 while verifying a new `paths.*` rule. Each one made
a **working** rule look broken, and two of them nearly caused a correct rule to be
reported as a failure. Check these before concluding a rule does not fire.

## 1. Policy resolution follows the current directory

`GuardConfig::load()` calls `load_from_project()`, which reads
`.claude/agent-guard.toml` **relative to the current directory**, and only then
falls back to the user-level file under `CLAUDE_CONFIG_DIR`.

A repo with no project policy silently falls back. Testing a freshly edited rule
from such a directory loads the **old** policy and reports `allow` for every case.

Always run from the repo whose policy you edited, and print proof that the rule
string is present in the file actually being loaded:

```bash
pwd
grep -c '<rule-id>' .claude/agent-guard.toml
```

## 2. Nushell does not deliver a piped string to an external binary's stdin

This silently sends nothing, so the guard sees empty input and allows everything:

```nu
$payload | ^$bin guard | complete     # WRONG — no stdin delivered
```

Build the hook JSON with `save -f`, then run the binary from bash with a redirect:

```nu
{tool_name: "Write", tool_input: {file_path: $f, content: (open --raw $p)}} | to json | save -f hook.json
```
```bash
"$CARGO_TARGET_DIR/debug/agent" guard < hook.json
```

The bash `printf ... | bin guard` form works correctly.

## 3. `META_DEBUG_GUARD` only instruments the Bash path

The `eprintln!` lives in `evaluate_segment()`, which serves `evaluate_command()` —
the Bash tool path. Write/Edit/NotebookEdit go through
`evaluate_path_law_for_target()`, which prints **nothing**.

Empty stderr does not mean no rule matched. Read `permissionDecisionReason` from
stdout instead.

## 4. Match the message's case in assertions

Rule messages use emphasis capitals. A lowercase `str contains` check reported
`allow` on a real deny. Assert on `"permissionDecision":"deny"`, or copy the
message casing exactly.

## 5. Edit and Write carry different payloads

`evaluate_path_law_for_target` receives `file_path`, `notebook_path`, `content`
and `new_string` joined with newlines. So:

- **Edit** sends only the changed hunk.
- **Write** sends the whole file.

A file can pass as an Edit and be denied as a Write, because unrelated text
elsewhere in it matches some other rule. Test the tool you actually intend to use,
and do not report a full-file Write result as though it applied to an Edit.

## Verify the negative cases too

A rule that cannot fail proves nothing, and a rule that fires on everything is
worse than none. Every rule change needs both directions:

- a real file that **must** be denied,
- a real file that **must** be allowed,
- and, when narrowing an existing pattern, a probe proving the original violation
  is still caught.
