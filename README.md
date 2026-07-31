# agent

Claude Code agent toolkit: guard, score, and more.

A standalone CLI for Claude Code agent integration. Provides deterministic command guards, session scoring, and other agent utilities.

## Installation

```bash
cargo install --git https://github.com/gitkb/agent
```

Or build from source:

```bash
cargo build --release
```

## Commands

### `agent guard`

Evaluate shell commands, file targets, and newly written source for policy
violations. Designed for Claude and Codex `PreToolUse` hooks; unknown tools are
silent no-ops.

```bash
# Test directly
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"git push --force"}}' | rtk agent guard
# Output: JSON with permissionDecision: "deny" and reason

printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"rtk git status"}}' | rtk agent guard
# Output: (silent = allowed)
```

Claude fires a hook without a matcher for every occurrence of that event:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "rtk agent guard",
            "timeout": 5,
            "type": "command"
          }
        ]
      }
    ]
  }
}
```

Codex should use a `"*"` PreToolUse matcher for this guard. Both routes deliver
all supported local tool events; the guard itself recognizes shell calls plus
direct and namespaced filesystem operations and silently ignores unrelated
tools. Codex supplies its `apply_patch` payload in `tool_input.command`.

**Blocked patterns** (configurable via `.claude/agent-guard.toml`):

| Pattern | What it blocks | Safe alternative |
|---------|----------------|------------------|
| `git push --force` | Force push | `rtk git pull --rebase`, then `rtk git push` |
| `git reset --hard` | Hard reset | `rtk git stash push --include-untracked` |
| `git clean -fd` | Clean force | `rtk git clean -nd` (dry run) |
| `git checkout .` | Checkout all | `rtk git diff -- <path>` before a targeted edit |
| `git branch -D` | Force delete branch | `rtk git branch -d <branch>` |
| `git stash drop/clear` | Drop stashes | `rtk git stash list` first |
| `rm -rf .` / `*` / `.meta` | Dangerous rm | `rtk rm -rf <specific-path>` |

### `agent score`

Score Claude Code sessions for agent effectiveness.

```bash
# Score most recent session
agent score

# Score specific session
agent score --session abc123

# Score last 5 sessions
agent score --recent 5

# JSON output
agent score --json
```

**Metrics:**
- Meta-command ratio (using `meta git` vs bare `git`)
- Workspace discovery (running `meta context` early)
- Snapshot safety (snapshots before destructive ops)
- Cross-repo awareness (status checks before commits)
- Guard effectiveness (blocked vs allowed destructive commands)

## Configuration

### Guard patterns

Create `.claude/agent-guard.toml` in your project to customize patterns:

```toml
schema_version = "1.0"

[[patterns]]
id = "custom.my_pattern"
priority = 100
enabled = true
matcher = { type = "regex", pattern = 'dangerous-command' }
message = "This command is blocked because..."
```

**Pattern options:**
- `id`: Unique identifier (namespaced recommended)
- `priority`: Higher = checked first (default: 100)
- `enabled`: Toggle pattern on/off
- `matcher`: Currently only `regex` type supported
- `validator`: Optional additional checks (`not_contains`, `flags_present`, `args_match_any`, `all_of`, `any_of`, `not`)
- `message`: Shown to Claude when command is blocked

## Development

```bash
# Run tests
cargo test

# Run integration tests (requires bats)
bats tests/

# Build
cargo build
```

## License

MIT
