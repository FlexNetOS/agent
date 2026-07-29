#!/usr/bin/env bats

# Integration tests for `agent guard`

setup() {
    local manifest="$BATS_TEST_DIRNAME/../Cargo.toml"

    # Ask cargo where it builds instead of assuming ./target. cargo honours
    # CARGO_TARGET_DIR and .cargo/config.toml build.target-dir, and this
    # workspace sets CARGO_TARGET_DIR outside the repo, so a hardcoded
    # ../target/debug/agent never exists. The old setup() then compounded it:
    # it ran `cargo build` on the miss but re-checked the same wrong path, so
    # the build succeeded and every test still failed with
    #   /bin/sh: 1: ./target/debug/agent: not found
    local target_dir
    target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$manifest" 2>/dev/null \
        | jq -r '.target_directory // empty' 2>/dev/null)"
    [ -n "$target_dir" ] || target_dir="${CARGO_TARGET_DIR:-$BATS_TEST_DIRNAME/../target}"

    AGENT_BIN="$target_dir/debug/agent"

    if [ ! -x "$AGENT_BIN" ]; then
        cargo build --manifest-path "$manifest" --quiet
    fi

    # Fail loudly with the resolved path rather than letting each test report a
    # bare "not found" from the shell.
    if [ ! -x "$AGENT_BIN" ]; then
        echo "agent binary not found after build: $AGENT_BIN" >&2
        return 1
    fi
}

# ============ Allow (safe commands) ============

@test "guard allows git status" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git status"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard allows cargo build" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"cargo build"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard allows normal git push" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push origin main"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard denies git push --force-with-lease to long-lived branch" {
    # ARCHBP-031 consolidated policy: long-lived branches are upgrade-only history.
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push --force-with-lease origin main"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard asks on git push --force-with-lease to feature branch" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push --force-with-lease origin task/foo"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *'"permissionDecision":"ask"'* ]]
}

@test "guard denies --dangerously-skip-permissions" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"claude --dangerously-skip-permissions"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies nested claude session" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rtk claude -p hi"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard allows claude --version" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"claude --version"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard denies git filter-branch (history rewrite)" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git filter-branch --all"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard allows git reset --soft" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git reset --soft HEAD~1"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard allows rm -rf on specific directory" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rm -rf node_modules"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard allows git checkout branch" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git checkout main"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard allows safe compound command" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git add . && git commit -m msg && git push"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ============ Deny (destructive commands) ============

@test "guard denies git push --force" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push --force origin main"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"permissionDecision"* ]]
    [[ "$output" == *"deny"* ]]
    [[ "$output" == *"--force-with-lease"* ]]
}

@test "guard denies git push -f" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push -f origin main"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies git reset --hard" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git reset --hard"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
    [[ "$output" == *"snapshot"* ]]
}

@test "guard denies git clean -fd" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git clean -fd"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies git clean -fdx" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git clean -fdx"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies git checkout ." {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git checkout ."}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies git checkout -- ." {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git checkout -- ."}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies rm -rf ." {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rm -rf ."}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies rm -rf /" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rm -rf /"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies rm -rf .meta" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rm -rf .meta"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

# ============ Compound commands ============

@test "guard denies destructive in compound command" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git add . && git push --force"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies second segment after semicolon" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"echo hi; git reset --hard"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

# ============ Graceful degradation ============

@test "guard handles empty stdin" {
    run bash -c 'echo "" | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard handles malformed JSON" {
    run bash -c 'echo "not json" | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard handles missing tool_input" {
    run bash -c 'echo '"'"'{"other":"field"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard handles missing command field" {
    run bash -c 'echo '"'"'{"tool_input":{}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ============ JSON output structure ============

@test "guard deny output is valid JSON with correct structure" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push --force"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    # Validate JSON and check structure
    echo "$output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert 'hookSpecificOutput' in data
hso = data['hookSpecificOutput']
assert hso['hookEventName'] == 'PreToolUse'
assert hso['permissionDecision'] == 'deny'
assert 'permissionDecisionReason' in hso
assert len(hso['permissionDecisionReason']) > 0
"
}

# ============ Pipe delimiter (bug fix) ============

@test "guard denies force push piped to tee" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git push --force origin main | tee output.log"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies reset hard piped" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git reset --hard | cat"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

# ============ Separate flags (bug fix) ============

@test "guard denies git clean -f -d (separate flags)" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git clean -f -d"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies git clean -d -f (separate flags reversed)" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git clean -d -f"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard allows git clean -f only (no -d)" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"git clean -f"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ============ rm -rf edge cases ============

@test "guard denies rm -rf .meta.yaml" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rm -rf .meta.yaml"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

@test "guard denies rm -rf with dangerous target among safe ones" {
    run bash -c 'echo '"'"'{"tool_input":{"command":"rm -rf node_modules .meta target"}}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [[ "$output" == *"deny"* ]]
}

# ============ Full hook input format ============

@test "guard handles full hook input with extra fields" {
    run bash -c 'echo '"'"'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status","description":"check status"},"session_id":"abc123","cwd":"/tmp"}'"'"' | '"$AGENT_BIN"' guard'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}
