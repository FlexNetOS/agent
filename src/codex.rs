//! Codex environment parity helpers for the FlexNetOS meta workspace.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

const WORKSPACE_ACK_TERMS: &[&str] = &[
    "meta git status",
    "meta project list",
    "cross-repo",
    "workspace state",
    "workspace-level",
    "multi-repo",
];

const STOP_REASON: &str = "Meta workspace has pending repo changes. Run `meta git status`, confirm the touched repos and dependent repos, then include the cross-repo workspace scope in the handoff before stopping.";

#[derive(Debug, Serialize)]
struct Inventory {
    root: String,
    layers: Vec<Layer>,
    hub_counts: HubCounts,
    missing: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Layer {
    name: &'static str,
    status: &'static str,
    evidence: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HubCounts {
    commands: usize,
    hooks: usize,
    plugins: usize,
    tools: usize,
    meta_plugins: usize,
}

#[derive(Debug, Default, Deserialize)]
struct StopInput {
    cwd: Option<String>,
    #[serde(rename = "lastAssistantMessage")]
    last_assistant_message_camel: Option<String>,
    #[serde(rename = "last_assistant_message")]
    last_assistant_message_snake: Option<String>,
}

#[derive(Debug, Serialize)]
struct StopOutput<'a> {
    decision: &'a str,
    reason: &'a str,
}

pub fn handle_inventory(json: bool) -> Result<()> {
    let root = std::env::current_dir().context("read current directory")?;
    let inventory = collect_inventory(&root);

    if json {
        println!("{}", serde_json::to_string_pretty(&inventory)?);
        return Ok(());
    }

    println!("Codex seven-layer environment: {}", inventory.root);
    for layer in &inventory.layers {
        println!("- {}: {}", layer.name, layer.status);
        for evidence in &layer.evidence {
            println!("  - {evidence}");
        }
    }
    println!(
        "Hub counts: commands={}, hooks={}, plugins={}, tools={}, meta_plugins={}",
        inventory.hub_counts.commands,
        inventory.hub_counts.hooks,
        inventory.hub_counts.plugins,
        inventory.hub_counts.tools,
        inventory.hub_counts.meta_plugins
    );
    if !inventory.missing.is_empty() {
        println!("Missing:");
        for item in &inventory.missing {
            println!("- {item}");
        }
    }

    Ok(())
}

pub fn handle_stop() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input = parse_stop_input(&input);
    let cwd = input.cwd.as_deref().unwrap_or(".");
    let last_message = input.last_assistant_message();

    let status = workspace_status(cwd);
    if should_block_stop(&status, last_message) {
        let output = StopOutput {
            decision: "block",
            reason: STOP_REASON,
        };
        println!("{}", serde_json::to_string(&output)?);
    }

    Ok(())
}

impl StopInput {
    fn last_assistant_message(&self) -> &str {
        self.last_assistant_message_camel
            .as_deref()
            .or(self.last_assistant_message_snake.as_deref())
            .unwrap_or("")
    }
}

fn collect_inventory(root: &Path) -> Inventory {
    let mut missing = Vec::new();

    let claude_evidence = existing(
        root,
        &[
            ".claude/settings.json",
            ".claude/agent-guard.toml",
            ".claude/skills",
            ".claude/rules",
            ".claude/agents",
            "claude-plugin/skills",
        ],
    );
    require(&mut missing, &claude_evidence, "Claude source surface");

    let codex_runtime = existing(
        root,
        &[
            ".codex/config.toml",
            ".codex/hooks.json",
            ".codex/policies/strict-upgrade.md",
            ".codex/rules/strict-upgrade.md",
        ],
    );
    require(&mut missing, &codex_runtime, "Codex config/hooks");

    let codex_skills = existing(root, &[".agents/skills"]);
    require(&mut missing, &codex_skills, "Codex repo skills");

    let codex_plugins = existing(
        root,
        &[
            ".agents/plugins/marketplace.json",
            ".agents/plugins/plugins/meta-codex-rust-env/.codex-plugin/plugin.json",
        ],
    );
    require(
        &mut missing,
        &codex_plugins,
        "Codex repo plugin marketplace",
    );

    let meta_cli = existing(
        root,
        &[
            "meta_cli",
            "meta_git_cli",
            "meta_project_cli",
            "meta_rust_cli",
            "meta_mcp",
            "meta-plugins/plugins",
        ],
    );
    require(&mut missing, &meta_cli, "meta CLI/plugin repos");

    let hubs = existing(
        root,
        &[
            "commands/registry.json",
            "hooks_hub/registry.json",
            "plugin_hub/registry.json",
            "tool_hub/registry.json",
        ],
    );
    require(&mut missing, &hubs, "workspace hub registries");

    let rust_tools = existing(root, &["agent/src/main.rs", "agent/src/codex.rs"]);
    require(&mut missing, &rust_tools, "Rust Codex environment tooling");

    let hub_counts = HubCounts {
        commands: json_array_len(&root.join("commands/registry.json"), "commands"),
        hooks: json_array_len(&root.join("hooks_hub/registry.json"), "hooks"),
        plugins: json_array_len(&root.join("plugin_hub/registry.json"), "plugins"),
        tools: json_array_len(&root.join("tool_hub/registry.json"), "tools"),
        meta_plugins: dir_entry_count(&root.join("meta-plugins/plugins")),
    };

    Inventory {
        root: root.display().to_string(),
        layers: vec![
            layer("1. Claude Source Surface", &claude_evidence),
            layer("2. Codex Runtime Config And Hooks", &codex_runtime),
            layer("3. Codex Repo Skills", &codex_skills),
            layer("4. Codex Plugin Marketplace", &codex_plugins),
            layer("5. Meta CLI And Plugin Commands", &meta_cli),
            layer("6. Slash/Hook/Plugin/Tool Hubs", &hubs),
            layer("7. Rust Guard/Inventory/Stop Tools", &rust_tools),
        ],
        hub_counts,
        missing,
    }
}

fn layer(name: &'static str, evidence: &[String]) -> Layer {
    Layer {
        name,
        status: if evidence.is_empty() {
            "missing"
        } else {
            "present"
        },
        evidence: evidence.to_vec(),
    }
}

fn existing(root: &Path, rels: &[&str]) -> Vec<String> {
    rels.iter()
        .filter(|rel| root.join(rel).exists())
        .map(|rel| (*rel).to_string())
        .collect()
}

fn require(missing: &mut Vec<String>, evidence: &[String], name: &str) {
    if evidence.is_empty() {
        missing.push(name.to_string());
    }
}

fn json_array_len(path: &Path, key: &str) -> usize {
    let Ok(contents) = fs::read_to_string(path) else {
        return 0;
    };
    let Ok(value) = serde_json::from_str::<Value>(&contents) else {
        return 0;
    };
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn dir_entry_count(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries.filter_map(Result::ok).count()
}

fn parse_stop_input(input: &str) -> StopInput {
    serde_json::from_str(input.trim()).unwrap_or_default()
}

fn workspace_status(cwd: &str) -> String {
    if let Ok(status) = std::env::var("AGENT_CODEX_META_STATUS") {
        return status;
    }

    let output = Command::new("meta")
        .args(["git", "status", "--json"])
        .current_dir(cwd)
        .output();

    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout).into(),
        Ok(output) => String::from_utf8_lossy(&output.stderr).into(),
        Err(_) => String::new(),
    }
}

fn should_block_stop(status: &str, last_assistant_message: &str) -> bool {
    status_has_pending_changes(status) && !acknowledges_workspace(last_assistant_message)
}

fn status_has_pending_changes(status: &str) -> bool {
    let normalized = strip_ansi(status);
    normalized.contains("Changes not staged")
        || normalized.contains("Changes to be committed")
        || normalized.contains("Untracked files")
        || normalized.contains("nothing added to commit but untracked files present")
        || normalized.contains("\"stdout\"")
            && (normalized.contains("Changes not staged")
                || normalized.contains("Untracked files")
                || normalized.contains("Changes to be committed"))
}

fn acknowledges_workspace(message: &str) -> bool {
    let lower = message.to_lowercase();
    WORKSPACE_ACK_TERMS
        .iter()
        .any(|term| lower.contains(&term.to_lowercase()))
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_detects_pending_changes() {
        assert!(status_has_pending_changes(
            "Changes not staged for commit:\n\tmodified: Cargo.toml"
        ));
        assert!(status_has_pending_changes(
            "Untracked files:\n\t.codex/hooks.json"
        ));
        assert!(!status_has_pending_changes(
            "nothing to commit, working tree clean"
        ));
    }

    #[test]
    fn stop_blocks_dirty_status_without_workspace_ack() {
        assert!(should_block_stop(
            "Untracked files:\n\t.codex/hooks.json",
            "Implemented the feature."
        ));
    }

    #[test]
    fn stop_allows_dirty_status_with_workspace_ack() {
        assert!(!should_block_stop(
            "Untracked files:\n\t.codex/hooks.json",
            "Ran meta git status and accounted for cross-repo workspace state."
        ));
    }

    #[test]
    fn parses_camel_and_snake_stop_input() {
        let camel = parse_stop_input(r#"{"lastAssistantMessage":"meta git status checked"}"#);
        assert_eq!(camel.last_assistant_message(), "meta git status checked");

        let snake = parse_stop_input(r#"{"last_assistant_message":"cross-repo checked"}"#);
        assert_eq!(snake.last_assistant_message(), "cross-repo checked");
    }
}
