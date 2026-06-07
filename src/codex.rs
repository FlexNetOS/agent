//! Codex environment parity helpers for the FlexNetOS meta workspace.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
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
    missing: Vec<String>,
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

pub fn handle_install_prompts() -> Result<()> {
    let root = std::env::current_dir().context("read current directory")?;
    let source = root.join(".codex/prompts");
    let dest = dirs::home_dir()
        .context("resolve home directory")?
        .join(".codex/prompts");

    let installed = install_prompt_templates(&source, &dest)?;
    for path in installed {
        println!("{}", path.display());
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

    let guidance = require_paths(
        &mut missing,
        root,
        "instructions/guidance/memory",
        &["AGENTS.md", "CLAUDE.md", ".agent/skills-catalog.md"],
    );

    let runtime = require_paths(
        &mut missing,
        root,
        "runtime config and custom agents",
        &[".codex/config.toml", ".codex/agents/meta-worker.toml"],
    );

    let mut slash_prompts = require_paths(
        &mut missing,
        root,
        "slash commands and prompt templates",
        &[
            ".codex/prompts/meta-status.md",
            ".codex/prompts/meta-upgrade.md",
            ".codex/prompts/meta-worker.md",
        ],
    );
    slash_prompts.extend(installed_prompt_evidence(&[
        "meta-status.md",
        "meta-upgrade.md",
        "meta-worker.md",
    ]));

    let codex_skills = require_paths(
        &mut missing,
        root,
        "repo skills",
        &[
            ".agents/skills/gitkb/SKILL.md",
            ".agents/skills/meta-exec/SKILL.md",
            ".agents/skills/meta-git/SKILL.md",
            ".agents/skills/meta-plugins/SKILL.md",
            ".agents/skills/meta-safety/SKILL.md",
            ".agents/skills/meta-slash-commands/SKILL.md",
            ".agents/skills/meta-workspace/SKILL.md",
            ".agents/skills/meta-worktree/SKILL.md",
        ],
    );

    let codex_plugins = require_paths(
        &mut missing,
        root,
        "repo plugin marketplace",
        &[
            ".agents/plugins/marketplace.json",
            ".agents/plugins/plugins/meta-codex-rust-env/.codex-plugin/plugin.json",
            ".agents/plugins/plugins/meta-codex-rust-env/skills/meta-codex-rust-env/SKILL.md",
            ".agents/plugins/plugins/meta-codex-rust-env/hooks/hooks.json",
        ],
    );

    let hooks_rules = require_paths(
        &mut missing,
        root,
        "hooks/rules/permissions",
        &[
            ".codex/hooks.json",
            ".codex/rules/strict-upgrade.rules",
            ".codex/rules/strict-upgrade.md",
            ".codex/policies/strict-upgrade.md",
        ],
    );

    let tools_mcp = require_paths(
        &mut missing,
        root,
        "tools/mcp/subagents/automation",
        &[
            "meta_mcp",
            "agent/src/main.rs",
            "agent/src/codex.rs",
            ".codex/config.toml",
            ".codex/agents/meta-worker.toml",
        ],
    );

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
            layer("1. Instructions, Guidance, And Memory", &guidance),
            layer("2. Runtime Config And Custom Agents", &runtime),
            layer("3. Slash Commands And Prompt Templates", &slash_prompts),
            layer("4. Repo Skills", &codex_skills),
            layer("5. Plugins And Marketplace", &codex_plugins),
            layer("6. Hooks, Rules, And Permissions", &hooks_rules),
            layer("7. Tools, MCP, Subagents, And Automation", &tools_mcp),
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
        missing: Vec::new(),
    }
}

fn require_paths(
    missing: &mut Vec<String>,
    root: &Path,
    layer_name: &str,
    rels: &[&str],
) -> Vec<String> {
    let mut evidence = Vec::new();
    for rel in rels {
        if root.join(rel).exists() {
            evidence.push((*rel).to_string());
        } else {
            missing.push(format!("{layer_name}: {rel}"));
        }
    }
    evidence
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

fn installed_prompt_evidence(names: &[&str]) -> Vec<String> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    names
        .iter()
        .filter_map(|name| {
            let path = home.join(".codex/prompts").join(name);
            path.exists().then(|| format!("~/.codex/prompts/{name}"))
        })
        .collect()
}

fn install_prompt_templates(source: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    let mut installed = Vec::new();

    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }

        let target = dest.join(entry.file_name());
        fs::copy(&path, &target)
            .with_context(|| format!("copy {} to {}", path.display(), target.display()))?;
        installed.push(target);
    }

    installed.sort();
    Ok(installed)
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

    #[test]
    fn require_paths_reports_each_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("present.txt"), "ok").unwrap();
        let mut missing = Vec::new();

        let evidence = require_paths(
            &mut missing,
            dir.path(),
            "test layer",
            &["present.txt", "missing.txt"],
        );

        assert_eq!(evidence, vec!["present.txt"]);
        assert_eq!(missing, vec!["test layer: missing.txt"]);
    }

    #[test]
    fn install_prompt_templates_copies_markdown_only() {
        let source = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        fs::write(source.path().join("meta-status.md"), "prompt").unwrap();
        fs::write(source.path().join("ignore.txt"), "no").unwrap();

        let installed = install_prompt_templates(source.path(), dest.path()).unwrap();

        assert_eq!(installed, vec![dest.path().join("meta-status.md")]);
        assert_eq!(
            fs::read_to_string(dest.path().join("meta-status.md")).unwrap(),
            "prompt"
        );
        assert!(!dest.path().join("ignore.txt").exists());
    }
}
