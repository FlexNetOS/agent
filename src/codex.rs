//! Codex environment parity helpers for the FlexNetOS meta workspace.

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const WORKSPACE_ACK_TERMS: &[&str] = &[
    "meta git status",
    "meta project list",
    "agent codex exec",
    "agent codex exec-status",
    ".handoff/codex-exec",
    "artifact log",
    "capped tail",
    "cross-repo",
    "workspace state",
    "workspace-level",
    "multi-repo",
];

const STOP_REASON: &str = "Meta workspace has pending repo changes. Run `meta git status`, confirm the touched repos and dependent repos, then include the cross-repo workspace scope in the handoff before stopping.";

const DEFAULT_EXEC_ARTIFACT_DIR: &str = ".handoff/codex-exec";
const DEFAULT_EXEC_TAIL_LINES: usize = 80;
const MAX_EXEC_TAIL_LINES: usize = 200;

#[derive(Args, Debug, Clone)]
pub struct ExecArgs {
    /// Short label used in the artifact directory name.
    #[arg(long)]
    pub label: Option<String>,

    /// Start the command in the background and return the artifact paths immediately.
    #[arg(long)]
    pub background: bool,

    /// Maximum log lines to print back into chat.
    #[arg(long, default_value_t = DEFAULT_EXEC_TAIL_LINES)]
    pub tail_lines: usize,

    /// Directory for run artifacts. Relative paths are resolved under --cwd/current directory.
    #[arg(long, default_value = DEFAULT_EXEC_ARTIFACT_DIR)]
    pub artifact_dir: PathBuf,

    /// Working directory for the command.
    #[arg(long)]
    pub cwd: Option<PathBuf>,

    /// Command and arguments to run. Use `--` before the command.
    #[arg(required = true, trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ExecStatusArgs {
    /// Run id to inspect. Defaults to the latest run in --artifact-dir.
    #[arg(long)]
    pub run_id: Option<String>,

    /// Maximum log lines to print back into chat.
    #[arg(long, default_value_t = DEFAULT_EXEC_TAIL_LINES)]
    pub tail_lines: usize,

    /// Directory for run artifacts. Relative paths are resolved under --cwd/current directory.
    #[arg(long, default_value = DEFAULT_EXEC_ARTIFACT_DIR)]
    pub artifact_dir: PathBuf,

    /// Directory used to resolve relative --artifact-dir paths.
    #[arg(long)]
    pub cwd: Option<PathBuf>,
}

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

#[derive(Debug, Serialize, Deserialize)]
struct ExecMetadata {
    run_id: String,
    label: String,
    cwd: String,
    command: Vec<String>,
    background: bool,
    pid: Option<u32>,
    log_path: String,
    exit_code_path: String,
    started_at_unix: u64,
}

#[derive(Debug, Serialize)]
struct ExecSummary {
    status: String,
    run_id: String,
    label: String,
    pid: Option<u32>,
    exit_code: Option<i32>,
    log_path: String,
    status_command: String,
    context_policy: &'static str,
    tail_lines: usize,
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

pub fn handle_exec(args: ExecArgs) -> Result<()> {
    let cwd = args
        .cwd
        .unwrap_or(std::env::current_dir().context("read current directory")?);
    let cwd = absolutize(&cwd).with_context(|| format!("resolve cwd {}", cwd.display()))?;
    let artifact_root = resolve_artifact_root(&cwd, &args.artifact_dir);
    let label = sanitize_label(args.label.as_deref().unwrap_or("codex-exec"));
    let run_id = new_run_id(&label)?;
    let run_dir = artifact_root.join(&run_id);
    fs::create_dir_all(&run_dir).with_context(|| format!("create {}", run_dir.display()))?;

    let log_path = run_dir.join("command.log");
    let exit_code_path = run_dir.join("exit-code");
    let script_path = run_dir.join("run.sh");
    let latest_path = artifact_root.join("latest");
    let tail_lines = capped_tail_lines(args.tail_lines);

    let metadata = ExecMetadata {
        run_id: run_id.clone(),
        label: label.clone(),
        cwd: cwd.display().to_string(),
        command: args.command.clone(),
        background: args.background,
        pid: None,
        log_path: log_path.display().to_string(),
        exit_code_path: exit_code_path.display().to_string(),
        started_at_unix: unix_timestamp()?,
    };

    write_metadata(&run_dir, &metadata)?;
    fs::write(&latest_path, &run_id).with_context(|| format!("write {}", latest_path.display()))?;

    if args.background {
        write_background_script(&script_path, &cwd, &args.command, &exit_code_path)?;
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("open {}", log_path.display()))?;
        let err = log
            .try_clone()
            .with_context(|| format!("clone {}", log_path.display()))?;
        let child = Command::new("bash")
            .arg(&script_path)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .with_context(|| format!("spawn background run {}", script_path.display()))?;
        let metadata = ExecMetadata {
            pid: Some(child.id()),
            ..metadata
        };
        write_metadata(&run_dir, &metadata)?;
        print_exec_summary(&metadata, "running", None, tail_lines);
        return Ok(());
    }

    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let err = log
        .try_clone()
        .with_context(|| format!("clone {}", log_path.display()))?;
    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]).current_dir(&cwd);
    let status = command
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .status()
        .with_context(|| format!("spawn {}", args.command.join(" ")))?;
    let code = status.code().unwrap_or(1);
    fs::write(&exit_code_path, format!("{code}\n"))
        .with_context(|| format!("write {}", exit_code_path.display()))?;
    print_exec_summary(&metadata, "finished", Some(code), tail_lines);
    print_capped_tail(&log_path, tail_lines)?;
    if code != 0 {
        anyhow::bail!(
            "command exited with {code}; full log is at {}",
            log_path.display()
        );
    }
    Ok(())
}

pub fn handle_exec_status(args: ExecStatusArgs) -> Result<()> {
    let cwd = args
        .cwd
        .unwrap_or(std::env::current_dir().context("read current directory")?);
    let cwd = absolutize(&cwd).with_context(|| format!("resolve cwd {}", cwd.display()))?;
    let artifact_root = resolve_artifact_root(&cwd, &args.artifact_dir);
    let run_id = match args.run_id {
        Some(run_id) => run_id,
        None => fs::read_to_string(artifact_root.join("latest"))
            .with_context(|| format!("read {}", artifact_root.join("latest").display()))?
            .trim()
            .to_string(),
    };
    let run_dir = artifact_root.join(&run_id);
    let metadata = read_metadata(&run_dir)?;
    let exit_code = read_exit_code(Path::new(&metadata.exit_code_path))?;
    let status = if exit_code.is_some() {
        "finished"
    } else if metadata.pid.is_some_and(pid_alive) {
        "running"
    } else {
        "unknown"
    };
    let tail_lines = capped_tail_lines(args.tail_lines);
    print_exec_summary(&metadata, status, exit_code, tail_lines);
    print_capped_tail(Path::new(&metadata.log_path), tail_lines)?;
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

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn resolve_artifact_root(cwd: &Path, artifact_dir: &Path) -> PathBuf {
    if artifact_dir.is_absolute() {
        artifact_dir.to_path_buf()
    } else {
        cwd.join(artifact_dir)
    }
}

fn capped_tail_lines(requested: usize) -> usize {
    requested.min(MAX_EXEC_TAIL_LINES)
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX_EPOCH")?
        .as_secs())
}

fn new_run_id(label: &str) -> Result<String> {
    Ok(format!(
        "{}-{}-{label}",
        unix_timestamp()?,
        std::process::id()
    ))
}

fn sanitize_label(label: &str) -> String {
    let mut out = String::new();
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() || ch == '.' || ch == '/' {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "codex-exec".to_string()
    } else {
        out.chars().take(48).collect()
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn write_background_script(
    script_path: &Path,
    cwd: &Path,
    command: &[String],
    exit_code_path: &Path,
) -> Result<()> {
    let command = command
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        r#"#!/usr/bin/env bash
set +e
cd {cwd}
{command}
code=$?
printf '%s\n' "$code" > {exit_code}
exit "$code"
"#,
        cwd = shell_quote(&cwd.display().to_string()),
        command = command,
        exit_code = shell_quote(&exit_code_path.display().to_string())
    );
    fs::write(script_path, script).with_context(|| format!("write {}", script_path.display()))?;
    Ok(())
}

fn write_metadata(run_dir: &Path, metadata: &ExecMetadata) -> Result<()> {
    fs::write(
        run_dir.join("metadata.json"),
        serde_json::to_string_pretty(metadata)?,
    )
    .with_context(|| format!("write {}", run_dir.join("metadata.json").display()))
}

fn read_metadata(run_dir: &Path) -> Result<ExecMetadata> {
    let path = run_dir.join("metadata.json");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn read_exit_code(path: &Path) -> Result<Option<i32>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text.trim().parse::<i32>().ok())
}

fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

fn print_exec_summary(
    metadata: &ExecMetadata,
    status: &str,
    exit_code: Option<i32>,
    tail_lines: usize,
) {
    let summary = ExecSummary {
        status: status.to_string(),
        run_id: metadata.run_id.clone(),
        label: metadata.label.clone(),
        pid: metadata.pid,
        exit_code,
        log_path: metadata.log_path.clone(),
        status_command: format!("agent codex exec-status --run-id {}", metadata.run_id),
        context_policy:
            "Do not paste full logs into chat; inspect this artifact or request a capped tail.",
        tail_lines,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).expect("serialize exec summary")
    );
}

fn print_capped_tail(path: &Path, tail_lines: usize) -> Result<()> {
    if tail_lines == 0 || !path.exists() {
        return Ok(());
    }
    let tail = tail_file(path, tail_lines)?;
    if tail.is_empty() {
        return Ok(());
    }
    println!(
        "--- capped tail: {} (last {tail_lines} lines) ---",
        path.display()
    );
    for line in tail {
        println!("{line}");
    }
    Ok(())
}

fn tail_file(path: &Path, tail_lines: usize) -> Result<Vec<String>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut tail = VecDeque::with_capacity(tail_lines);
    for line in reader.lines() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        if tail.len() == tail_lines {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    Ok(tail.into_iter().collect())
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

    #[test]
    fn sanitizes_exec_labels_for_artifact_paths() {
        assert_eq!(sanitize_label("Envctl Check/Push"), "envctl-check-push");
        assert_eq!(sanitize_label("!!!"), "codex-exec");
    }

    #[test]
    fn shell_quotes_single_quotes() {
        assert_eq!(shell_quote("it's ok"), "'it'\"'\"'s ok'");
    }

    #[test]
    fn tail_file_returns_only_requested_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("command.log");
        fs::write(&log, "one\ntwo\nthree\nfour\n").unwrap();

        assert_eq!(
            tail_file(&log, 2).unwrap(),
            vec!["three".to_string(), "four".to_string()]
        );
    }

    #[test]
    fn stop_ack_accepts_artifact_based_capped_execution() {
        assert!(!should_block_stop(
            "Untracked files:\n\t.codex/hooks.json",
            "Wrote meta git status scope to .handoff/codex-exec and surfaced a capped tail."
        ));
    }
}
