//! Agent effectiveness scoring based on Claude Code session transcripts.
//!
//! Analyzes transcript files from `~/.claude/projects/{PROJECT_HASH}/` and computes
//! metrics on how well agents use meta tools: meta-command ratio, workspace discovery,
//! snapshot safety, cross-repo awareness, and guard effectiveness.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::path::{Path, PathBuf};

// ── Public API ──────────────────────────────────────────

/// Entry point for `meta agent score`.
pub fn handle_score(
    session_id: Option<String>,
    recent: Option<usize>,
    json: bool,
    verbose: bool,
) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let finder = SessionFinder::new(&cwd)?;

    let sessions = if let Some(id) = session_id {
        vec![finder.find_session(&id)?]
    } else {
        finder.recent_sessions(recent.unwrap_or(1))?
    };

    if verbose {
        eprintln!("Analyzing {} session(s)...", sessions.len());
    }

    let mut scores = Vec::new();
    for session_path in &sessions {
        if verbose {
            eprintln!("Parsing: {}", session_path.display());
        }
        let metrics = parse_and_score(session_path)?;
        let score = compute_score(metrics);
        scores.push(score);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&scores)?);
    } else {
        for (i, score) in scores.iter().enumerate() {
            print!("{}", format_markdown(score));
            if i < scores.len() - 1 {
                println!("\n---\n");
            }
        }
    }

    Ok(())
}

// ── Session Discovery ───────────────────────────────────

/// Finds Claude Code session transcript files for a project.
pub struct SessionFinder {
    project_dir: PathBuf,
}

impl SessionFinder {
    /// Create a finder for the given project path.
    ///
    /// Project hash is computed as the absolute path with `/` replaced by `-`.
    pub fn new(project_path: &Path) -> Result<Self> {
        let abs_path = project_path
            .canonicalize()
            .context("Failed to resolve project path")?;
        let hash = Self::compute_project_hash(&abs_path);

        let claude_dir = dirs::home_dir()
            .context("Could not determine home directory")?
            .join(".claude")
            .join("projects")
            .join(&hash);

        if !claude_dir.exists() {
            anyhow::bail!(
                "No Claude Code sessions found for project: {}\nExpected directory: {}",
                project_path.display(),
                claude_dir.display()
            );
        }

        Ok(Self {
            project_dir: claude_dir,
        })
    }

    /// Compute project hash: replace `/` with `-` in absolute path.
    fn compute_project_hash(path: &Path) -> String {
        path.to_string_lossy().replace('/', "-")
    }

    /// Find the N most recent session transcripts (sorted by modified time).
    pub fn recent_sessions(&self, n: usize) -> Result<Vec<PathBuf>> {
        let mut files: Vec<(PathBuf, std::time::SystemTime)> =
            std::fs::read_dir(&self.project_dir)?
                .filter_map(|entry| entry.ok())
                .filter(|e| {
                    e.path().extension().map(|s| s == "jsonl").unwrap_or(false)
                        && !e
                            .path()
                            .file_name()
                            .map(|n| n.to_string_lossy().starts_with("agent-"))
                            .unwrap_or(false)
                })
                .filter_map(|e| {
                    let path = e.path();
                    let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
                    Some((path, modified))
                })
                .collect();

        files.sort_by(|a, b| b.1.cmp(&a.1)); // Newest first
        Ok(files.into_iter().take(n).map(|(p, _)| p).collect())
    }

    /// Find a specific session by ID.
    pub fn find_session(&self, session_id: &str) -> Result<PathBuf> {
        let path = self.project_dir.join(format!("{session_id}.jsonl"));
        if path.exists() {
            Ok(path)
        } else {
            anyhow::bail!("Session not found: {session_id}")
        }
    }
}

// ── JSONL Transcript Parsing ────────────────────────────

/// A single line from a Claude Code JSONL transcript.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum TranscriptEntry {
    User {
        _uuid: String,
        #[serde(rename = "sessionId")]
        _session_id: String,
        _timestamp: String,
        _message: Message,
    },
    Assistant {
        _uuid: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        timestamp: String,
        message: Message,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
struct Message {
    _role: String,
    content: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ContentBlock {
    Text {
        _text: String,
    },
    ToolUse {
        _id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        _tool_use_id: String,
        _content: serde_json::Value,
        _is_error: Option<bool>,
    },
    #[serde(other)]
    Other,
}

// ── Metrics Computation ─────────────────────────────────

/// Metrics for a single session.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SessionMetrics {
    pub session_id: String,
    pub tool_calls: usize,
    pub bash_commands: Vec<BashCommand>,

    // Metric 1: Meta-command ratio
    pub total_git_commands: usize,
    pub meta_git_commands: usize,

    // Metric 2: Workspace discovery
    pub workspace_discovery_rank: Option<usize>,

    // Metric 3: Snapshot safety
    pub destructive_ops_detected: usize,
    pub snapshots_before_destructive: usize,

    // Metric 4: Cross-repo awareness
    pub commits_attempted: usize,
    pub meta_status_before_commit: Vec<usize>,

    // Metric 5: Guard effectiveness (placeholder - requires hook logs)
    pub destructive_blocked: usize,
    pub destructive_allowed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BashCommand {
    pub rank: usize,
    pub command: String,
    pub is_git: bool,
    pub is_meta_git: bool,
    pub is_destructive: bool,
    pub timestamp: String,
}

/// Parse a transcript file and compute metrics in a single streaming pass.
pub fn parse_and_score(transcript_path: &Path) -> Result<SessionMetrics> {
    let file = std::fs::File::open(transcript_path)?;
    let reader = std::io::BufReader::new(file);

    let mut metrics = SessionMetrics::default();
    let mut call_rank = 0;
    let mut last_snapshot_rank: Option<usize> = None;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: TranscriptEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue, // Skip malformed lines gracefully
        };

        if let TranscriptEntry::Assistant {
            message,
            session_id,
            timestamp,
            ..
        } = entry
        {
            metrics.session_id = session_id;

            // Parse content as array of ContentBlock
            if let Ok(content_array) =
                serde_json::from_value::<Vec<ContentBlock>>(message.content.clone())
            {
                for content in content_array {
                    if let ContentBlock::ToolUse { name, input, .. } = content {
                        if name == "Bash" {
                            call_rank += 1;
                            metrics.tool_calls += 1;

                            if let Some(command) = input.get("command").and_then(|v| v.as_str()) {
                                process_bash_command(
                                    command,
                                    call_rank,
                                    timestamp.clone(),
                                    &mut metrics,
                                    &mut last_snapshot_rank,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(metrics)
}

fn process_bash_command(
    command: &str,
    rank: usize,
    timestamp: String,
    metrics: &mut SessionMetrics,
    last_snapshot_rank: &mut Option<usize>,
) {
    let is_git = command.contains("git");
    let is_meta_git = command.starts_with("meta git") || command.contains(" meta git ");
    let is_destructive = is_destructive_command(command);

    // Metric 1: Meta-command ratio
    if is_git {
        metrics.total_git_commands += 1;
        if is_meta_git {
            metrics.meta_git_commands += 1;
        }
    }

    // Metric 2: Workspace discovery (first occurrence in session)
    if (command.contains("meta context") || command.contains("meta project list"))
        && metrics.workspace_discovery_rank.is_none()
    {
        metrics.workspace_discovery_rank = Some(rank);
    }

    // Metric 3: Snapshot safety
    if command.contains("meta git snapshot create") {
        *last_snapshot_rank = Some(rank);
    }

    if is_destructive {
        metrics.destructive_ops_detected += 1;
        // Check if there's a recent snapshot protecting this op
        if let Some(snapshot_rank) = last_snapshot_rank {
            if *snapshot_rank < rank && (rank - *snapshot_rank) <= 5 {
                metrics.snapshots_before_destructive += 1;
            }
        }
    }

    // Metric 4: Cross-repo awareness
    if command.contains("meta git status") || command.contains("meta git diff") {
        metrics.meta_status_before_commit.push(rank);
    }

    if command.contains("git commit") {
        metrics.commits_attempted += 1;
    }

    // Metric 5: Guard effectiveness (placeholder - requires hook log parsing)
    // This would need to parse hook denial messages from transcript, deferred for now

    metrics.bash_commands.push(BashCommand {
        rank,
        command: command.to_string(),
        is_git,
        is_meta_git,
        is_destructive,
        timestamp,
    });
}

fn is_destructive_command(cmd: &str) -> bool {
    // Reuse patterns from agent_guard.rs
    cmd.contains("git push --force")
        || cmd.contains("git push -f")
        || cmd.contains("git reset --hard")
        || cmd.contains("git clean -fd")
        || cmd.contains("git clean -f -d")
        || cmd.contains("git checkout .")
        || cmd.contains("rm -rf")
}

// ── Scoring ─────────────────────────────────────────────

/// Computed score for a session with grading.
#[derive(Debug, Clone, Serialize)]
pub struct SessionScore {
    pub session_id: String,
    pub metrics: SessionMetrics,

    pub meta_command_ratio: f64,
    pub meta_command_grade: Grade,

    pub workspace_discovery_score: f64,
    pub workspace_discovery_grade: Grade,

    pub snapshot_safety_score: f64,
    pub snapshot_safety_grade: Grade,

    pub cross_repo_awareness_score: f64,
    pub cross_repo_awareness_grade: Grade,

    pub guard_effectiveness_score: f64,
    pub guard_effectiveness_grade: Grade,

    pub overall_grade: Grade,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    fn from_score(score: f64) -> Self {
        if score >= 0.90 {
            Grade::A
        } else if score >= 0.80 {
            Grade::B
        } else if score >= 0.70 {
            Grade::C
        } else if score >= 0.60 {
            Grade::D
        } else {
            Grade::F
        }
    }

    fn display(&self) -> &'static str {
        match self {
            Grade::A => "A ✓",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F ✗",
        }
    }
}

pub fn compute_score(metrics: SessionMetrics) -> SessionScore {
    // Metric 1: Meta-command ratio (target: > 80%)
    let meta_ratio = if metrics.total_git_commands > 0 {
        metrics.meta_git_commands as f64 / metrics.total_git_commands as f64
    } else {
        1.0 // No git commands = perfect score
    };
    let meta_grade = Grade::from_score(meta_ratio);

    // Metric 2: Workspace discovery (target: 100%, in first 3 calls)
    let discovery_score = match metrics.workspace_discovery_rank {
        Some(rank) if rank <= 3 => 1.0,
        Some(_) => 0.5,
        None => 0.0,
    };
    let discovery_grade = Grade::from_score(discovery_score);

    // Metric 3: Snapshot safety (target: 100%)
    let snapshot_score = if metrics.destructive_ops_detected > 0 {
        metrics.snapshots_before_destructive as f64 / metrics.destructive_ops_detected as f64
    } else {
        1.0 // No destructive ops = perfect
    };
    let snapshot_grade = Grade::from_score(snapshot_score);

    // Metric 4: Cross-repo awareness (target: > 90%)
    let awareness_score = if metrics.commits_attempted > 0 {
        let commit_ranks: Vec<usize> = metrics
            .bash_commands
            .iter()
            .filter(|c| c.command.contains("git commit"))
            .map(|c| c.rank)
            .collect();

        let protected_count = commit_ranks
            .iter()
            .filter(|&&commit_rank| {
                metrics
                    .meta_status_before_commit
                    .iter()
                    .any(|&status_rank| {
                        status_rank < commit_rank && (commit_rank - status_rank) <= 10
                    })
            })
            .count();

        protected_count as f64 / metrics.commits_attempted as f64
    } else {
        1.0 // No commits = perfect
    };
    let awareness_grade = Grade::from_score(awareness_score);

    // Metric 5: Guard effectiveness (placeholder - requires hook logs)
    let guard_total = metrics.destructive_blocked + metrics.destructive_allowed;
    let guard_score = if guard_total > 0 {
        metrics.destructive_blocked as f64 / guard_total as f64
    } else {
        1.0 // No destructive attempts = perfect
    };
    let guard_grade = Grade::from_score(guard_score);

    // Overall grade: weighted average
    let overall = (meta_ratio * 0.25)
        + (discovery_score * 0.20)
        + (snapshot_score * 0.25)
        + (awareness_score * 0.20)
        + (guard_score * 0.10);
    let overall_grade = Grade::from_score(overall);

    // Generate suggestions
    let suggestions = generate_suggestions(
        &metrics,
        meta_ratio,
        discovery_score,
        snapshot_score,
        awareness_score,
    );

    SessionScore {
        session_id: metrics.session_id.clone(),
        metrics,
        meta_command_ratio: meta_ratio,
        meta_command_grade: meta_grade,
        workspace_discovery_score: discovery_score,
        workspace_discovery_grade: discovery_grade,
        snapshot_safety_score: snapshot_score,
        snapshot_safety_grade: snapshot_grade,
        cross_repo_awareness_score: awareness_score,
        cross_repo_awareness_grade: awareness_grade,
        guard_effectiveness_score: guard_score,
        guard_effectiveness_grade: guard_grade,
        overall_grade,
        suggestions,
    }
}

fn generate_suggestions(
    metrics: &SessionMetrics,
    meta_ratio: f64,
    discovery_score: f64,
    snapshot_score: f64,
    awareness_score: f64,
) -> Vec<String> {
    let mut suggestions = Vec::new();

    if meta_ratio < 0.80 {
        let bare_count = metrics.total_git_commands - metrics.meta_git_commands;
        suggestions.push(format!(
            "Low meta-command usage ({:.0}%). Found {bare_count} bare git commands. Use `meta git` for cross-repo operations.",
            meta_ratio * 100.0
        ));
    }

    if discovery_score < 1.0 {
        match metrics.workspace_discovery_rank {
            None => {
                suggestions.push(
                    "No workspace discovery detected. Run `meta context` early to understand repo structure.".to_string()
                );
            }
            Some(rank) => {
                suggestions.push(format!(
                    "Workspace discovery occurred late (call #{rank}). Run `meta context` in first 3 tool calls."
                ));
            }
        }
    }

    if snapshot_score < 0.95 && metrics.destructive_ops_detected > 0 {
        let unprotected = metrics.destructive_ops_detected - metrics.snapshots_before_destructive;
        suggestions.push(format!(
            "Only {}/{} destructive operations were preceded by snapshots ({unprotected} unprotected). Use `meta git snapshot create` before batch changes.",
            metrics.snapshots_before_destructive,
            metrics.destructive_ops_detected
        ));
    }

    if awareness_score < 0.95 && metrics.commits_attempted > 0 {
        suggestions.push(
            "Not all commits were preceded by `meta git status/diff` within 10 commands. Always check workspace state before committing.".to_string()
        );
    }

    if suggestions.is_empty() {
        suggestions.push("Excellent meta-repo practices! Keep it up.".to_string());
    }

    suggestions
}

// ── Output Formatting ───────────────────────────────────

pub fn format_markdown(score: &SessionScore) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "# Session Score: {} ({})\n\n",
        score.session_id,
        score.overall_grade.display()
    ));

    out.push_str("## Metrics\n\n");
    out.push_str("| Metric | Score | Grade | Weight |\n");
    out.push_str("|--------|-------|-------|--------|\n");
    out.push_str(&format!(
        "| Meta-command ratio | {:.0}% | {} | 25% |\n",
        score.meta_command_ratio * 100.0,
        score.meta_command_grade.display()
    ));
    out.push_str(&format!(
        "| Workspace discovery | {:.0}% | {} | 20% |\n",
        score.workspace_discovery_score * 100.0,
        score.workspace_discovery_grade.display()
    ));
    out.push_str(&format!(
        "| Snapshot safety | {:.0}% | {} | 25% |\n",
        score.snapshot_safety_score * 100.0,
        score.snapshot_safety_grade.display()
    ));
    out.push_str(&format!(
        "| Cross-repo awareness | {:.0}% | {} | 20% |\n",
        score.cross_repo_awareness_score * 100.0,
        score.cross_repo_awareness_grade.display()
    ));
    out.push_str(&format!(
        "| Guard effectiveness | {:.0}% | {} | 10% |\n\n",
        score.guard_effectiveness_score * 100.0,
        score.guard_effectiveness_grade.display()
    ));

    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Tool calls: {}\n", score.metrics.tool_calls));
    out.push_str(&format!(
        "- Git commands: {} ({} meta, {} bare)\n",
        score.metrics.total_git_commands,
        score.metrics.meta_git_commands,
        score.metrics.total_git_commands - score.metrics.meta_git_commands
    ));
    out.push_str(&format!(
        "- Destructive ops: {} ({} protected)\n",
        score.metrics.destructive_ops_detected, score.metrics.snapshots_before_destructive
    ));
    out.push_str(&format!(
        "- Commits: {}\n\n",
        score.metrics.commits_attempted
    ));

    out.push_str("## Suggestions\n\n");
    for suggestion in &score.suggestions {
        out.push_str(&format!("- {suggestion}\n"));
    }

    out
}

// ── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_project_hash() {
        let path = Path::new("/Users/matt/development/meta");
        let hash = SessionFinder::compute_project_hash(path);
        assert_eq!(hash, "-Users-matt-development-meta");
    }

    #[test]
    fn test_grade_from_score() {
        assert_eq!(Grade::from_score(0.95), Grade::A);
        assert_eq!(Grade::from_score(0.85), Grade::B);
        assert_eq!(Grade::from_score(0.75), Grade::C);
        assert_eq!(Grade::from_score(0.65), Grade::D);
        assert_eq!(Grade::from_score(0.50), Grade::F);
    }

    #[test]
    fn test_meta_command_detection() {
        let mut metrics = SessionMetrics::default();
        let mut last_snapshot = None;

        process_bash_command(
            "meta git status",
            1,
            "2026-01-27T00:00:00Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );
        assert_eq!(metrics.total_git_commands, 1);
        assert_eq!(metrics.meta_git_commands, 1);

        process_bash_command(
            "git commit -m 'test'",
            2,
            "2026-01-27T00:00:01Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );
        assert_eq!(metrics.total_git_commands, 2);
        assert_eq!(metrics.meta_git_commands, 1);
    }

    #[test]
    fn test_workspace_discovery_early() {
        let mut metrics = SessionMetrics::default();
        let mut last_snapshot = None;

        process_bash_command(
            "meta context",
            2,
            "2026-01-27T00:00:00Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );
        assert_eq!(metrics.workspace_discovery_rank, Some(2));
    }

    #[test]
    fn test_is_destructive_command() {
        assert!(is_destructive_command("git push --force origin main"));
        assert!(is_destructive_command("git reset --hard"));
        assert!(is_destructive_command("rm -rf ."));
        assert!(!is_destructive_command("git status"));
        assert!(!is_destructive_command("meta git status"));
    }

    #[test]
    fn test_snapshot_protection() {
        let mut metrics = SessionMetrics::default();
        let mut last_snapshot = None;

        // Create snapshot
        process_bash_command(
            "meta git snapshot create before-refactor",
            1,
            "2026-01-27T00:00:00Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );

        // Destructive op within 5 calls - should be protected
        process_bash_command(
            "git reset --hard HEAD~1",
            3,
            "2026-01-27T00:00:01Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );

        assert_eq!(metrics.destructive_ops_detected, 1);
        assert_eq!(metrics.snapshots_before_destructive, 1);
    }

    #[test]
    fn test_cross_repo_awareness() {
        let mut metrics = SessionMetrics::default();
        let mut last_snapshot = None;

        // meta status
        process_bash_command(
            "meta git status",
            5,
            "2026-01-27T00:00:00Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );

        // commit within 10 calls - protected
        process_bash_command(
            "git commit -m 'test'",
            8,
            "2026-01-27T00:00:01Z".to_string(),
            &mut metrics,
            &mut last_snapshot,
        );

        assert_eq!(metrics.commits_attempted, 1);
        assert_eq!(metrics.meta_status_before_commit, vec![5]);
    }
}
