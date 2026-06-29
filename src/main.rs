//! Claude Code agent toolkit: guard, score, and more.
//!
//! A standalone CLI for Claude Code agent integration. Provides deterministic
//! command guards, session scoring, and other agent utilities.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod codex;
mod guard;
mod score;

/// Claude Code agent toolkit
#[derive(Parser)]
#[command(name = "agent")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Codex environment parity tools for the meta workspace
    Codex {
        #[command(subcommand)]
        command: CodexCommands,
    },

    /// Evaluate a command for destructive patterns (PreToolUse hook)
    Guard,

    /// Score Claude Code sessions for agent effectiveness
    Score {
        /// Specific session ID to score
        #[arg(long)]
        session: Option<String>,

        /// Number of recent sessions to score
        #[arg(long, default_value = "1")]
        recent: Option<usize>,
    },
}

#[derive(Subcommand)]
enum CodexCommands {
    /// Inventory the seven-layer Codex environment
    Inventory,

    /// Install repo prompt templates into ~/.codex/prompts for /prompts:* commands
    InstallPrompts,

    /// Codex Stop/SubagentStop hook for meta workspace discipline
    Stop,

    /// Run a command with full output captured to an artifact and only a capped tail printed
    Exec(codex::ExecArgs),

    /// Check a background/capped Codex exec artifact without dumping the full log
    ExecStatus(codex::ExecStatusArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Codex { command }) => match command {
            CodexCommands::Inventory => codex::handle_inventory(cli.json),
            CodexCommands::InstallPrompts => codex::handle_install_prompts(),
            CodexCommands::Stop => codex::handle_stop(),
            CodexCommands::Exec(args) => codex::handle_exec(args),
            CodexCommands::ExecStatus(args) => codex::handle_exec_status(args),
        },
        Some(Commands::Guard) => guard::handle_guard(),
        Some(Commands::Score { session, recent }) => {
            score::handle_score(session, recent, cli.json, cli.verbose)
        }
        None => {
            eprintln!("Claude Code agent toolkit");
            eprintln!();
            eprintln!("Usage: agent <COMMAND>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  codex   Codex environment parity tools for the meta workspace");
            eprintln!("  guard   Evaluate a command for destructive patterns (PreToolUse hook)");
            eprintln!("  score   Score Claude Code sessions for agent effectiveness");
            eprintln!();
            eprintln!("For more information, use: agent --help");
            Ok(())
        }
    }
}
