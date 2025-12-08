use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod client;
mod metrics;
mod runner;
mod setup;
mod ucan;

#[derive(Parser)]
#[command(name = "keycast-loadtest")]
#[command(about = "Load testing tool for Keycast HTTP RPC endpoint")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Create test users with OAuth authorizations
    Setup(SetupArgs),

    /// Run load test against the HTTP RPC endpoint
    Run(RunArgs),

    /// Display results from a previous test run
    Report(ReportArgs),
}

#[derive(clap::Args)]
struct SetupArgs {
    /// Target server URL
    #[arg(short, long, default_value = "http://localhost:3000")]
    url: String,

    /// Number of test users to create
    #[arg(short = 'n', long, default_value = "100")]
    users: usize,

    /// Concurrent registration requests (for HTTP mode)
    #[arg(short, long, default_value = "50")]
    concurrency: usize,

    /// Database connection URL (enables DB mode for localhost)
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Master key path for encryption (DB mode only)
    #[arg(long, env = "MASTER_KEY_PATH", default_value = "./master.key")]
    master_key_path: PathBuf,

    /// Force specific mode instead of auto-detection
    #[arg(long, value_enum)]
    mode: Option<SetupMode>,

    /// Output file for generated credentials
    #[arg(short, long, default_value = "./loadtest-users.json")]
    output: PathBuf,
}

#[derive(Clone, ValueEnum)]
enum SetupMode {
    /// Direct database access (fastest, requires DATABASE_URL)
    Db,
    /// HTTP registration API (works against any server)
    Http,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Target server URL
    #[arg(short, long, default_value = "http://localhost:3000")]
    url: String,

    /// Number of concurrent connections
    #[arg(short, long, default_value = "10")]
    concurrency: usize,

    /// Total number of requests (0 = unlimited until duration)
    #[arg(short = 'n', long, default_value = "0")]
    requests: usize,

    /// Test duration in seconds (0 = until requests complete)
    #[arg(short, long, default_value = "60")]
    duration: u64,

    /// Ramp-up period in seconds
    #[arg(long, default_value = "5")]
    ramp_up: u64,

    /// Test scenario
    #[arg(short, long, value_enum, default_value = "mixed")]
    scenario: TestScenario,

    /// RPC method to test
    #[arg(short, long, value_enum, default_value = "sign-event")]
    method: RpcMethod,

    /// Path to user credentials file from setup
    #[arg(long, default_value = "./loadtest-users.json")]
    users_file: PathBuf,

    /// Output file for results
    #[arg(short, long, default_value = "./loadtest-results.json")]
    output: PathBuf,

    /// Real-time progress report interval in seconds
    #[arg(long, default_value = "5")]
    report_interval: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TestScenario {
    /// All requests use first user (100% cache hit after warmup)
    WarmCache,
    /// Each request uses different user (100% cache miss)
    ColdStart,
    /// Rotate through users with 80/20 hot/cold split
    Mixed,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RpcMethod {
    /// Sign a Nostr event (kind 1 text note)
    SignEvent,
    /// Get user's public key
    GetPublicKey,
    /// Encrypt with NIP-44
    Nip44Encrypt,
    /// Full registration flow (register + OAuth authorize + token)
    Register,
}

#[derive(clap::Args)]
struct ReportArgs {
    /// Path to results file
    #[arg(short, long, default_value = "./loadtest-results.json")]
    input: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: ReportFormat,

    /// Compare with another results file
    #[arg(long)]
    compare: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
    Csv,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    match cli.command {
        Commands::Setup(args) => {
            setup::run_setup(args).await?;
        }
        Commands::Run(args) => {
            runner::run_loadtest(args).await?;
        }
        Commands::Report(args) => {
            report::run_report(args)?;
        }
    }

    Ok(())
}

mod report {
    use super::*;

    pub fn run_report(args: ReportArgs) -> anyhow::Result<()> {
        let results = std::fs::read_to_string(&args.input)?;
        let results: metrics::TestResults = serde_json::from_str(&results)?;

        match args.format {
            ReportFormat::Text => {
                println!("{}", results.format_text());
            }
            ReportFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            ReportFormat::Csv => {
                println!("{}", results.format_csv());
            }
        }

        if let Some(compare_path) = args.compare {
            let compare = std::fs::read_to_string(&compare_path)?;
            let compare: metrics::TestResults = serde_json::from_str(&compare)?;
            println!("\n{}", results.compare(&compare));
        }

        Ok(())
    }
}
