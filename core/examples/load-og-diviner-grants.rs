// ABOUTME: Loads a private OG Diviner grant roster into og_diviner_grants
// ABOUTME: Run with: cargo run -p keycast_core --example load-og-diviner-grants
//
// Usage:
//   DATABASE_URL=... cargo run -p keycast_core --example load-og-diviner-grants -- \
//     --tenant-id <id> --evidence pre_cutoff_app_post [--apply] <roster-file>
//
// The roster is one 64-character lowercase hex pubkey per line, built privately
// from relay data (keycast#440). It is never committed, and this loader never
// prints a pubkey, a line of the file, or its path: output is counts and line
// numbers only. Without --apply it is a dry run that reports what a load would
// do. Re-running an applied roster is a no-op.
//
// Point DATABASE_URL at a connection that bypasses the transaction-mode
// pooler, as the migration job does: sqlx caches prepared statements per
// connection. See "OG Diviner grants" in docs/DEPLOYMENT.md.

use keycast_core::repositories::{
    parse_grant_roster, OgDivinerGrantEvidence, OgDivinerGrantRepository,
};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::process::ExitCode;

const USAGE: &str =
    "usage: load-og-diviner-grants --tenant-id <id> --evidence <label> [--apply] <roster-file>";

struct Args {
    tenant_id: i64,
    evidence: OgDivinerGrantEvidence,
    apply: bool,
    roster_path: String,
}

fn parse_args() -> Result<Args, String> {
    let mut tenant_id = None;
    let mut evidence = None;
    let mut apply = false;
    let mut roster_path = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tenant-id" => {
                let value = args.next().ok_or("--tenant-id needs a value")?;
                tenant_id = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| "--tenant-id must be a number")?,
                );
            }
            "--evidence" => {
                let value = args.next().ok_or("--evidence needs a value")?;
                evidence = Some(value.parse::<OgDivinerGrantEvidence>()?);
            }
            "--apply" => apply = true,
            flag if flag.starts_with("--") => return Err("unknown option".to_string()),
            _ if roster_path.is_some() => return Err("only one roster file".to_string()),
            _ => roster_path = Some(arg),
        }
    }

    Ok(Args {
        tenant_id: tenant_id.ok_or("--tenant-id is required")?,
        evidence: evidence.ok_or("--evidence is required")?,
        apply,
        roster_path: roster_path.ok_or("a roster file is required")?,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    // io::Error's message names the failure, not the path or the contents.
    let input = match std::fs::read_to_string(&args.roster_path) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("could not read the roster file: {error}");
            return ExitCode::FAILURE;
        }
    };
    let roster = match parse_grant_roster(&input) {
        Ok(roster) => roster,
        Err(error) => {
            eprintln!("roster rejected, nothing loaded: {error}");
            return ExitCode::FAILURE;
        }
    };
    drop(input);

    let Ok(database_url) = env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL must be set");
        return ExitCode::from(2);
    };
    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("could not connect to the database: {error}");
            return ExitCode::FAILURE;
        }
    };

    let report = OgDivinerGrantRepository::new(pool.clone())
        .load(args.tenant_id, args.evidence, &roster, args.apply)
        .await;
    pool.close().await;
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            eprintln!("load failed, nothing loaded: {error}");
            return ExitCode::FAILURE;
        }
    };

    if !report.applied {
        println!("DRY RUN: nothing written; pass --apply to load");
    }
    println!("tenant:          {}", args.tenant_id);
    println!("evidence:        {}", args.evidence.as_str());
    println!("lines read:      {}", roster.entries());
    println!("duplicate lines: {}", roster.duplicates());
    println!("unique pubkeys:  {}", report.unique);
    println!(
        "{} {}",
        if report.applied {
            "newly granted:  "
        } else {
            "would grant:    "
        },
        report.newly_granted
    );
    println!("already granted: {}", report.already_granted);
    ExitCode::SUCCESS
}
