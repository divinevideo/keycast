use crate::metrics::TestResults;
use crate::{runner, CapacityArgs, RpcMethod, RunArgs, TestScenario};
use anyhow::{Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

const EVIDENCE_SCHEMA_VERSION: u32 = 1;
const REQUIRED_PHASES: [PhaseKind; 6] = [
    PhaseKind::Ramp,
    PhaseKind::Spike,
    PhaseKind::Soak,
    PhaseKind::Recovery,
    PhaseKind::Rollout,
    PhaseKind::ScaleDown,
];
const BLOCKED_PRODUCTION_HOSTS: [&str; 2] = ["login.divine.video", "keycast.divine.video"];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PlatformProfile {
    CloudRun,
    Gke,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PhaseKind {
    Ramp,
    Spike,
    Soak,
    Recovery,
    Rollout,
    ScaleDown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapacityPlan {
    profile_name: String,
    profile_platform: PlatformProfile,
    target_url: String,
    users_file: PathBuf,
    seed: u64,
    revisions: Revisions,
    environment_parity: String,
    objectives: Objectives,
    stop_conditions: StopConditions,
    phases: Vec<CapacityPhase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Revisions {
    code: String,
    image: String,
    infrastructure: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Objectives {
    availability_percent: f64,
    latency_p95_ms: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StopConditions {
    max_error_rate: f64,
    max_latency_p95_ms: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapacityPhase {
    name: String,
    kind: PhaseKind,
    method: RpcMethod,
    scenario: TestScenario,
    concurrency: usize,
    duration_seconds: u64,
    ramp_up_seconds: u64,
    max_error_rate: f64,
    max_latency_p95_ms: f64,
    slo_applies: bool,
    min_intentional_rejection_rate: f64,
}

#[derive(Debug, Serialize)]
struct CapacityEvidence {
    schema_version: u32,
    evidence_scope: &'static str,
    generated_at: chrono::DateTime<chrono::Utc>,
    execution_environment: ExecutionEnvironment,
    plan: CapacityPlan,
    passed: bool,
    stopped_after_phase: Option<String>,
    phases: Vec<PhaseEvidence>,
}

#[derive(Debug, Serialize)]
struct PhaseEvidence {
    name: String,
    kind: PhaseKind,
    passed: bool,
    checks: Vec<EvidenceCheck>,
    stop_breached: bool,
    stop_checks: Vec<EvidenceCheck>,
    results: TestResults,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ExecutionEnvironment {
    Local,
    AuthorizedNonProduction,
}

#[derive(Debug, Serialize)]
struct EvidenceCheck {
    metric: &'static str,
    comparison: &'static str,
    observed: f64,
    limit: f64,
    passed: bool,
}

pub async fn run_capacity(args: CapacityArgs) -> Result<()> {
    let plan_text = std::fs::read_to_string(&args.plan)
        .with_context(|| format!("failed to read capacity plan {:?}", args.plan))?;
    let plan: CapacityPlan = serde_json::from_str(&plan_text)
        .with_context(|| format!("failed to parse capacity plan {:?}", args.plan))?;
    let execution_environment = validate_plan(&plan, args.allow_host.as_deref())?;

    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("failed to create evidence directory {:?}", args.output))?;

    let mut phase_evidence = Vec::with_capacity(plan.phases.len());
    let mut stopped_after_phase = None;
    for (index, phase) in plan.phases.iter().enumerate() {
        let phase_output = args.output.join(format!(
            "phase-{:02}-{}.json",
            index + 1,
            safe_file_component(&phase.name)
        ));
        let results = runner::run_loadtest(RunArgs {
            url: plan.target_url.clone(),
            concurrency: phase.concurrency,
            requests: 0,
            duration: phase.duration_seconds,
            ramp_up: phase.ramp_up_seconds,
            scenario: phase.scenario,
            method: phase.method,
            users_file: plan.users_file.clone(),
            output: phase_output,
            report_interval: phase.duration_seconds.clamp(1, 5),
            seed: plan.seed,
        })
        .await
        .with_context(|| format!("capacity phase {:?} failed", phase.name))?;

        let mut checks = vec![
            EvidenceCheck {
                metric: "total_requests",
                comparison: "at-least",
                observed: results.summary.total_requests as f64,
                limit: 1.0,
                passed: results.summary.total_requests > 0,
            },
            EvidenceCheck {
                metric: "unintentional_error_rate",
                comparison: "at-most",
                observed: results.summary.unintentional_error_rate,
                limit: phase.max_error_rate,
                passed: results.summary.unintentional_error_rate <= phase.max_error_rate,
            },
            EvidenceCheck {
                metric: "latency_p95_ms",
                comparison: "at-most",
                observed: results.summary.latency_p95_ms,
                limit: phase.max_latency_p95_ms,
                passed: results.summary.latency_p95_ms <= phase.max_latency_p95_ms,
            },
            EvidenceCheck {
                metric: "intentional_rejection_rate",
                comparison: "at-least",
                observed: results.summary.intentional_rejection_rate,
                limit: phase.min_intentional_rejection_rate,
                passed: results.summary.intentional_rejection_rate
                    >= phase.min_intentional_rejection_rate,
            },
        ];
        if phase.slo_applies {
            checks.extend([
                EvidenceCheck {
                    metric: "availability_percent",
                    comparison: "at-least",
                    observed: (1.0 - results.summary.unintentional_error_rate) * 100.0,
                    limit: plan.objectives.availability_percent,
                    passed: (1.0 - results.summary.unintentional_error_rate) * 100.0
                        >= plan.objectives.availability_percent,
                },
                EvidenceCheck {
                    metric: "slo_latency_p95_ms",
                    comparison: "at-most",
                    observed: results.summary.latency_p95_ms,
                    limit: plan.objectives.latency_p95_ms,
                    passed: results.summary.latency_p95_ms <= plan.objectives.latency_p95_ms,
                },
            ]);
        }
        let stop_checks = vec![
            EvidenceCheck {
                metric: "stop_unintentional_error_rate",
                comparison: "at-most",
                observed: results.summary.unintentional_error_rate,
                limit: plan.stop_conditions.max_error_rate,
                passed: results.summary.unintentional_error_rate
                    <= plan.stop_conditions.max_error_rate,
            },
            EvidenceCheck {
                metric: "stop_latency_p95_ms",
                comparison: "at-most",
                observed: results.summary.latency_p95_ms,
                limit: plan.stop_conditions.max_latency_p95_ms,
                passed: results.summary.latency_p95_ms <= plan.stop_conditions.max_latency_p95_ms,
            },
        ];
        let stop_breached = stop_checks.iter().any(|check| !check.passed);
        let phase_passed = checks.iter().all(|check| check.passed) && !stop_breached;
        phase_evidence.push(PhaseEvidence {
            name: phase.name.clone(),
            kind: phase.kind,
            passed: phase_passed,
            checks,
            stop_breached,
            stop_checks,
            results,
        });
        if stop_breached {
            stopped_after_phase = Some(phase.name.clone());
            break;
        }
    }

    let passed = phase_evidence.iter().all(|phase| phase.passed);
    let evidence = CapacityEvidence {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        evidence_scope: "synthetic non-production capacity rehearsal",
        generated_at: chrono::Utc::now(),
        execution_environment,
        plan,
        passed,
        stopped_after_phase,
        phases: phase_evidence,
    };
    let evidence_path = args.output.join("evidence.json");
    std::fs::write(&evidence_path, serde_json::to_string_pretty(&evidence)?)
        .with_context(|| format!("failed to write evidence bundle {evidence_path:?}"))?;

    println!("Capacity evidence saved to {}", evidence_path.display());
    if !passed {
        anyhow::bail!("one or more capacity phases exceeded their predeclared limits");
    }
    Ok(())
}

fn validate_plan(plan: &CapacityPlan, allowed_host: Option<&str>) -> Result<ExecutionEnvironment> {
    validate_nonempty("profile_name", &plan.profile_name)?;
    validate_nonempty("environment_parity", &plan.environment_parity)?;
    validate_nonempty("revisions.code", &plan.revisions.code)?;
    validate_nonempty("revisions.image", &plan.revisions.image)?;
    validate_nonempty("revisions.infrastructure", &plan.revisions.infrastructure)?;
    validate_percentage(
        "objectives.availability_percent",
        plan.objectives.availability_percent,
    )?;
    validate_positive("objectives.latency_p95_ms", plan.objectives.latency_p95_ms)?;
    validate_rate(
        "stop_conditions.max_error_rate",
        plan.stop_conditions.max_error_rate,
    )?;
    validate_positive(
        "stop_conditions.max_latency_p95_ms",
        plan.stop_conditions.max_latency_p95_ms,
    )?;

    let target = Url::parse(&plan.target_url).context("target_url must be an absolute URL")?;
    let host = target
        .host_str()
        .context("target_url must include a host")?;
    if !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
    {
        anyhow::bail!("target_url must not contain credentials, query parameters, or fragments");
    }
    if BLOCKED_PRODUCTION_HOSTS.contains(&host) {
        anyhow::bail!("capacity profiles cannot target the production host {host}");
    }
    if !is_local_host(host) && allowed_host != Some(host) {
        anyhow::bail!(
            "non-local target {host} requires the exact --allow-host {host} authorization"
        );
    }
    let execution_environment = if is_local_host(host) {
        ExecutionEnvironment::Local
    } else {
        ExecutionEnvironment::AuthorizedNonProduction
    };

    let present: BTreeSet<_> = plan.phases.iter().map(|phase| phase.kind).collect();
    for required in REQUIRED_PHASES {
        if !present.contains(&required) {
            anyhow::bail!("capacity plan is missing required {required:?} phase");
        }
    }
    let mut phase_names = BTreeSet::new();
    for phase in &plan.phases {
        validate_nonempty("phases[].name", &phase.name)?;
        let file_component = safe_file_component(&phase.name);
        if file_component.is_empty() || !phase_names.insert(file_component) {
            anyhow::bail!("phase names must produce unique non-empty evidence file names");
        }
        if phase.concurrency == 0 || phase.duration_seconds == 0 {
            anyhow::bail!(
                "phase {:?} must have non-zero concurrency and duration",
                phase.name
            );
        }
        validate_rate("phases[].max_error_rate", phase.max_error_rate)?;
        validate_rate(
            "phases[].min_intentional_rejection_rate",
            phase.min_intentional_rejection_rate,
        )?;
        validate_positive("phases[].max_latency_p95_ms", phase.max_latency_p95_ms)?;
        if matches!(phase.method, RpcMethod::Register) {
            anyhow::bail!("capacity profiles do not support non-deterministic registration phases");
        }
        if phase.kind != PhaseKind::Spike && !phase.slo_applies {
            anyhow::bail!("only the spike phase may opt out of profile SLO checks");
        }
        if phase.kind == PhaseKind::Spike && phase.min_intentional_rejection_rate <= 0.0 {
            anyhow::bail!("the spike phase must declare a non-zero intentional rejection rate");
        }
    }
    Ok(execution_environment)
}

fn is_local_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".localhost")
}

fn validate_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    Ok(())
}

fn validate_rate(field: &str, value: f64) -> Result<()> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        anyhow::bail!("{field} must be between 0 and 1");
    }
    Ok(())
}

fn validate_percentage(field: &str, value: f64) -> Result<()> {
    if !value.is_finite() || !(0.0..=100.0).contains(&value) {
        anyhow::bail!("{field} must be between 0 and 100");
    }
    Ok(())
}

fn validate_positive(field: &str, value: f64) -> Result<()> {
    if !value.is_finite() || value <= 0.0 {
        anyhow::bail!("{field} must be greater than zero");
    }
    Ok(())
}

fn safe_file_component(value: &str) -> String {
    let component: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect();
    component.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> CapacityPlan {
        CapacityPlan {
            profile_name: "local-cloud-run".to_owned(),
            profile_platform: PlatformProfile::CloudRun,
            target_url: "http://localhost:3000".to_owned(),
            users_file: PathBuf::from("users.json"),
            seed: 371,
            revisions: Revisions {
                code: "abc123".to_owned(),
                image: "sha256:example".to_owned(),
                infrastructure: "local-compose-v1".to_owned(),
            },
            environment_parity: "Local rehearsal only".to_owned(),
            objectives: Objectives {
                availability_percent: 99.9,
                latency_p95_ms: 500.0,
            },
            stop_conditions: StopConditions {
                max_error_rate: 0.05,
                max_latency_p95_ms: 1_000.0,
            },
            phases: REQUIRED_PHASES
                .into_iter()
                .map(|kind| CapacityPhase {
                    name: format!("{kind:?}"),
                    kind,
                    method: RpcMethod::GetPublicKey,
                    scenario: TestScenario::Mixed,
                    concurrency: 1,
                    duration_seconds: 1,
                    ramp_up_seconds: 0,
                    max_error_rate: 0.01,
                    max_latency_p95_ms: 500.0,
                    slo_applies: kind != PhaseKind::Spike,
                    min_intentional_rejection_rate: if kind == PhaseKind::Spike {
                        0.01
                    } else {
                        0.0
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn local_complete_plan_is_valid() {
        validate_plan(&plan(), None).unwrap();
    }

    #[test]
    fn non_local_target_requires_exact_authorization() {
        let mut plan = plan();
        plan.target_url = "https://staging.example.test".to_owned();

        let error = validate_plan(&plan, None).unwrap_err();
        assert!(error
            .to_string()
            .contains("--allow-host staging.example.test"));
        assert_eq!(
            validate_plan(&plan, Some("staging.example.test")).unwrap(),
            ExecutionEnvironment::AuthorizedNonProduction
        );
    }

    #[test]
    fn production_target_is_always_rejected() {
        let mut plan = plan();
        plan.target_url = "https://login.divine.video".to_owned();

        let error = validate_plan(&plan, Some("login.divine.video")).unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot target the production host"));
    }

    #[test]
    fn target_url_cannot_embed_sensitive_components() {
        let mut plan = plan();
        plan.target_url = "http://user:password@localhost:3000?token=value".to_owned();

        let error = validate_plan(&plan, None).unwrap_err();
        assert!(error.to_string().contains("must not contain credentials"));
    }

    #[test]
    fn every_required_phase_must_be_predeclared() {
        let mut plan = plan();
        plan.phases
            .retain(|phase| phase.kind != PhaseKind::Recovery);

        let error = validate_plan(&plan, None).unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required Recovery phase"));
    }

    #[test]
    fn absolute_stop_limits_are_independent_from_phase_limits() {
        let mut plan = plan();
        plan.phases[0].max_error_rate = 0.1;

        validate_plan(&plan, None).unwrap();
    }

    #[test]
    fn registration_is_excluded_from_seeded_capacity_profiles() {
        let mut plan = plan();
        plan.phases[0].method = RpcMethod::Register;

        let error = validate_plan(&plan, None).unwrap_err();
        assert!(error.to_string().contains("non-deterministic registration"));
    }

    #[test]
    fn evidence_file_names_are_sanitized() {
        assert_eq!(
            safe_file_component("ramp / cache warm"),
            "ramp---cache-warm"
        );
    }
}
