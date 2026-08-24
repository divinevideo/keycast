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
    intentional_shedding: Option<IntentionalSheddingExpectation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentionalSheddingExpectation {
    status: u16,
    error_code: String,
    min_rate: f64,
}

#[derive(Debug, Serialize)]
struct CapacityEvidence {
    schema_version: u32,
    evidence_scope: &'static str,
    generated_at: chrono::DateTime<chrono::Utc>,
    execution_environment: ExecutionEnvironment,
    plan: CapacityPlan,
    passed: bool,
    certification_ready: bool,
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
    results: Option<TestResults>,
    error: Option<String>,
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
    outcome: CheckOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CheckOutcome {
    Passed,
    Failed,
    NotTested,
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
        let results = runner::run_loadtest_with_stop(
            RunArgs {
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
            },
            Some(runner::LiveStopConditions {
                max_unintentional_error_rate: plan.stop_conditions.max_error_rate,
                max_latency_p95_ms: plan.stop_conditions.max_latency_p95_ms,
            }),
        )
        .await;
        let results = match results {
            Ok(results) => results,
            Err(error) => {
                stopped_after_phase = Some(phase.name.clone());
                phase_evidence.push(PhaseEvidence {
                    name: phase.name.clone(),
                    kind: phase.kind,
                    passed: false,
                    checks: Vec::new(),
                    stop_breached: false,
                    stop_checks: Vec::new(),
                    results: None,
                    error: Some(format!("{error:#}")),
                });
                break;
            }
        };

        let mut checks = vec![
            EvidenceCheck {
                metric: "total_requests",
                comparison: "at-least",
                observed: results.summary.total_requests as f64,
                limit: 1.0,
                outcome: outcome(results.summary.total_requests > 0),
            },
            EvidenceCheck {
                metric: "unintentional_error_rate",
                comparison: "at-most",
                observed: results.summary.unintentional_error_rate,
                limit: phase.max_error_rate,
                outcome: outcome(results.summary.unintentional_error_rate <= phase.max_error_rate),
            },
            EvidenceCheck {
                metric: "latency_p95_ms",
                comparison: "at-most",
                observed: results.summary.latency_p95_ms,
                limit: phase.max_latency_p95_ms,
                outcome: outcome(results.summary.latency_p95_ms <= phase.max_latency_p95_ms),
            },
        ];
        checks.push(match &phase.intentional_shedding {
            Some(expectation) => EvidenceCheck {
                metric: "intentional_rejection_rate",
                comparison: "at-least",
                observed: results.summary.intentional_rejection_rate,
                limit: expectation.min_rate,
                outcome: outcome(
                    results.summary.intentional_rejection_rate >= expectation.min_rate,
                ),
            },
            None => EvidenceCheck {
                metric: "intentional_rejection_rate",
                comparison: "at-least",
                observed: results.summary.intentional_rejection_rate,
                limit: 0.0,
                outcome: CheckOutcome::NotTested,
            },
        });
        let availability = availability_percent(&results);
        if phase.slo_applies {
            checks.extend([
                EvidenceCheck {
                    metric: "availability_percent",
                    comparison: "at-least",
                    observed: availability,
                    limit: plan.objectives.availability_percent,
                    outcome: outcome(availability >= plan.objectives.availability_percent),
                },
                EvidenceCheck {
                    metric: "slo_latency_p95_ms",
                    comparison: "at-most",
                    observed: results.summary.latency_p95_ms,
                    limit: plan.objectives.latency_p95_ms,
                    outcome: outcome(
                        results.summary.latency_p95_ms <= plan.objectives.latency_p95_ms,
                    ),
                },
            ]);
        }
        let stop_checks = vec![
            EvidenceCheck {
                metric: "stop_unintentional_error_rate",
                comparison: "at-most",
                observed: results.summary.unintentional_error_rate,
                limit: plan.stop_conditions.max_error_rate,
                outcome: outcome(
                    results.summary.unintentional_error_rate <= plan.stop_conditions.max_error_rate,
                ),
            },
            EvidenceCheck {
                metric: "stop_latency_p95_ms",
                comparison: "at-most",
                observed: results.summary.latency_p95_ms,
                limit: plan.stop_conditions.max_latency_p95_ms,
                outcome: outcome(
                    results.summary.latency_p95_ms <= plan.stop_conditions.max_latency_p95_ms,
                ),
            },
        ];
        let (phase_passed, stop_breached) = phase_outcome(&checks, &stop_checks);
        phase_evidence.push(PhaseEvidence {
            name: phase.name.clone(),
            kind: phase.kind,
            passed: phase_passed,
            checks,
            stop_breached,
            stop_checks,
            results: Some(results),
            error: None,
        });
        if stop_breached {
            stopped_after_phase = Some(phase.name.clone());
            break;
        }
    }

    let passed = phase_evidence.len() == plan.phases.len()
        && phase_evidence.iter().all(|phase| phase.passed);
    let certification_ready = passed
        && plan
            .phases
            .iter()
            .any(|phase| phase.intentional_shedding.is_some())
        && phase_evidence.iter().all(|phase| {
            phase.checks.iter().all(|check| {
                check.metric != "intentional_rejection_rate"
                    || check.outcome != CheckOutcome::Failed
            })
        });
    let evidence = CapacityEvidence {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        evidence_scope: "synthetic non-production capacity rehearsal",
        generated_at: chrono::Utc::now(),
        execution_environment,
        plan,
        passed,
        certification_ready,
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

fn availability_percent(results: &TestResults) -> f64 {
    (1.0 - results.summary.error_rate) * 100.0
}

fn phase_outcome(checks: &[EvidenceCheck], stop_checks: &[EvidenceCheck]) -> (bool, bool) {
    let stop_breached = stop_checks
        .iter()
        .any(|check| check.outcome == CheckOutcome::Failed);
    (
        checks
            .iter()
            .all(|check| check.outcome != CheckOutcome::Failed)
            && !stop_breached,
        stop_breached,
    )
}

fn outcome(passed: bool) -> CheckOutcome {
    if passed {
        CheckOutcome::Passed
    } else {
        CheckOutcome::Failed
    }
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

    let actual_phases: Vec<_> = plan.phases.iter().map(|phase| phase.kind).collect();
    if actual_phases != REQUIRED_PHASES {
        anyhow::bail!(
            "capacity phases must appear exactly once in this order: ramp, spike, soak, recovery, rollout, scale-down"
        );
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
        if phase.ramp_up_seconds >= phase.duration_seconds && phase.ramp_up_seconds != 0 {
            anyhow::bail!(
                "phase {:?} ramp-up must be shorter than its duration",
                phase.name
            );
        }
        validate_rate("phases[].max_error_rate", phase.max_error_rate)?;
        if let Some(expectation) = &phase.intentional_shedding {
            if phase.kind != PhaseKind::Spike {
                anyhow::bail!("only the spike phase may declare intentional shedding");
            }
            if expectation.status != 503 || expectation.error_code != "admission_rejected" {
                anyhow::bail!(
                    "intentional shedding must use HTTP 503 with error code admission_rejected"
                );
            }
            validate_rate(
                "phases[].intentional_shedding.min_rate",
                expectation.min_rate,
            )?;
            if expectation.min_rate <= 0.0 {
                anyhow::bail!("intentional shedding min_rate must be greater than zero");
            }
        }
        validate_positive("phases[].max_latency_p95_ms", phase.max_latency_p95_ms)?;
        if matches!(phase.method, RpcMethod::Register) {
            anyhow::bail!("capacity profiles do not support non-deterministic registration phases");
        }
        if phase.kind != PhaseKind::Spike && !phase.slo_applies {
            anyhow::bail!("only the spike phase may opt out of profile SLO checks");
        }
    }
    Ok(execution_environment)
}

fn is_local_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host.ends_with(".localhost")
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
    use crate::metrics::{MetricsSummary, TestMetadata};

    fn results(error_rate: f64) -> TestResults {
        TestResults {
            metadata: TestMetadata {
                url: "http://localhost:3000".to_owned(),
                scenario: "Mixed".to_owned(),
                method: "GetPublicKey".to_owned(),
                concurrency: 1,
                duration_secs: 1,
                user_count: 1,
                timestamp: chrono::Utc::now(),
                seed: 371,
            },
            summary: MetricsSummary {
                duration_secs: 1.0,
                requests_per_second: 1.0,
                total_requests: 1,
                successful_requests: 0,
                failed_requests: 1,
                latency_min_ms: 1.0,
                latency_p50_ms: 1.0,
                latency_p95_ms: 1.0,
                latency_p99_ms: 1.0,
                latency_max_ms: 1.0,
                cache_hit_ratio: 0.0,
                error_rate,
                unintentional_error_rate: 0.0,
                errors_auth: 0,
                errors_server: 0,
                errors_client: 0,
                errors_network: 0,
                rate_limited_requests: 0,
                intentional_rejections: 1,
                intentional_rejection_rate: error_rate,
            },
            timeline: Vec::new(),
            server_metrics: None,
        }
    }

    fn check(passed: bool) -> EvidenceCheck {
        EvidenceCheck {
            metric: "test",
            comparison: "at-most",
            observed: 0.0,
            limit: 0.0,
            outcome: outcome(passed),
        }
    }

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
                    intentional_shedding: if kind == PhaseKind::Spike {
                        Some(IntentionalSheddingExpectation {
                            status: 503,
                            error_code: "admission_rejected".to_owned(),
                            min_rate: 0.01,
                        })
                    } else {
                        None
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
    fn intentional_rejections_reduce_healthy_phase_availability() {
        assert_eq!(availability_percent(&results(1.0)), 0.0);
    }

    #[test]
    fn ordinary_miss_continues_but_absolute_breach_stops() {
        assert_eq!(
            phase_outcome(&[check(false)], &[check(true)]),
            (false, false)
        );
        assert_eq!(
            phase_outcome(&[check(true)], &[check(false)]),
            (false, true)
        );
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
    fn every_required_phase_must_be_predeclared_in_order() {
        let mut missing_plan = plan();
        missing_plan
            .phases
            .retain(|phase| phase.kind != PhaseKind::Recovery);

        let error = validate_plan(&missing_plan, None).unwrap_err();
        assert!(error
            .to_string()
            .contains("must appear exactly once in this order"));

        let mut reordered_plan = plan();
        reordered_plan.phases.swap(1, 3);
        assert!(validate_plan(&reordered_plan, None)
            .unwrap_err()
            .to_string()
            .contains("must appear exactly once in this order"));
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
    fn spike_may_leave_shedding_not_tested() {
        let mut plan = plan();
        plan.phases[1].intentional_shedding = None;

        validate_plan(&plan, None).unwrap();
    }

    #[test]
    fn shedding_contract_is_fixed_and_explicit() {
        let mut plan = plan();
        plan.phases[1]
            .intentional_shedding
            .as_mut()
            .unwrap()
            .error_code = "database_unavailable".to_owned();

        assert!(validate_plan(&plan, None)
            .unwrap_err()
            .to_string()
            .contains("admission_rejected"));
    }

    #[test]
    fn ramp_up_must_be_shorter_than_duration() {
        let mut plan = plan();
        plan.phases[0].ramp_up_seconds = plan.phases[0].duration_seconds;

        assert!(validate_plan(&plan, None)
            .unwrap_err()
            .to_string()
            .contains("ramp-up must be shorter"));
    }

    #[test]
    fn ipv6_loopback_is_local() {
        let mut plan = plan();
        plan.target_url = "http://[::1]:3000".to_owned();

        assert_eq!(
            validate_plan(&plan, None).unwrap(),
            ExecutionEnvironment::Local
        );
    }

    #[tokio::test]
    async fn phase_setup_error_still_writes_partial_evidence() {
        let temp = std::env::temp_dir().join(format!(
            "keycast-capacity-partial-evidence-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let mut plan = plan();
        plan.users_file = temp.join("missing-users.json");
        plan.phases[1].intentional_shedding = None;
        let plan_path = temp.join("plan.json");
        std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        let output = temp.join("evidence");

        let error = run_capacity(CapacityArgs {
            plan: plan_path,
            output: output.clone(),
            allow_host: None,
        })
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("exceeded their predeclared limits"));
        let evidence: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("evidence.json")).unwrap()).unwrap();
        assert_eq!(evidence["passed"], false);
        assert_eq!(evidence["certification_ready"], false);
        assert_eq!(evidence["phases"][0]["passed"], false);
        assert!(!evidence["phases"][0]["error"].as_str().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn evidence_file_names_are_sanitized() {
        assert_eq!(
            safe_file_component("ramp / cache warm"),
            "ramp---cache-warm"
        );
    }
}
