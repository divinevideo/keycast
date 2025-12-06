//! Multi-process integration tests for ClusterAwarePool.
//!
//! These tests spawn real separate processes to verify:
//! - Multiple instances can start without blocking each other
//! - Connection limits adjust correctly across processes
//! - Eviction works when membership changes
//!
//! Run with: cargo test -p pg-hashring --features pool --test multiprocess -- --test-threads=1

#![cfg(feature = "pool")]

use serial_test::serial;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct PoolNode {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    stdin: std::process::ChildStdin,
    id: String,
}

impl PoolNode {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pool_node"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdout = BufReader::new(child.stdout.take().unwrap());
        let stdin = child.stdin.take().unwrap();

        let mut node = Self {
            child,
            stdout,
            stdin,
            id: String::new(),
        };

        // Wait for ready message
        let status = node.read_status(Duration::from_secs(30))?;
        node.id = status
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(node)
    }

    fn send(&mut self, cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
        writeln!(self.stdin, "{}", cmd)?;
        self.stdin.flush()?;
        Ok(())
    }

    fn read_status(
        &mut self,
        timeout: Duration,
    ) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
        let start = Instant::now();
        let mut line = String::new();

        while start.elapsed() < timeout {
            line.clear();
            if self.stdout.read_line(&mut line)? > 0 {
                if let Ok(json) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&line)
                {
                    return Ok(json);
                }
            }
        }
        Err("timeout reading status".into())
    }

    fn quit(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.send("quit");
        let _ = self.child.wait();
        Ok(())
    }

    #[allow(dead_code)] // Useful for crash testing scenarios
    fn kill(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.child.kill()?;
        let _ = self.child.wait();
        Ok(())
    }
}

fn cleanup_instances() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".into());

    // Use psql to clean up - simpler than setting up sqlx in the test
    let _ = Command::new("psql")
        .arg(&database_url)
        .arg("-c")
        .arg("DELETE FROM signer_instances")
        .output();
}

#[test]
#[serial]
fn test_single_instance_starts() {
    cleanup_instances();

    let node = PoolNode::spawn().expect("Failed to spawn node");
    assert!(!node.id.is_empty(), "Node should have an ID");

    node.quit().expect("Failed to quit node");
}

#[test]
#[serial]
fn test_two_instances_both_start() {
    cleanup_instances();

    let node1 = PoolNode::spawn().expect("Failed to spawn node1");
    let node2 = PoolNode::spawn().expect("Failed to spawn node2");

    assert!(!node1.id.is_empty());
    assert!(!node2.id.is_empty());
    assert_ne!(node1.id, node2.id);

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
}

#[test]
#[serial]
fn test_three_instances_all_start() {
    cleanup_instances();

    let node1 = PoolNode::spawn().expect("Failed to spawn node1");
    let node2 = PoolNode::spawn().expect("Failed to spawn node2");
    let node3 = PoolNode::spawn().expect("Failed to spawn node3");

    assert!(!node1.id.is_empty());
    assert!(!node2.id.is_empty());
    assert!(!node3.id.is_empty());

    // All IDs should be unique
    assert_ne!(node1.id, node2.id);
    assert_ne!(node2.id, node3.id);
    assert_ne!(node1.id, node3.id);

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
    node3.quit().expect("Failed to quit node3");
}

#[test]
#[serial]
fn test_instance_receives_membership_events() {
    cleanup_instances();

    let mut node1 = PoolNode::spawn().expect("Failed to spawn node1");

    // Start second instance
    let node2 = PoolNode::spawn().expect("Failed to spawn node2");

    // Node1 should receive a join event
    let status = node1
        .read_status(Duration::from_secs(5))
        .expect("Timeout waiting for join event");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        event.starts_with("joined:"),
        "Expected join event, got: {}",
        event
    );

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
}

#[test]
#[serial]
fn test_limit_adjusts_on_join() {
    cleanup_instances();

    let mut node1 = PoolNode::spawn().expect("Failed to spawn node1");

    // With 1 instance and max_total=60, limit should be 60
    node1.send("status").expect("Failed to send status");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let limit1 = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(limit1, 60, "Single instance should have limit 60");

    // Start second instance
    let node2 = PoolNode::spawn().expect("Failed to spawn node2");

    // Wait for membership event and check new limit
    let status = node1
        .read_status(Duration::from_secs(5))
        .expect("Timeout waiting for event");
    let limit2 = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(limit2, 30, "Two instances should each have limit 30");

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
}

#[test]
#[serial]
fn test_limit_adjusts_on_leave() {
    cleanup_instances();

    let mut node1 = PoolNode::spawn().expect("Failed to spawn node1");
    let node2 = PoolNode::spawn().expect("Failed to spawn node2");

    // Wait for node1 to see node2 join
    let _ = node1.read_status(Duration::from_secs(5));

    // Verify limit is 30 (60/2)
    node1.send("status").expect("Failed to send status");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let limit = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(limit, 30);

    // Gracefully shut down node2
    node2.quit().expect("Failed to quit node2");

    // Node1 should receive leave event and limit should go back to 60
    let status = node1
        .read_status(Duration::from_secs(5))
        .expect("Timeout waiting for leave");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert!(event.starts_with("left:"), "Expected leave event");
    let limit = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(limit, 60, "After node2 leaves, node1 should have limit 60");

    node1.quit().expect("Failed to quit node1");
}

#[test]
#[serial]
fn test_acquire_and_release() {
    cleanup_instances();

    let mut node = PoolNode::spawn().expect("Failed to spawn node");

    // Acquire some connections
    node.send("acquire 5").expect("Failed to send acquire");
    let status = node.read_status(Duration::from_secs(10)).expect("Timeout");
    let held = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(held, 5);

    // Release them
    node.send("release").expect("Failed to send release");
    let status = node.read_status(Duration::from_secs(5)).expect("Timeout");
    let held = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(held, 0);

    node.quit().expect("Failed to quit node");
}

#[test]
#[serial]
fn test_work_succeeds() {
    cleanup_instances();

    let mut node = PoolNode::spawn().expect("Failed to spawn node");

    node.send("work").expect("Failed to send work");
    let status = node.read_status(Duration::from_secs(10)).expect("Timeout");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(event, "work_done");

    node.quit().expect("Failed to quit node");
}

#[test]
#[serial]
fn test_five_instances_concurrent_start() {
    cleanup_instances();

    // Start 5 instances as fast as possible
    let nodes: Vec<_> = (0..5)
        .map(|i| PoolNode::spawn().unwrap_or_else(|e| panic!("Failed to spawn node{}: {}", i, e)))
        .collect();

    // All should have started
    assert_eq!(nodes.len(), 5);

    // All should have unique IDs
    let ids: std::collections::HashSet<_> = nodes.iter().map(|n| &n.id).collect();
    assert_eq!(ids.len(), 5, "All instances should have unique IDs");

    // Clean up
    for node in nodes {
        node.quit().expect("Failed to quit node");
    }
}

#[test]
#[serial]
fn test_eviction_when_instance_joins_during_work() {
    cleanup_instances();

    let mut node1 = PoolNode::spawn().expect("Failed to spawn node1");

    // First verify node1 can do actual database work
    node1.send("work").expect("Failed to send work to node1");
    let status = node1
        .read_status(Duration::from_secs(10))
        .expect("Timeout node1 work");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(event, "work_done", "Node1 should do work initially");

    // Node1 acquires connections (more than it will be allowed after node2 joins)
    // With max_total=60, single instance gets limit=60
    // After node2 joins, limit drops to 30 each
    // If node1 holds 40 connections, it will be 10 over limit and should evict on release
    node1.send("acquire 40").expect("Failed to send acquire");
    let status = node1
        .read_status(Duration::from_secs(30))
        .expect("Timeout acquiring");
    let held = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(held, 40, "Node1 should hold 40 connections");

    // Check initial eviction count is 0
    node1.send("status").expect("Failed to send status");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let evicted_before = status.get("evicted").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(evicted_before, 0, "No evictions yet");

    // Node2 joins - limit drops to 30, node1 is now 10 over limit
    let node2 = PoolNode::spawn().expect("Failed to spawn node2");

    // Wait for membership event
    let status = node1
        .read_status(Duration::from_secs(5))
        .expect("Timeout waiting for join");
    let limit = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(limit, 30, "Limit should be 30 after node2 joins");

    // Release connections - should trigger eviction for the 10 over-limit connections
    node1.send("release 20").expect("Failed to send release");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let held_after = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(
        held_after, 20,
        "Node1 should hold 20 connections after releasing 20"
    );

    // Check eviction count - releasing 20 when holding 40 with limit 30 means:
    // First 10 releases are over-limit (40->39->...->31, all evicted)
    // Next 10 releases are at/under limit (30->29->...->21, returned to pool)
    node1.send("status").expect("Failed to send status");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let evicted_after = status.get("evicted").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        evicted_after >= 10,
        "Should have evicted at least 10 connections, got {}",
        evicted_after
    );

    // Node2 should be able to work
    let mut node2 = node2;
    node2.send("work").expect("Failed to send work");
    let status = node2.read_status(Duration::from_secs(10)).expect("Timeout");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(event, "work_done", "Node2 should be able to do work");

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
}

#[test]
#[serial]
fn test_third_instance_can_work_while_others_hold_connections() {
    cleanup_instances();

    // Scenario: Two instances are actively working and trying to acquire MORE
    // connections than available (2x their limit). Tests backpressure mechanism.
    //
    // With max_total=60 and PostgreSQL default max_connections=100:
    // - 2 instances: limit=30 each
    // - Each tries to acquire 50 (simulating high load)
    // - Soft limit should block at 30 each
    //
    // Then node3 joins:
    // - Limits drop to 20 each
    // - Nodes 1&2 are now 10 over their new limit
    // - Node3 should still be able to acquire and work

    let mut node1 = PoolNode::spawn().expect("Failed to spawn node1");
    let mut node2 = PoolNode::spawn().expect("Failed to spawn node2");

    // Wait for node1 to see node2
    let _ = node1.read_status(Duration::from_secs(5));

    // First, verify both nodes can do actual database work
    node1.send("work").expect("Failed to send work to node1");
    let status = node1
        .read_status(Duration::from_secs(10))
        .expect("Timeout node1 work");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(event, "work_done", "Node1 should do work initially");

    node2.send("work").expect("Failed to send work to node2");
    let status = node2
        .read_status(Duration::from_secs(10))
        .expect("Timeout node2 work");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(event, "work_done", "Node2 should do work initially");

    // Both nodes try to acquire MORE than their limit (50 > 30)
    // The soft limit should cap them at 30 each
    node1
        .send("acquire 50")
        .expect("Failed to send acquire to node1");
    let status = node1
        .read_status(Duration::from_secs(30))
        .expect("Timeout node1 acquire");
    let held1 = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit1 = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    let capped1 = status
        .get("capped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert_eq!(limit1, 30, "Node1 limit should be 30");
    assert_eq!(held1, 30, "Node1 should be capped at limit (30), not 50");
    assert!(capped1, "Node1 should report being capped by soft limit");

    node2
        .send("acquire 50")
        .expect("Failed to send acquire to node2");
    let status = node2
        .read_status(Duration::from_secs(30))
        .expect("Timeout node2 acquire");
    let held2 = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    let capped2 = status
        .get("capped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert_eq!(held2, 30, "Node2 should be capped at limit (30), not 50");
    assert!(capped2, "Node2 should report being capped by soft limit");

    // Node3 joins - limits drop to 20, nodes 1&2 are 10 over each
    let mut node3 = PoolNode::spawn().expect("Failed to spawn node3");

    // Wait for membership events
    let _ = node1.read_status(Duration::from_secs(5));
    let _ = node2.read_status(Duration::from_secs(5));

    // Verify limits dropped
    node1.send("status").expect("Failed to send status");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let limit = status.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(limit, 20, "Limit should be 20 with 3 instances");

    // Node3 should be able to do work despite nodes 1&2 being over-limit
    // PostgreSQL has headroom: 100 - 60 = 40 connections available
    node3.send("work").expect("Failed to send work to node3");
    let status = node3
        .read_status(Duration::from_secs(10))
        .expect("Timeout node3 work");
    let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(event, "work_done", "Node3 should be able to do work");

    // Node3 can acquire up to its limit
    node3
        .send("acquire 20")
        .expect("Failed to send acquire to node3");
    let status = node3
        .read_status(Duration::from_secs(30))
        .expect("Timeout node3 acquire");
    let held3 = status.get("held").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(held3, 20, "Node3 should hold its full limit (20)");

    // Release from nodes 1&2 - should trigger eviction
    node1.send("release 15").expect("Failed to send release");
    let _ = node1.read_status(Duration::from_secs(5));
    node2.send("release 15").expect("Failed to send release");
    let _ = node2.read_status(Duration::from_secs(5));

    // Check eviction happened on both nodes
    node1.send("status").expect("Failed to send status");
    let status = node1.read_status(Duration::from_secs(5)).expect("Timeout");
    let evicted1 = status.get("evicted").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(evicted1 >= 10, "Node1 should have evicted at least 10");

    node2.send("status").expect("Failed to send status");
    let status = node2.read_status(Duration::from_secs(5)).expect("Timeout");
    let evicted2 = status.get("evicted").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(evicted2 >= 10, "Node2 should have evicted at least 10");

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
    node3.quit().expect("Failed to quit node3");
}

#[test]
#[serial]
fn test_all_instances_can_work_at_every_stage() {
    cleanup_instances();

    // Comprehensive test: verify ALL instances can execute real database queries
    // at every stage of the cluster lifecycle.
    //
    // Key insight: Each "work" command does acquire → SELECT 1 → release.
    // By doing MORE work tasks than the connection limit, we test:
    // 1. Connection pool reuse (connections returned and reacquired)
    // 2. Eviction works when limits shrink (new instance joins)
    // 3. All instances can work even when limits change dynamically
    //
    // With max_total=60:
    // - 1 instance: limit=60, we do 80 work tasks → tests reuse
    // - 2 instances: limit=30 each, we do 50 work tasks each → tests reuse
    // - 3 instances: limit=20 each, we do 40 work tasks each → tests reuse + eviction

    // Helper to do N work tasks and verify all succeed
    fn do_work_tasks(node: &mut PoolNode, count: usize, node_name: &str) {
        for i in 0..count {
            node.send("work")
                .expect(&format!("Failed to send work {} to {}", i, node_name));
            let status = node
                .read_status(Duration::from_secs(10))
                .expect(&format!("Timeout {} work {}", node_name, i));
            let event = status.get("event").and_then(|v| v.as_str()).unwrap_or("");
            assert_eq!(
                event, "work_done",
                "{} work {} failed: got event '{}'",
                node_name, i, event
            );
        }
    }

    // Stage 1: Single instance, limit=60, do 80 work tasks (tests reuse)
    let mut node1 = PoolNode::spawn().expect("Failed to spawn node1");
    do_work_tasks(&mut node1, 80, "node1");

    // Stage 2: Second instance joins, limits=30 each, do 50 tasks each
    let mut node2 = PoolNode::spawn().expect("Failed to spawn node2");

    // Wait for membership event
    let _ = node1.read_status(Duration::from_secs(5));

    // Both do work exceeding their new limit (50 > 30)
    do_work_tasks(&mut node1, 50, "node1");
    do_work_tasks(&mut node2, 50, "node2");

    // Stage 3: Third instance joins, limits=20 each, do 40 tasks each
    let mut node3 = PoolNode::spawn().expect("Failed to spawn node3");

    // Wait for membership events
    let _ = node1.read_status(Duration::from_secs(5));
    let _ = node2.read_status(Duration::from_secs(5));

    // All three do work exceeding their new limit (40 > 20)
    do_work_tasks(&mut node1, 40, "node1");
    do_work_tasks(&mut node2, 40, "node2");
    do_work_tasks(&mut node3, 40, "node3");

    // Stage 4: One instance leaves, limits=30 each, remaining two do 50 tasks each
    node3.quit().expect("Failed to quit node3");

    // Wait for leave event
    let _ = node1.read_status(Duration::from_secs(5));
    let _ = node2.read_status(Duration::from_secs(5));

    // Remaining nodes do work exceeding their new limit
    do_work_tasks(&mut node1, 50, "node1");
    do_work_tasks(&mut node2, 50, "node2");

    node1.quit().expect("Failed to quit node1");
    node2.quit().expect("Failed to quit node2");
}
