// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Common consensus evaluation harness.
//!
//! This module is deliberately protocol-independent.  It measures lifecycle
//! events that every comparison can expose through the existing consensus API:
//! submission, block inclusion, and sequencing.  Protocol-specific notions
//! such as conflict detection and object release/commit are added by adapters
//! on top of these samples.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, ensure};
use consensus_config::{
    AuthorityIndex, Committee, ConsensusProtocolConfig, NetworkKeyPair, Parameters,
    ProtocolKeyPair, local_committee_and_keys,
};
use consensus_types::block::BlockRef;
use futures::{StreamExt, future::join_all, stream};
use mysten_metrics::{RegistryService, monitored_mpsc::UnboundedReceiver};
use prometheus::Registry;
use tempfile::TempDir;
use typed_store::DBMetrics;

use crate::{
    CommitConsumerArgs, CommittedSubDag, ConsensusAuthority, NetworkType,
    block::VerifiedBlock,
    context::Clock,
    storage::Store,
    transaction::{BlockStatus, NoopTransactionVerifier},
};

use crate::snapper::{
    SNAPPER_OBJECT_ID_LENGTH, SnapperObjectDecision, SnapperObjectKey,
    SnapperResolutionObservation, SnapperResolutionPath, SnapperTransactionEnvelope,
};

#[derive(Clone, Debug)]
struct CommonEvalTransaction {
    id: u64,
    submitter: usize,
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct CommonEvalSample {
    id: u64,
    submitter: usize,
    payload_bytes: usize,
    submitted_at_ms: u64,
    included_at_ms: u64,
    sequenced_at_ms: u64,
    included_block: BlockRef,
    included_round: u32,
    inclusion_latency: Duration,
    sequencing_after_inclusion: Duration,
    end_to_end_latency: Duration,
}

#[derive(Debug)]
struct CommonEvalReport {
    samples: Vec<CommonEvalSample>,
    elapsed: Duration,
    throughput_tps: f64,
    unique_inclusion_blocks: usize,
    inclusion_block_bytes: usize,
}

impl CommonEvalReport {
    fn tx_count(&self) -> usize {
        self.samples.len()
    }

    fn inclusion_block_bytes_per_tx(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.inclusion_block_bytes as f64 / self.samples.len() as f64
    }

    fn inclusion_percentile_ms(&self, percentile: f64) -> f64 {
        duration_percentile_ms(
            self.samples.iter().map(|sample| sample.inclusion_latency),
            percentile,
        )
    }

    fn end_to_end_percentile_ms(&self, percentile: f64) -> f64 {
        duration_percentile_ms(
            self.samples.iter().map(|sample| sample.end_to_end_latency),
            percentile,
        )
    }

    fn print_summary(&self, label: &str) {
        println!();
        println!("=== Common consensus evaluation: {label} ===");
        println!("transactions={}", self.tx_count());
        println!("elapsed_ms={:.3}", self.elapsed.as_secs_f64() * 1000.0);
        println!("throughput_tps={:.3}", self.throughput_tps);
        println!(
            "inclusion_latency_ms_p50={:.3}",
            self.inclusion_percentile_ms(0.50)
        );
        println!(
            "inclusion_latency_ms_p95={:.3}",
            self.inclusion_percentile_ms(0.95)
        );
        println!(
            "inclusion_latency_ms_p99={:.3}",
            self.inclusion_percentile_ms(0.99)
        );
        println!(
            "sequencing_latency_ms_p50={:.3}",
            self.end_to_end_percentile_ms(0.50)
        );
        println!(
            "sequencing_latency_ms_p95={:.3}",
            self.end_to_end_percentile_ms(0.95)
        );
        println!(
            "sequencing_latency_ms_p99={:.3}",
            self.end_to_end_percentile_ms(0.99)
        );
        println!("unique_inclusion_blocks={}", self.unique_inclusion_blocks);
        println!("inclusion_block_bytes={}", self.inclusion_block_bytes);
        println!(
            "inclusion_block_bytes_per_tx={:.3}",
            self.inclusion_block_bytes_per_tx()
        );
    }

    fn print_csv(&self, label: &str) {
        println!();
        println!("# consensus-eval-csv label={label}");
        println!(
            "tx_id,submitter,payload_bytes,submitted_at_ms,included_at_ms,sequenced_at_ms,included_round,inclusion_latency_ms,sequencing_after_inclusion_ms,end_to_end_latency_ms"
        );
        for sample in &self.samples {
            println!(
                "{},{},{},{},{},{},{},{:.3},{:.3},{:.3}",
                sample.id,
                sample.submitter,
                sample.payload_bytes,
                sample.submitted_at_ms,
                sample.included_at_ms,
                sample.sequenced_at_ms,
                sample.included_round,
                sample.inclusion_latency.as_secs_f64() * 1000.0,
                sample.sequencing_after_inclusion.as_secs_f64() * 1000.0,
                sample.end_to_end_latency.as_secs_f64() * 1000.0,
            );
        }
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_millis() as u64
}

fn duration_percentile_ms(durations: impl IntoIterator<Item = Duration>, percentile: f64) -> f64 {
    let mut values = durations
        .into_iter()
        .map(|duration| duration.as_secs_f64() * 1000.0)
        .collect::<Vec<_>>();

    if values.is_empty() {
        return 0.0;
    }

    values.sort_by(f64::total_cmp);
    let rank = ((percentile.clamp(0.0, 1.0) * values.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(values.len() - 1);
    values[rank]
}

/// Produces opaque benchmark transactions.  The encoding intentionally has no
/// Snapper/Mysticeti-FPC/Cuttlefish semantics; protocol adapters will supply
/// their own payloads for conflict/unlock experiments.
fn opaque_workload(
    transaction_count: usize,
    payload_bytes: usize,
    authority_count: usize,
) -> Vec<CommonEvalTransaction> {
    assert!(
        payload_bytes >= 16,
        "evaluation payload must be at least 16 bytes"
    );
    assert!(authority_count > 0);

    (0..transaction_count)
        .map(|index| {
            let mut payload = vec![0u8; payload_bytes];
            payload[..8].copy_from_slice(b"CEVAL001");
            payload[8..16].copy_from_slice(&(index as u64).to_le_bytes());

            // Give equal-sized transactions distinct bodies while keeping the
            // workload deterministic across systems.
            for (offset, byte) in payload[16..].iter_mut().enumerate() {
                *byte = (index as u64).wrapping_mul(31).wrapping_add(offset as u64) as u8;
            }

            CommonEvalTransaction {
                id: index as u64,
                submitter: index % authority_count,
                payload,
            }
        })
        .collect()
}

/// Executes the same transaction schedule against any consensus implementation
/// exposing ConsensusAuthority/TransactionClient.
///
/// `max_in_flight` is the closed-loop offered-load control for the initial
/// harness.  A later load-sweep step will add an open-loop target-TPS scheduler.
async fn run_common_workload(
    authorities: &[ConsensusAuthority],
    transactions: Vec<CommonEvalTransaction>,
    max_in_flight: usize,
    per_transaction_timeout: Duration,
) -> Result<CommonEvalReport> {
    ensure!(
        !authorities.is_empty(),
        "evaluation requires at least one authority"
    );
    ensure!(max_in_flight > 0, "max_in_flight must be positive");

    let clients = authorities
        .iter()
        .map(ConsensusAuthority::transaction_client)
        .collect::<Vec<_>>();

    let workload_start = Instant::now();

    let results = stream::iter(transactions.into_iter().map(|transaction| {
        let client = clients[transaction.submitter].clone();

        async move {
            let payload_bytes = transaction.payload.len();
            let submitted_at = Instant::now();
            let submitted_at_ms = unix_time_ms();

            let submit_result = tokio::time::timeout(
                per_transaction_timeout,
                client.submit(vec![transaction.payload]),
            )
            .await
            .with_context(|| {
                format!(
                    "timed out waiting for transaction {} to be included",
                    transaction.id
                )
            })?;

            let (included_block, transaction_indices, status_receiver) = submit_result
                .with_context(|| format!("failed to submit transaction {}", transaction.id))?;

            ensure!(
                transaction_indices.len() == 1,
                "transaction {} expected one transaction index, got {:?}",
                transaction.id,
                transaction_indices
            );

            let included_at = Instant::now();
            let included_at_ms = unix_time_ms();

            let status = tokio::time::timeout(per_transaction_timeout, status_receiver)
                .await
                .with_context(|| {
                    format!(
                        "timed out waiting for transaction {} block {} to be sequenced",
                        transaction.id, included_block
                    )
                })?
                .with_context(|| {
                    format!(
                        "status channel closed for transaction {} block {}",
                        transaction.id, included_block
                    )
                })?;

            match status {
                BlockStatus::Sequenced(block_ref) => {
                    ensure!(
                        block_ref == included_block,
                        "transaction {} was included in {} but sequenced status named {}",
                        transaction.id,
                        included_block,
                        block_ref
                    );
                }
                BlockStatus::GarbageCollected(block_ref) => {
                    return Err(anyhow!(
                        "transaction {} inclusion block {} was garbage collected",
                        transaction.id,
                        block_ref
                    ));
                }
            }

            let sequenced_at = Instant::now();
            let sequenced_at_ms = unix_time_ms();

            Ok::<_, anyhow::Error>(CommonEvalSample {
                id: transaction.id,
                submitter: transaction.submitter,
                payload_bytes,
                submitted_at_ms,
                included_at_ms,
                sequenced_at_ms,
                included_block,
                included_round: included_block.round,
                inclusion_latency: included_at.duration_since(submitted_at),
                sequencing_after_inclusion: sequenced_at.duration_since(included_at),
                end_to_end_latency: sequenced_at.duration_since(submitted_at),
            })
        }
    }))
    .buffer_unordered(max_in_flight)
    .collect::<Vec<_>>()
    .await;

    let workload_elapsed = workload_start.elapsed();

    let mut samples = Vec::with_capacity(results.len());
    for result in results {
        samples.push(result?);
    }
    samples.sort_by_key(|sample| sample.id);

    // Recover payload sizes from the deterministic workload header contract.
    // All payloads in the common smoke workload have equal size.  Protocol
    // adapters will populate this field directly when they add custom payloads.
    //
    // The initial harness only uses this field for CSV readability; block-byte
    // accounting below is taken from the actual serialized blocks.
    let mut unique_blocks = BTreeSet::new();
    for sample in &samples {
        unique_blocks.insert((sample.submitter, sample.included_block));
    }

    let mut inclusion_block_bytes = 0usize;
    for (submitter, block_ref) in unique_blocks.iter().copied() {
        let store = authorities[submitter].store();
        let mut blocks = store
            .read_blocks(&[block_ref])
            .with_context(|| format!("failed reading inclusion block {block_ref}"))?;
        let block: VerifiedBlock = blocks
            .pop()
            .flatten()
            .with_context(|| format!("missing inclusion block {block_ref} from store"))?;
        inclusion_block_bytes += block.serialized().len();
    }

    let throughput_tps = if workload_elapsed.is_zero() {
        0.0
    } else {
        samples.len() as f64 / workload_elapsed.as_secs_f64()
    };

    Ok(CommonEvalReport {
        samples,
        elapsed: workload_elapsed,
        throughput_tps,
        unique_inclusion_blocks: unique_blocks.len(),
        inclusion_block_bytes,
    })
}

#[test]
fn consensus_eval_percentile_helper() {
    let durations = [1, 2, 3, 4, 100]
        .into_iter()
        .map(Duration::from_millis)
        .collect::<Vec<_>>();

    assert_eq!(duration_percentile_ms(durations.clone(), 0.50), 3.0);
    assert_eq!(duration_percentile_ms(durations.clone(), 0.95), 100.0);
    assert_eq!(duration_percentile_ms(durations, 0.99), 100.0);
}

/// Protocol-independent live smoke test.
///
/// It intentionally uses opaque payloads and therefore does not exercise any
/// Snapper-specific code.  Its job is to validate that the exact same workload
/// runner can later be reused by Snapper, Mysticeti-FPC, and Cuttlefish
/// adapters.
#[tokio::test(flavor = "current_thread")]
#[ignore = "starts a live four-validator consensus network"]
async fn consensus_eval_common_smoke() {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;
    const TRANSACTIONS: usize = 64;
    const PAYLOAD_BYTES: usize = 256;
    const MAX_IN_FLIGHT: usize = 16;

    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);
    let protocol_config = ConsensusProtocolConfig::for_testing();

    let temp_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().unwrap())
        .collect::<Vec<_>>();

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut _commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let (authority, commit_receiver) = make_eval_authority(
            index,
            &temp_dirs[index.value()],
            committee.clone(),
            keypairs.clone(),
            protocol_config.clone(),
        )
        .await;
        authorities.push(authority);
        _commit_receivers.push(commit_receiver);
    }

    let transactions = opaque_workload(TRANSACTIONS, PAYLOAD_BYTES, AUTHORITIES);
    let report = run_common_workload(
        &authorities,
        transactions,
        MAX_IN_FLIGHT,
        Duration::from_secs(30),
    )
    .await
    .expect("common consensus evaluation workload should complete");

    ensure_report_is_sane(&report, TRANSACTIONS);
    report.print_summary("common-smoke");
    report.print_csv("common-smoke");

    for authority in authorities {
        authority.stop().await;
    }
}

/// Snapper-specific comparison adapter.
///
/// The common comparison starts at the client boundary: the timestamp is taken
/// immediately before submitting a second transaction that conflicts with one
/// already included in the DAG. Future Mysticeti-FPC and Cuttlefish adapters
/// must use the same start point.
#[tokio::test(flavor = "current_thread")]
#[ignore = "starts a live four-validator Snapper conflict workload"]
async fn snapper_eval_conflict_smoke() {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;
    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);
    let protocol_config = ConsensusProtocolConfig::for_testing();
    assert!(protocol_config.transaction_voting_enabled());

    let temp_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().unwrap())
        .collect::<Vec<_>>();

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut _commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let (authority, commit_receiver) = make_eval_authority(
            index,
            &temp_dirs[index.value()],
            committee.clone(),
            keypairs.clone(),
            protocol_config.clone(),
        )
        .await;
        authorities.push(authority);
        _commit_receivers.push(commit_receiver);
    }

    let object = SnapperObjectKey {
        object_id: [0x5B; SNAPPER_OBJECT_ID_LENGTH],
        version: 0,
    };

    // tx0 is already in the DAG when tx1, which conflicts on the same object
    // version, is injected through a different validator.
    let first_bytes = SnapperTransactionEnvelope::new(vec![object], vec![0xA1; 256]).encode();
    let first_id = SnapperTransactionEnvelope::transaction_id(&first_bytes);
    let (first_block, _, _first_status) = authorities[0]
        .transaction_client()
        .submit(vec![first_bytes])
        .await
        .expect("first Snapper transaction should be included");

    let conflict_injected_at_ms = unix_time_ms();

    let second_bytes = SnapperTransactionEnvelope::new(vec![object], vec![0xB2; 256]).encode();
    let second_id = SnapperTransactionEnvelope::transaction_id(&second_bytes);
    let (second_block, _, _second_status) = authorities[1]
        .transaction_client()
        .submit(vec![second_bytes])
        .await
        .expect("conflicting Snapper transaction should be included");

    let conflict_included_at_ms = unix_time_ms();

    let observations =
        wait_for_snapper_resolutions(&authorities, object, Duration::from_secs(30)).await;

    let expected_decision = observations[0].decision;
    assert!(
        observations
            .iter()
            .all(|observation| observation.decision == expected_decision),
        "Snapper validators disagreed on object resolution: {observations:#?}"
    );

    assert!(
        observations
            .iter()
            .all(|observation| observation.timestamp_ms >= conflict_injected_at_ms),
        "a Snapper resolution was recorded before conflict injection: {observations:#?}"
    );

    println!();
    println!("=== Snapper conflict adapter ===");
    println!("first_tx={first_id:?}");
    println!("conflicting_tx={second_id:?}");
    println!("first_included_round={}", first_block.round);
    println!("conflict_injected_at_ms={conflict_injected_at_ms}");
    println!("conflict_included_round={}", second_block.round);
    println!("conflict_included_at_ms={conflict_included_at_ms}");
    println!("decision={expected_decision:?}");
    println!();
    println!(
        "authority,resolution_path,resolution_round,rounds_from_conflict_inclusion,resolution_at_ms,inject_to_resolution_ms,inclusion_to_resolution_ms"
    );

    for (authority, observation) in observations.iter().enumerate() {
        let inject_latency_ms = observation
            .timestamp_ms
            .saturating_sub(conflict_injected_at_ms);
        let inclusion_latency_ms = observation
            .timestamp_ms
            .saturating_sub(conflict_included_at_ms);
        let round_latency = observation.round.saturating_sub(second_block.round);

        println!(
            "{authority},{:?},{},{},{},{},{}",
            observation.path,
            observation.round,
            round_latency,
            observation.timestamp_ms,
            inject_latency_ms,
            inclusion_latency_ms,
        );
    }

    for authority in authorities {
        authority.stop().await;
    }
}

async fn wait_for_snapper_resolutions(
    authorities: &[ConsensusAuthority],
    object: SnapperObjectKey,
    max_wait: Duration,
) -> Vec<SnapperResolutionObservation> {
    let deadline = Instant::now() + max_wait;

    loop {
        let observations = authorities
            .iter()
            .map(|authority| authority.snapper_resolution_observation(&object))
            .collect::<Vec<_>>();

        if observations.iter().all(Option::is_some) {
            return observations.into_iter().map(Option::unwrap).collect();
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for Snapper resolution of {object:?}; current={observations:?}"
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Controlled live Snapper split experiment.
///
/// `SNAPPER_SPLIT=3-1` gives the threshold/univalent case at n=4: one
/// candidate is initially injected at three validators and the other at one.
/// `SNAPPER_SPLIT=2-2` gives the bivalent case.
///
/// We intentionally do not use 4-0 as a main unlocking data point: with no
/// conflicting supporter it is essentially the uncontended case rather than
/// an unlocking experiment.
#[tokio::test(flavor = "current_thread")]
#[ignore = "evaluation-only controlled Snapper split experiment"]
async fn snapper_vote_split_smoke() {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;

    let split = std::env::var("SNAPPER_SPLIT").unwrap_or_else(|_| "2-2".to_string());
    let (split_a, split_b) = match split.as_str() {
        "3-1" => (3usize, 1usize),
        "2-2" => (2usize, 2usize),
        other => {
            panic!("unsupported SNAPPER_SPLIT={other}; use 3-1 or 2-2 for the unlocking experiment")
        }
    };

    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);
    let protocol_config = ConsensusProtocolConfig::for_testing();
    assert!(protocol_config.transaction_voting_enabled());

    let temp_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().unwrap())
        .collect::<Vec<_>>();

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut _commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let (authority, commit_receiver) = make_eval_authority(
            index,
            &temp_dirs[index.value()],
            committee.clone(),
            keypairs.clone(),
            protocol_config.clone(),
        )
        .await;
        authorities.push(authority);
        _commit_receivers.push(commit_receiver);
    }

    let object = SnapperObjectKey {
        object_id: [0x6C; SNAPPER_OBJECT_ID_LENGTH],
        version: 0,
    };

    let tx_a_bytes = SnapperTransactionEnvelope::new(vec![object], vec![0xA5; 256]).encode();
    let tx_b_bytes = SnapperTransactionEnvelope::new(vec![object], vec![0xB6; 256]).encode();

    let tx_a = SnapperTransactionEnvelope::transaction_id(&tx_a_bytes);
    let tx_b = SnapperTransactionEnvelope::transaction_id(&tx_b_bytes);

    let conflict_injected_at_ms = unix_time_ms();

    let submissions = (0..AUTHORITIES).map(|authority_index| {
        let client = authorities[authority_index].transaction_client();
        let bytes = if authority_index < split_a {
            tx_a_bytes.clone()
        } else {
            tx_b_bytes.clone()
        };

        async move {
            client
                .submit(vec![bytes])
                .await
                .expect("split transaction should be included")
                .0
        }
    });

    let included_blocks = join_all(submissions).await;
    let min_included_round = included_blocks
        .iter()
        .map(|block| block.round)
        .min()
        .unwrap();
    let max_included_round = included_blocks
        .iter()
        .map(|block| block.round)
        .max()
        .unwrap();

    let observations =
        wait_for_snapper_resolutions(&authorities, object, Duration::from_secs(30)).await;

    let decision = observations[0].decision;
    assert!(
        observations
            .iter()
            .all(|observation| observation.decision == decision),
        "validators disagreed on Snapper decision: {observations:#?}"
    );

    let fast_count = observations
        .iter()
        .filter(|observation| observation.path == SnapperResolutionPath::Fast)
        .count();
    let anchor_count = observations
        .iter()
        .filter(|observation| observation.path == SnapperResolutionPath::CommittedAnchor)
        .count();

    let decision_commit_a = usize::from(decision == SnapperObjectDecision::Commit(tx_a));
    let decision_commit_b = usize::from(decision == SnapperObjectDecision::Commit(tx_b));
    let decision_release = usize::from(decision == SnapperObjectDecision::Release);

    assert_eq!(
        decision_commit_a + decision_commit_b + decision_release,
        1,
        "unexpected Snapper decision {decision:?}"
    );

    let min_resolution_round = observations
        .iter()
        .map(|observation| observation.round)
        .min()
        .unwrap();
    let max_resolution_round = observations
        .iter()
        .map(|observation| observation.round)
        .max()
        .unwrap();
    let resolution_at_ms = observations
        .iter()
        .map(|observation| observation.timestamp_ms)
        .max()
        .unwrap();

    let conflict_to_resolution_ms = resolution_at_ms.saturating_sub(conflict_injected_at_ms);

    println!();
    println!("=== Snapper vote split ===");
    println!("split_a={split_a}");
    println!("split_b={split_b}");
    println!("min_included_round={min_included_round}");
    println!("max_included_round={max_included_round}");
    println!("decision_commit_a={decision_commit_a}");
    println!("decision_commit_b={decision_commit_b}");
    println!("decision_release={decision_release}");
    println!("fast_count={fast_count}");
    println!("anchor_count={anchor_count}");
    println!("min_resolution_round={min_resolution_round}");
    println!("max_resolution_round={max_resolution_round}");
    println!("conflict_to_resolution_ms={conflict_to_resolution_ms}");
    println!();

    for authority in authorities {
        authority.stop().await;
    }
}

/// Step 7A: mechanism-level parallel-certification benchmark for one
/// uncontested mixed transaction. Certification and ordering both advance from
/// the same live Mysticeti DAG; the mixed transaction is forbidden from the
/// consensusless fast-finalization route.
#[tokio::test(flavor = "current_thread")]
#[ignore = "starts a live four-validator parallel-certification benchmark"]
async fn snapper_parallel_certification_smoke() {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;
    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);
    let protocol_config = ConsensusProtocolConfig::for_testing();
    assert!(protocol_config.transaction_voting_enabled());

    let temp_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().unwrap())
        .collect::<Vec<_>>();
    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut _commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let (authority, commit_receiver) = make_eval_authority(
            index,
            &temp_dirs[index.value()],
            committee.clone(),
            keypairs.clone(),
            protocol_config.clone(),
        )
        .await;
        authorities.push(authority);
        _commit_receivers.push(commit_receiver);
    }

    let object = SnapperObjectKey {
        object_id: [0x71; SNAPPER_OBJECT_ID_LENGTH],
        version: 0,
    };
    let bytes = SnapperTransactionEnvelope::new_mixed(vec![object], vec![0x72; 256]).encode();
    let tx = SnapperTransactionEnvelope::transaction_id(&bytes);

    let submitted_at_ms = unix_time_ms();
    let (included_block, indices, status_receiver) = authorities[0]
        .transaction_client()
        .submit(vec![bytes])
        .await
        .expect("mixed Snapper transaction should be included");
    assert_eq!(indices.len(), 1);
    let included_at_ms = unix_time_ms();

    let cert_future = async {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if authorities
                .iter()
                .any(|authority| authority.snapper_has_transaction_certificate(tx))
            {
                break unix_time_ms();
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for certificate"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };

    let order_future = async {
        let status = tokio::time::timeout(Duration::from_secs(30), status_receiver)
            .await
            .expect("timed out waiting for sequencing")
            .expect("status channel closed");
        match status {
            BlockStatus::Sequenced(block_ref) => assert_eq!(block_ref, included_block),
            BlockStatus::GarbageCollected(block_ref) => {
                panic!("mixed transaction inclusion block was GCed: {block_ref}")
            }
        }
        unix_time_ms()
    };

    let (certificate_seen_at_ms, ordered_at_ms) = tokio::join!(cert_future, order_future);

    let observations =
        wait_for_snapper_resolutions(&authorities, object, Duration::from_secs(30)).await;

    assert!(
        observations.iter().all(|o| {
            o.decision == SnapperObjectDecision::Commit(tx)
                && o.path == SnapperResolutionPath::CommittedAnchor
        }),
        "mixed tx must finalize only from a committed anchor: {observations:#?}"
    );

    let finalized_at_ms = observations.iter().map(|o| o.timestamp_ms).max().unwrap();
    let finalization_round = observations.iter().map(|o| o.round).max().unwrap();

    assert!(certificate_seen_at_ms <= finalized_at_ms);
    assert!(ordered_at_ms <= finalized_at_ms);

    println!();
    println!("=== Snapper Step 7A: parallel certification ===");
    println!("protocol=snapper");
    println!("transaction_kind=mixed");
    println!("submitted_at_ms={submitted_at_ms}");
    println!("included_at_ms={included_at_ms}");
    println!("certificate_seen_at_ms={certificate_seen_at_ms}");
    println!("ordered_at_ms={ordered_at_ms}");
    println!("finalized_at_ms={finalized_at_ms}");
    println!("included_round={}", included_block.round);
    println!("finalization_round={finalization_round}");
    println!(
        "submit_to_inclusion_ms={}",
        included_at_ms.saturating_sub(submitted_at_ms)
    );
    println!(
        "submit_to_certificate_ms={}",
        certificate_seen_at_ms.saturating_sub(submitted_at_ms)
    );
    println!(
        "submit_to_order_ms={}",
        ordered_at_ms.saturating_sub(submitted_at_ms)
    );
    println!(
        "submit_to_finalize_ms={}",
        finalized_at_ms.saturating_sub(submitted_at_ms)
    );
    println!(
        "certificate_order_delta_ms={}",
        certificate_seen_at_ms.abs_diff(ordered_at_ms)
    );
    println!(
        "finalize_after_both_ms={}",
        finalized_at_ms.saturating_sub(certificate_seen_at_ms.max(ordered_at_ms))
    );
    println!();

    for authority in authorities {
        authority.stop().await;
    }
}

/// Step 7B: sequential certify-then-order control.
///
/// The same live four-validator Mysticeti network is used as in Step 7A.
/// First, a Snapper transaction is injected only to drive the certification
/// mechanism. The ordering phase is deliberately not admitted until a
/// transaction certificate is observed. At that point an opaque ordering
/// marker of the same serialized size is submitted to Mysticeti and we wait
/// for that marker's inclusion block to be sequenced.
///
/// The marker is an evaluation device: it represents the point at which a
/// certify-then-order design would admit the now-certified mixed transaction
/// to consensus. We therefore compare "both prerequisites ready":
///   Step 7A: max(certificate, ordering)
///   Step 7B: certificate, then ordering.
///
/// This is a controlled mechanism comparison, not an implementation of the
/// historical Sui Quorum Driver.
#[tokio::test(flavor = "current_thread")]
#[ignore = "starts a live four-validator sequential certify-then-order benchmark"]
async fn snapper_sequential_certify_then_order_smoke() {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;

    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);

    let protocol_config = ConsensusProtocolConfig::for_testing();
    assert!(protocol_config.transaction_voting_enabled());

    let temp_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().unwrap())
        .collect::<Vec<_>>();

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut _commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let (authority, commit_receiver) = make_eval_authority(
            index,
            &temp_dirs[index.value()],
            committee.clone(),
            keypairs.clone(),
            protocol_config.clone(),
        )
        .await;

        authorities.push(authority);
        _commit_receivers.push(commit_receiver);
    }

    let object = SnapperObjectKey {
        object_id: [0x81; SNAPPER_OBJECT_ID_LENGTH],
        version: 0,
    };

    let certification_bytes =
        SnapperTransactionEnvelope::new_mixed(vec![object], vec![0x82; 256]).encode();

    let tx = SnapperTransactionEnvelope::transaction_id(&certification_bytes);

    let serialized_tx_bytes = certification_bytes.len();

    let submitted_at_ms = unix_time_ms();

    let (certification_included_block, certification_indices, _certification_status_receiver) =
        authorities[0]
            .transaction_client()
            .submit(vec![certification_bytes])
            .await
            .expect("certification carrier should be included");

    assert_eq!(certification_indices.len(), 1);

    let certification_included_at_ms = unix_time_ms();

    let certificate_deadline = Instant::now() + Duration::from_secs(30);

    let certificate_seen_at_ms = loop {
        if authorities
            .iter()
            .any(|authority| authority.snapper_has_transaction_certificate(tx))
        {
            break unix_time_ms();
        }

        assert!(
            Instant::now() < certificate_deadline,
            "timed out waiting for sequential-control certificate"
        );

        tokio::time::sleep(Duration::from_millis(1)).await;
    };

    let ordering_admitted_at_ms = unix_time_ms();

    assert!(
        ordering_admitted_at_ms >= certificate_seen_at_ms,
        "ordering was admitted before certification completed"
    );

    let mut ordering_marker = vec![0x83; serialized_tx_bytes.max(16)];
    ordering_marker[..8].copy_from_slice(b"SEQORD01");

    let (ordering_included_block, ordering_indices, ordering_status_receiver) = authorities[0]
        .transaction_client()
        .submit(vec![ordering_marker])
        .await
        .expect("ordering marker should be included");

    assert_eq!(ordering_indices.len(), 1);

    let ordering_included_at_ms = unix_time_ms();

    let status = tokio::time::timeout(Duration::from_secs(30), ordering_status_receiver)
        .await
        .expect("timed out waiting for sequential ordering marker")
        .expect("ordering marker status channel closed");

    match status {
        BlockStatus::Sequenced(block_ref) => {
            assert_eq!(
                block_ref, ordering_included_block,
                "sequenced block differs from ordering-marker inclusion block"
            );
        }
        BlockStatus::GarbageCollected(block_ref) => {
            panic!("sequential ordering-marker inclusion block was garbage collected: {block_ref}");
        }
    }

    let ordered_at_ms = unix_time_ms();
    let both_ready_at_ms = ordered_at_ms;

    assert!(
        certificate_seen_at_ms <= ordering_admitted_at_ms
            && ordering_admitted_at_ms <= ordering_included_at_ms
            && ordering_included_at_ms <= ordered_at_ms,
        "sequential phase timestamps are out of order"
    );

    println!();
    println!("=== Snapper Step 7B: sequential certify-then-order control ===");
    println!("protocol=sequential-control");
    println!("transaction_kind=mixed");
    println!("ordering_gate=after_certificate");
    println!("ordering_marker_bytes={}", serialized_tx_bytes);
    println!("submitted_at_ms={submitted_at_ms}");
    println!("certification_included_at_ms={certification_included_at_ms}");
    println!("certificate_seen_at_ms={certificate_seen_at_ms}");
    println!("ordering_admitted_at_ms={ordering_admitted_at_ms}");
    println!("ordering_included_at_ms={ordering_included_at_ms}");
    println!("ordered_at_ms={ordered_at_ms}");
    println!("both_ready_at_ms={both_ready_at_ms}");
    println!(
        "certification_included_round={}",
        certification_included_block.round
    );
    println!("ordering_included_round={}", ordering_included_block.round);
    println!(
        "submit_to_certification_inclusion_ms={}",
        certification_included_at_ms.saturating_sub(submitted_at_ms)
    );
    println!(
        "submit_to_certificate_ms={}",
        certificate_seen_at_ms.saturating_sub(submitted_at_ms)
    );
    println!(
        "certification_inclusion_to_certificate_ms={}",
        certificate_seen_at_ms.saturating_sub(certification_included_at_ms)
    );
    println!(
        "certificate_to_ordering_admission_ms={}",
        ordering_admitted_at_ms.saturating_sub(certificate_seen_at_ms)
    );
    println!(
        "certificate_to_ordering_inclusion_ms={}",
        ordering_included_at_ms.saturating_sub(certificate_seen_at_ms)
    );
    println!(
        "certificate_to_order_ms={}",
        ordered_at_ms.saturating_sub(certificate_seen_at_ms)
    );
    println!(
        "ordering_admission_to_inclusion_ms={}",
        ordering_included_at_ms.saturating_sub(ordering_admitted_at_ms)
    );
    println!(
        "ordering_admission_to_order_ms={}",
        ordered_at_ms.saturating_sub(ordering_admitted_at_ms)
    );
    println!(
        "submit_to_both_ready_ms={}",
        both_ready_at_ms.saturating_sub(submitted_at_ms)
    );
    println!();

    for authority in authorities {
        authority.stop().await;
    }
}

fn ensure_report_is_sane(report: &CommonEvalReport, expected_transactions: usize) {
    assert_eq!(report.tx_count(), expected_transactions);
    assert!(report.throughput_tps.is_finite());
    assert!(report.throughput_tps > 0.0);
    assert!(report.unique_inclusion_blocks > 0);
    assert!(report.inclusion_block_bytes > 0);
    assert!(
        report
            .samples
            .iter()
            .all(|sample| sample.included_round > 0)
    );
}

async fn make_eval_authority(
    index: AuthorityIndex,
    db_dir: &TempDir,
    committee: Committee,
    keypairs: Vec<(NetworkKeyPair, ProtocolKeyPair)>,
    protocol_config: ConsensusProtocolConfig,
) -> (ConsensusAuthority, UnboundedReceiver<CommittedSubDag>) {
    let registry = Registry::new();
    let parameters = Parameters {
        db_path: db_dir.path().to_path_buf(),
        dag_state_cached_rounds: 5,
        commit_sync_parallel_fetches: 2,
        commit_sync_batch_size: 3,
        sync_last_known_own_block_timeout: Duration::from_millis(2_000),
        ..Default::default()
    };

    let protocol_keypair = keypairs[index].1.clone();
    let network_keypair = keypairs[index].0.clone();
    let (commit_consumer, commit_receiver) = CommitConsumerArgs::new(0, 0);

    let authority = ConsensusAuthority::start(
        NetworkType::Tonic,
        0,
        committee,
        parameters,
        protocol_config,
        Some(protocol_keypair),
        network_keypair,
        Arc::new(Clock::default()),
        Arc::new(NoopTransactionVerifier {}),
        commit_consumer,
        registry,
        0,
        None,
    )
    .await;

    (authority, commit_receiver)
}
