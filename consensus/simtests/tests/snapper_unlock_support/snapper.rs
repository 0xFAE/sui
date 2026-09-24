use consensus_core::snapper::{
    SNAPPER_OBJECT_ID_LENGTH, SnapperObjectDecision, SnapperObjectKey, SnapperObjectStance,
    SnapperResolutionObservation, SnapperResolutionPath, SnapperTransactionEnvelope,
    SnapperTransactionId,
};
use consensus_simtests::node::AuthorityNode;
use tokio::time::{Instant, sleep};

use super::common::{AUTHORITIES, MAX_WAIT, Scenario, ms, network_profile, start_authorities};

async fn wait_for_ack_precondition(
    authorities: &[AuthorityNode],
    object: SnapperObjectKey,
    transaction: SnapperTransactionId,
    required_acks: usize,
) {
    let deadline = Instant::now() + MAX_WAIT;
    loop {
        let ack_count = authorities
            .iter()
            .filter(|authority| {
                authority.snapper_own_stance(&object)
                    == Some(SnapperObjectStance::Transaction(transaction))
            })
            .count();
        let has_certificate = authorities
            .iter()
            .any(|authority| authority.snapper_has_transaction_certificate(transaction));

        if ack_count >= required_acks && !has_certificate {
            return;
        }
        assert!(
            !has_certificate,
            "post-ACK precondition missed: certificate formed before conflict injection"
        );
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {required_acks} ACKs; current ACK count={ack_count}"
        );
        sleep(std::time::Duration::from_millis(1)).await;
    }
}

async fn wait_for_resolutions(
    authorities: &[AuthorityNode],
    object: SnapperObjectKey,
) -> Vec<SnapperResolutionObservation> {
    let deadline = Instant::now() + MAX_WAIT;
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
        sleep(std::time::Duration::from_millis(1)).await;
    }
}

pub async fn run(scenario: Scenario) {
    let authorities = start_authorities().await;
    let object = SnapperObjectKey {
        object_id: [scenario.tag(); SNAPPER_OBJECT_ID_LENGTH],
        version: 0,
    };
    let tx_a_bytes =
        SnapperTransactionEnvelope::new(vec![object], vec![scenario.tag(); 256]).encode();
    let tx_b_bytes = SnapperTransactionEnvelope::new(
        vec![object],
        vec![scenario.tag().wrapping_add(1); 256],
    )
    .encode();
    let tx_a = SnapperTransactionEnvelope::transaction_id(&tx_a_bytes);
    let tx_b = SnapperTransactionEnvelope::transaction_id(&tx_b_bytes);

    let conflict_start = match scenario {
        Scenario::PreAck => {
            let start = Instant::now();
            let (r0, r1, r2, r3) = tokio::join!(
                authorities[0]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone(), tx_b_bytes.clone()]),
                authorities[1]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone(), tx_b_bytes.clone()]),
                authorities[2]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone(), tx_b_bytes.clone()]),
                authorities[3]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone(), tx_b_bytes.clone()]),
            );
            r0.expect("authority 0 should include bundled conflict");
            r1.expect("authority 1 should include bundled conflict");
            r2.expect("authority 2 should include bundled conflict");
            r3.expect("authority 3 should include bundled conflict");
            start
        }
        Scenario::NoCertificate => {
            let start = Instant::now();
            let (r0, r1, r2, r3) = tokio::join!(
                authorities[0]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone()]),
                authorities[1]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone()]),
                authorities[2]
                    .transaction_client()
                    .submit(vec![tx_b_bytes.clone()]),
                authorities[3]
                    .transaction_client()
                    .submit(vec![tx_b_bytes.clone()]),
            );
            r0.expect("authority 0 should include tx_a");
            r1.expect("authority 1 should include tx_a");
            r2.expect("authority 2 should include tx_b");
            r3.expect("authority 3 should include tx_b");
            start
        }
        Scenario::PostAck => {
            let (r0, r1) = tokio::join!(
                authorities[0]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone()]),
                authorities[1]
                    .transaction_client()
                    .submit(vec![tx_a_bytes.clone()]),
            );
            r0.expect("authority 0 should include tx_a");
            r1.expect("authority 1 should include tx_a");
            wait_for_ack_precondition(&authorities, object, tx_a, 2).await;

            let start = Instant::now();
            let (r2, r3) = tokio::join!(
                authorities[2]
                    .transaction_client()
                    .submit(vec![tx_b_bytes.clone()]),
                authorities[3]
                    .transaction_client()
                    .submit(vec![tx_b_bytes.clone()]),
            );
            r2.expect("authority 2 should include tx_b");
            r3.expect("authority 3 should include tx_b");
            start
        }
    };

    let observations = wait_for_resolutions(&authorities, object).await;
    let resolution_elapsed = conflict_start.elapsed();
    let decision = observations[0].decision;
    assert!(
        observations.iter().all(|o| o.decision == decision),
        "Snapper validators disagreed: {observations:#?}"
    );

    let fast_count = observations
        .iter()
        .filter(|o| o.path == SnapperResolutionPath::Fast)
        .count();
    let anchor_count = observations
        .iter()
        .filter(|o| o.path == SnapperResolutionPath::CommittedAnchor)
        .count();
    let tx_a_certificate_seen = authorities
        .iter()
        .any(|a| a.snapper_has_transaction_certificate(tx_a));
    let tx_b_certificate_seen = authorities
        .iter()
        .any(|a| a.snapper_has_transaction_certificate(tx_b));
    let decision_release = usize::from(decision == SnapperObjectDecision::Release);

    let valid = match scenario {
        Scenario::PreAck => {
            decision_release == 1
                && fast_count == AUTHORITIES
                && anchor_count == 0
                && !tx_a_certificate_seen
                && !tx_b_certificate_seen
        }
        Scenario::NoCertificate => {
            decision_release == 1 && !tx_a_certificate_seen && !tx_b_certificate_seen
        }
        Scenario::PostAck => decision_release == 1 && anchor_count > 0,
    };
    assert!(
        valid,
        "scenario {scenario:?} missed requested path: {observations:#?}"
    );

    let max_resolution_round = observations.iter().map(|o| o.round).max().unwrap();
    println!(
        "SNAPPER_UNLOCK_SIM_RESULT protocol=snapper scenario={} profile={} conflict_to_object_usable_ms={} conflict_to_resolution_ms={} decision_release={} fast_count={} anchor_count={} max_resolution_round={}",
        scenario.code(),
        network_profile(),
        ms(resolution_elapsed),
        ms(resolution_elapsed),
        decision_release,
        fast_count,
        anchor_count,
        max_resolution_round,
    );

    for authority in authorities {
        authority.stop();
    }
}
