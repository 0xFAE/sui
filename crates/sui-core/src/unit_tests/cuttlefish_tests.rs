// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use consensus_config::{ConsensusProtocolConfig, Parameters, local_committee_and_keys};
use consensus_core::{
    BlockAPI as _, CommitConsumerArgs, CommittedSubDag, ConsensusAuthority, NetworkType,
    TransactionVerifier, ValidationError,
};
use consensus_types::block::{BlockRef, TransactionIndex};
use fastcrypto::{
    ed25519::{ED25519_SIGNATURE_LENGTH, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature},
    traits::{KeyPair as _, Signer as _, ToFromBytes as _, VerifyingKey as _},
};
use futures::{StreamExt, stream::FuturesUnordered};
use mysten_metrics::{RegistryService, monitored_mpsc::UnboundedReceiver};
use prometheus::Registry;
use rand::{SeedableRng as _, rngs::StdRng};
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex as TokioMutex,
};
use typed_store::DBMetrics;

use sui_types::{
    base_types::{ObjectID, SequenceNumber, dbg_addr},
    crypto::{AccountKeyPair, get_key_pair},
    object::{Object, Owner},
};

use crate::authority::{
    authority_per_epoch_store::consensus_quarantine::ConsensusCommitOutput,
    authority_test_utils::init_transfer_transaction, test_authority_builder::TestAuthorityBuilder,
};

use crate::cuttlefish::{
    CuttlefishCertificateId, CuttlefishFastUnlockState, CuttlefishObjectKey, CuttlefishResolution,
    CuttlefishUnlockCertificate, CuttlefishUnlockRequest,
};

struct CuttlefishEvalNoopVerifier;

impl TransactionVerifier for CuttlefishEvalNoopVerifier {
    fn verify_batch(&self, _batch: &[&[u8]]) -> Result<(), ValidationError> {
        Ok(())
    }

    fn verify_and_vote_batch(
        &self,
        _block_ref: &BlockRef,
        _batch: &[&[u8]],
    ) -> Result<Vec<TransactionIndex>, ValidationError> {
        Ok(vec![])
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_millis() as u64
}

fn commit_contains_payload(committed: &CommittedSubDag, payload: &[u8]) -> bool {
    committed.blocks.iter().any(|block| {
        block
            .transactions()
            .iter()
            .any(|transaction| transaction.data() == payload)
    })
}

async fn wait_until_committed(
    receiver: &mut UnboundedReceiver<CommittedSubDag>,
    payload: &[u8],
    timeout: Duration,
) -> (CommittedSubDag, u64) {
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for Cuttlefish UnlockCert consensus commit");

        let committed = tokio::time::timeout(remaining, receiver.recv())
            .await
            .expect("timed out waiting for Cuttlefish UnlockCert consensus commit")
            .expect("consensus commit stream closed");

        if commit_contains_payload(&committed, payload) {
            return (committed, unix_time_ms());
        }
    }
}

fn encode_unlock_request(request: &CuttlefishUnlockRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 8 + 32);
    out.extend_from_slice(&request.object.object_id);
    out.extend_from_slice(&request.object.version.to_le_bytes());
    out.extend_from_slice(&request.auth_transaction);
    out
}

fn decode_unlock_request(data: &[u8]) -> Option<CuttlefishUnlockRequest> {
    if data.len() != 32 + 8 + 32 {
        return None;
    }

    let object_id: [u8; 32] = data[0..32].try_into().ok()?;
    let version = u64::from_le_bytes(data[32..40].try_into().ok()?);
    let auth_transaction: [u8; 32] = data[40..72].try_into().ok()?;

    Some(CuttlefishUnlockRequest {
        object: CuttlefishObjectKey { object_id, version },
        auth_transaction,
    })
}

fn encode_unlock_vote(vote: &crate::cuttlefish::CuttlefishUnlockVote) -> Vec<u8> {
    let mut out = encode_unlock_request(&vote.request);

    match vote.certificate {
        Some(certificate) => {
            out.push(1);
            out.extend_from_slice(&certificate.0);
        }
        None => out.push(0),
    }

    out.extend_from_slice(&vote.authority.to_le_bytes());
    out
}

fn decode_unlock_vote(data: &[u8]) -> Option<crate::cuttlefish::CuttlefishUnlockVote> {
    const REQUEST_LEN: usize = 32 + 8 + 32;

    if data.len() != REQUEST_LEN + 1 + 4 && data.len() != REQUEST_LEN + 1 + 32 + 4 {
        return None;
    }

    let request = decode_unlock_request(data.get(..REQUEST_LEN)?)?;

    let mut offset = REQUEST_LEN;

    let certificate = match *data.get(offset)? {
        0 => {
            offset += 1;
            None
        }
        1 => {
            offset += 1;
            let bytes: [u8; 32] = data.get(offset..offset + 32)?.try_into().ok()?;
            offset += 32;
            Some(CuttlefishCertificateId(bytes))
        }
        _ => return None,
    };

    let authority = u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?);
    offset += 4;

    if offset != data.len() {
        return None;
    }

    Some(crate::cuttlefish::CuttlefishUnlockVote {
        request,
        certificate,
        authority,
    })
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).expect("evaluation frame too large");

    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;

    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;

    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];

    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn spawn_cuttlefish_unlock_server(
    authority: u32,
    state: Arc<TokioMutex<CuttlefishFastUnlockState>>,
    signing_key: Arc<Ed25519KeyPair>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Cuttlefish evaluation RPC");

    let address = listener
        .local_addr()
        .expect("Cuttlefish evaluation RPC local address");

    let task = tokio::spawn(async move {
        let (mut socket, _) = listener
            .accept()
            .await
            .expect("accept Cuttlefish UnlockRqt");

        let payload = read_frame(&mut socket)
            .await
            .expect("read Cuttlefish UnlockRqt");

        let request = decode_unlock_request(&payload).expect("decode Cuttlefish UnlockRqt");

        let vote = {
            let mut state = state.lock().await;
            state
                .process_unlock_request(request, authority, true)
                .expect("authenticated Cuttlefish UnlockRqt should produce UnlockVote")
        };

        let vote_bytes = encode_unlock_vote(&vote);
        let signature: Ed25519Signature = signing_key.sign(&vote_bytes);

        let mut response = Vec::with_capacity(vote_bytes.len() + ED25519_SIGNATURE_LENGTH);
        response.extend_from_slice(&vote_bytes);
        response.extend_from_slice(signature.as_ref());

        write_frame(&mut socket, &response)
            .await
            .expect("write signed Cuttlefish UnlockVote");
    });

    (address, task)
}

async fn request_unlock_vote_over_tcp(
    address: SocketAddr,
    request: CuttlefishUnlockRequest,
    public_key: Ed25519PublicKey,
) -> crate::cuttlefish::CuttlefishUnlockVote {
    let mut socket = TcpStream::connect(address)
        .await
        .expect("connect to Cuttlefish evaluation RPC");

    let payload = encode_unlock_request(&request);

    write_frame(&mut socket, &payload)
        .await
        .expect("send Cuttlefish UnlockRqt");

    let response = read_frame(&mut socket)
        .await
        .expect("receive signed Cuttlefish UnlockVote");

    assert!(
        response.len() > ED25519_SIGNATURE_LENGTH,
        "signed UnlockVote response is too short"
    );

    let vote_len = response.len() - ED25519_SIGNATURE_LENGTH;
    let (vote_bytes, signature_bytes) = response.split_at(vote_len);

    let signature =
        Ed25519Signature::from_bytes(signature_bytes).expect("decode Ed25519 UnlockVote signature");

    public_key
        .verify(vote_bytes, &signature)
        .expect("verify Cuttlefish UnlockVote signature");

    decode_unlock_vote(vote_bytes).expect("decode verified Cuttlefish UnlockVote")
}

fn object(tag: u8, version: u64) -> CuttlefishObjectKey {
    CuttlefishObjectKey {
        object_id: [tag; 32],
        version,
    }
}

fn request(object: CuttlefishObjectKey, auth_tag: u8) -> CuttlefishUnlockRequest {
    CuttlefishUnlockRequest {
        object,
        auth_transaction: [auth_tag; 32],
    }
}

fn build_unlock_certificate(
    states: &mut [CuttlefishFastUnlockState],
    request: CuttlefishUnlockRequest,
    quorum: usize,
) -> CuttlefishUnlockCertificate {
    let votes = states
        .iter_mut()
        .enumerate()
        .take(quorum)
        .map(|(authority, state)| {
            state
                .process_unlock_request(request, authority as u32, true)
                .expect("authenticated UnlockRqt should produce vote")
        })
        .collect::<Vec<_>>();

    CuttlefishFastUnlockState::assemble_unlock_certificate(votes, quorum)
        .expect("2f+1 matching unlock votes should form UnlockCert")
}

#[tokio::test]
#[ignore = "evaluation-only Cuttlefish FastUnlock/Mysticeti integration"]
async fn cuttlefish_unlock_certificate_orders_through_mysticeti() {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;
    const QUORUM: usize = 3;

    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);

    let protocol_config = ConsensusProtocolConfig::for_testing();

    let consensus_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().expect("temp consensus db"))
        .collect::<Vec<_>>();

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let parameters = Parameters {
            db_path: consensus_dirs[index.value()].path().to_path_buf(),
            dag_state_cached_rounds: 5,
            commit_sync_parallel_fetches: 2,
            commit_sync_batch_size: 3,
            sync_last_known_own_block_timeout: Duration::from_millis(2_000),
            ..Default::default()
        };

        let (commit_consumer, commit_receiver) = CommitConsumerArgs::new(0, 0);

        let authority = ConsensusAuthority::start(
            NetworkType::Tonic,
            0,
            committee.clone(),
            parameters,
            protocol_config.clone(),
            Some(keypairs[index].1.clone()),
            keypairs[index].0.clone(),
            Arc::new(consensus_core::Clock::default()),
            Arc::new(CuttlefishEvalNoopVerifier),
            commit_consumer,
            Registry::new(),
            0,
            None,
        )
        .await;

        authorities.push(authority);
        commit_receivers.push(commit_receiver);
    }

    let object_no_cert = object(0x31, 7);
    let request_no_cert = request(object_no_cert, 0xA1);

    let mut no_cert_states = (0..AUTHORITIES)
        .map(|_| {
            let mut state = CuttlefishFastUnlockState::new();
            state.set_lock(object_no_cert, None);
            state
        })
        .collect::<Vec<_>>();

    let unlock_cert_no_cert =
        build_unlock_certificate(&mut no_cert_states, request_no_cert, QUORUM);

    assert_eq!(unlock_cert_no_cert.certificate, None);

    let payload_no_cert = unlock_cert_no_cert.encode_consensus_transaction();

    assert_eq!(
        CuttlefishUnlockCertificate::decode_consensus_transaction(&payload_no_cert),
        Some(unlock_cert_no_cert.clone())
    );

    let submit_no_cert_ms = unix_time_ms();

    authorities[0]
        .transaction_client()
        .submit(vec![payload_no_cert.clone()])
        .await
        .expect("Cuttlefish UnlockCert should enter a Mysticeti block");

    let mut no_cert_commits = Vec::with_capacity(AUTHORITIES);

    for receiver in &mut commit_receivers {
        let (committed, observed_ms) =
            wait_until_committed(receiver, &payload_no_cert, Duration::from_secs(30)).await;

        no_cert_commits.push((committed, observed_ms));
    }

    let no_cert_consensus_ms = no_cert_commits
        .iter()
        .map(|(_, observed_ms)| *observed_ms)
        .max()
        .unwrap();

    for state in &mut no_cert_states {
        let resolution = state
            .process_unlock_certificate(&unlock_cert_no_cert, QUORUM)
            .expect("sequenced UnlockCert should process");

        assert_eq!(
            resolution,
            CuttlefishResolution::NoopVersionBump {
                old_object: object_no_cert,
                new_object: object_no_cert.next_version(),
            }
        );
    }

    let object_with_cert = object(0x32, 19);
    let request_with_cert = request(object_with_cert, 0xA2);
    let tx_certificate = CuttlefishCertificateId([0xC9; 32]);

    let mut with_cert_states = (0..AUTHORITIES)
        .map(|_| {
            let mut state = CuttlefishFastUnlockState::new();
            state.set_lock(object_with_cert, Some(tx_certificate));
            state
        })
        .collect::<Vec<_>>();

    let unlock_cert_with_cert =
        build_unlock_certificate(&mut with_cert_states, request_with_cert, QUORUM);

    assert_eq!(unlock_cert_with_cert.certificate, Some(tx_certificate));

    let payload_with_cert = unlock_cert_with_cert.encode_consensus_transaction();

    let submit_with_cert_ms = unix_time_ms();

    authorities[1]
        .transaction_client()
        .submit(vec![payload_with_cert.clone()])
        .await
        .expect("Cuttlefish UnlockCert with Cert should enter Mysticeti");

    let mut with_cert_commits = Vec::with_capacity(AUTHORITIES);

    for receiver in &mut commit_receivers {
        let (committed, observed_ms) =
            wait_until_committed(receiver, &payload_with_cert, Duration::from_secs(30)).await;

        with_cert_commits.push((committed, observed_ms));
    }

    let with_cert_consensus_ms = with_cert_commits
        .iter()
        .map(|(_, observed_ms)| *observed_ms)
        .max()
        .unwrap();

    for state in &mut with_cert_states {
        let resolution = state
            .process_unlock_certificate(&unlock_cert_with_cert, QUORUM)
            .expect("sequenced UnlockCert should process");

        assert_eq!(
            resolution,
            CuttlefishResolution::ExecuteCertificate(tx_certificate)
        );
    }

    println!();
    println!("=== Cuttlefish Step 6B ===");
    println!(
        "no_certificate_submit_to_all_committed_ms={}",
        no_cert_consensus_ms.saturating_sub(submit_no_cert_ms)
    );
    println!(
        "no_certificate_commit_round={}",
        no_cert_commits
            .iter()
            .map(|(commit, _)| commit.leader.round)
            .max()
            .unwrap()
    );
    println!(
        "with_certificate_submit_to_all_committed_ms={}",
        with_cert_consensus_ms.saturating_sub(submit_with_cert_ms)
    );
    println!(
        "with_certificate_commit_round={}",
        with_cert_commits
            .iter()
            .map(|(commit, _)| commit.leader.round)
            .max()
            .unwrap()
    );
    println!();

    for authority in authorities {
        authority.stop().await;
    }
}

/// Cross-layer Cuttlefish FastUnlock evaluation.
///
/// This is the direct analogue of the Snapper Step-5D benchmark:
///   owned-object conflict
///   -> send UnlockRqt to validators over real localhost TCP connections
///   -> collect the first 2f+1 UnlockVotes
///   -> order UnlockCert through real Mysticeti
///   -> apply the Cuttlefish no-op version bump
///   -> verify that a fresh Sui transaction can use the new object version
///
/// The Sui state transition uses the existing test-only object insertion API.
/// Production execution wiring is intentionally out of scope for this benchmark.
#[tokio::test]
#[ignore = "evaluation-only Cuttlefish end-to-end owned-object recovery benchmark"]
async fn cuttlefish_end_to_end_unlock_smoke() {
    telemetry_subscribers::init_for_testing();

    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    const AUTHORITIES: usize = 4;
    const QUORUM: usize = 3;

    let (sender, sender_key): (_, AccountKeyPair) = get_key_pair();

    let target_id = ObjectID::random();
    let target_object = Object::with_id_owner_for_testing(target_id, sender);
    let gas0 = Object::with_id_owner_for_testing(ObjectID::random(), sender);
    let gas1 = Object::with_id_owner_for_testing(ObjectID::random(), sender);

    let target_ref = target_object.compute_object_reference();
    let gas0_ref = gas0.compute_object_reference();
    let gas1_ref = gas1.compute_object_reference();

    let starting_objects = vec![target_object.clone(), gas0.clone(), gas1.clone()];

    let sui_authority = TestAuthorityBuilder::new()
        .with_starting_objects(&starting_objects)
        .build()
        .await;

    let epoch_store = sui_authority.epoch_store_for_testing();
    let rgp = sui_authority
        .reference_gas_price_for_testing()
        .expect("reference gas price");

    let locking_tx = init_transfer_transaction(
        &sui_authority,
        sender,
        &sender_key,
        dbg_addr(40),
        target_ref,
        gas0_ref,
        5_000_000,
        rgp,
    );

    sui_authority
        .handle_vote_transaction(&epoch_store, locking_tx.clone())
        .expect("locking transaction should validate");

    let initial_locks = epoch_store
        .try_acquire_owned_object_locks_post_consensus(
            &[target_ref, gas0_ref],
            *locking_tx.digest(),
            &HashMap::new(),
        )
        .expect("locking transaction should acquire old object version");

    let mut output = ConsensusCommitOutput::new(1);
    output.set_default_commit_stats_for_testing();
    output.set_owned_object_locks(initial_locks.into_iter().collect());

    epoch_store
        .consensus_quarantine
        .write()
        .push_consensus_output(output, &epoch_store)
        .expect("initial owned-object lock should enter quarantine");

    assert!(
        epoch_store
            .get_owned_object_locks(&[target_ref])
            .expect("old lock lookup")[0]
            .is_some(),
        "old target version should be locked before FastUnlock"
    );

    let conflicting_tx = init_transfer_transaction(
        &sui_authority,
        sender,
        &sender_key,
        dbg_addr(41),
        target_ref,
        gas1_ref,
        5_000_000,
        rgp,
    );

    sui_authority
        .handle_vote_transaction(&epoch_store, conflicting_tx.clone())
        .expect("conflicting transaction should pass pre-consensus validation");

    assert!(
        epoch_store
            .try_acquire_owned_object_locks_post_consensus(
                &[target_ref, gas1_ref],
                *conflicting_tx.digest(),
                &HashMap::new(),
            )
            .is_err(),
        "conflicting old-version transaction must be blocked before FastUnlock"
    );

    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);

    let protocol_config = ConsensusProtocolConfig::for_testing();

    let consensus_dirs = (0..AUTHORITIES)
        .map(|_| TempDir::new().expect("temp consensus db"))
        .collect::<Vec<_>>();

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    let mut commit_receivers = Vec::with_capacity(AUTHORITIES);

    for (index, _) in committee.authorities() {
        let parameters = Parameters {
            db_path: consensus_dirs[index.value()].path().to_path_buf(),
            dag_state_cached_rounds: 5,
            commit_sync_parallel_fetches: 2,
            commit_sync_batch_size: 3,
            sync_last_known_own_block_timeout: Duration::from_millis(2_000),
            ..Default::default()
        };

        let (commit_consumer, commit_receiver) = CommitConsumerArgs::new(0, 0);

        let authority = ConsensusAuthority::start(
            NetworkType::Tonic,
            0,
            committee.clone(),
            parameters,
            protocol_config.clone(),
            Some(keypairs[index].1.clone()),
            keypairs[index].0.clone(),
            Arc::new(consensus_core::Clock::default()),
            Arc::new(CuttlefishEvalNoopVerifier),
            commit_consumer,
            Registry::new(),
            0,
            None,
        )
        .await;

        authorities.push(authority);
        commit_receivers.push(commit_receiver);
    }

    let cuttlefish_object = CuttlefishObjectKey {
        object_id: target_id.into_bytes(),
        version: target_ref.1.value(),
    };

    let request = CuttlefishUnlockRequest {
        object: cuttlefish_object,
        auth_transaction: conflicting_tx.digest().into_inner(),
    };

    // Validator authentication setup is outside the measured recovery interval.

    // Signing and verification themselves happen inside the UnlockVote RPC path.

    let mut unlock_key_rng = StdRng::from_seed([0xC7; 32]);

    let unlock_signing_keys = (0..AUTHORITIES)
        .map(|_| Arc::new(Ed25519KeyPair::generate(&mut unlock_key_rng)))
        .collect::<Vec<_>>();

    let unlock_public_keys = unlock_signing_keys
        .iter()
        .map(|keypair| keypair.public().clone())
        .collect::<Vec<_>>();

    let fastunlock_states = (0..AUTHORITIES)
        .map(|_| {
            let mut state = CuttlefishFastUnlockState::new();
            state.set_lock(cuttlefish_object, None);
            Arc::new(TokioMutex::new(state))
        })
        .collect::<Vec<_>>();

    let mut unlock_rpc_addresses = Vec::with_capacity(AUTHORITIES);
    let mut unlock_rpc_tasks = Vec::with_capacity(AUTHORITIES);

    for (authority, state) in fastunlock_states.iter().cloned().enumerate() {
        let (address, task) = spawn_cuttlefish_unlock_server(
            authority as u32,
            state,
            unlock_signing_keys[authority].clone(),
        )
        .await;
        unlock_rpc_addresses.push(address);
        unlock_rpc_tasks.push(task);
    }

    let conflict_injected_at_ms = unix_time_ms();

    let mut vote_requests = FuturesUnordered::new();

    for (authority, address) in unlock_rpc_addresses.iter().copied().enumerate() {
        let public_key = unlock_public_keys[authority].clone();

        vote_requests.push(tokio::spawn(request_unlock_vote_over_tcp(
            address, request, public_key,
        )));
    }

    let mut quorum_votes = Vec::with_capacity(QUORUM);

    while quorum_votes.len() < QUORUM {
        let vote = vote_requests
            .next()
            .await
            .expect("Cuttlefish vote request set ended before quorum")
            .expect("Cuttlefish vote request task failed");

        quorum_votes.push(vote);
    }

    let unlock_certificate_formed_at_ms = unix_time_ms();

    let unlock_cert = CuttlefishFastUnlockState::assemble_unlock_certificate(quorum_votes, QUORUM)
        .expect("first 2f+1 network UnlockVotes should form UnlockCert");

    while let Some(result) = vote_requests.next().await {
        result.expect("remaining Cuttlefish vote request failed");
    }

    for task in unlock_rpc_tasks {
        task.await.expect("Cuttlefish evaluation RPC task failed");
    }

    assert_eq!(unlock_cert.certificate, None);

    let payload = unlock_cert.encode_consensus_transaction();
    let consensus_submit_at_ms = unix_time_ms();

    authorities[0]
        .transaction_client()
        .submit(vec![payload.clone()])
        .await
        .expect("UnlockCert should enter Mysticeti");

    let mut commits = Vec::with_capacity(AUTHORITIES);

    for receiver in &mut commit_receivers {
        let (committed, observed_ms) =
            wait_until_committed(receiver, &payload, Duration::from_secs(30)).await;

        commits.push((committed, observed_ms));
    }

    let consensus_committed_at_ms = commits
        .iter()
        .map(|(_, observed_ms)| *observed_ms)
        .max()
        .unwrap();

    for state in &fastunlock_states {
        let mut state = state.lock().await;

        let resolution = state
            .process_unlock_certificate(&unlock_cert, QUORUM)
            .expect("committed UnlockCert should process");

        assert_eq!(
            resolution,
            CuttlefishResolution::NoopVersionBump {
                old_object: cuttlefish_object,
                new_object: cuttlefish_object.next_version(),
            }
        );
    }

    let fastunlock_processed_at_ms = unix_time_ms();

    let bumped_version = SequenceNumber::from_u64(
        target_ref
            .1
            .value()
            .checked_add(1)
            .expect("object version overflow"),
    );

    let bumped_target = Object::with_id_owner_version_for_testing(
        target_id,
        bumped_version,
        Owner::AddressOwner(sender),
    );

    let bumped_ref = bumped_target.compute_object_reference();

    sui_authority
        .insert_objects_unsafe_for_testing_only(std::slice::from_ref(&bumped_target))
        .await
        .expect("test-only Cuttlefish version bump should update Sui object");

    let live_target = sui_authority
        .get_object(&target_id)
        .expect("bumped target should exist");

    assert_eq!(
        live_target.version(),
        bumped_version,
        "Cuttlefish no-op must advance the live object version"
    );

    let fresh_epoch_store = sui_authority.epoch_store_for_testing();

    let fresh_tx = init_transfer_transaction(
        &sui_authority,
        sender,
        &sender_key,
        dbg_addr(42),
        bumped_ref,
        gas1_ref,
        5_000_000,
        rgp,
    );

    sui_authority
        .handle_vote_transaction(&fresh_epoch_store, fresh_tx.clone())
        .expect("fresh transaction on bumped version should validate");

    let fresh_locks = fresh_epoch_store
        .try_acquire_owned_object_locks_post_consensus(
            &[bumped_ref, gas1_ref],
            *fresh_tx.digest(),
            &HashMap::new(),
        )
        .expect("fresh transaction should acquire bumped object version");

    assert!(
        fresh_locks
            .iter()
            .any(|(object_ref, _)| *object_ref == bumped_ref),
        "fresh transaction did not acquire the Cuttlefish v+1 object"
    );

    let object_usable_at_ms = unix_time_ms();

    println!();
    println!("=== Cuttlefish Step 6E ===");
    println!("conflict_injected_at_ms={conflict_injected_at_ms}");
    println!("unlock_certificate_formed_at_ms={unlock_certificate_formed_at_ms}");
    println!("consensus_submit_at_ms={consensus_submit_at_ms}");
    println!("consensus_committed_at_ms={consensus_committed_at_ms}");
    println!("fastunlock_processed_at_ms={fastunlock_processed_at_ms}");
    println!("object_usable_at_ms={object_usable_at_ms}");
    println!(
        "unlock_vote_collection_ms={}",
        unlock_certificate_formed_at_ms.saturating_sub(conflict_injected_at_ms)
    );
    println!("unlock_vote_transport=tcp");
    println!("unlock_vote_signature=ed25519");
    println!("unlock_votes_required={QUORUM}");
    println!(
        "unlockcert_consensus_ms={}",
        consensus_committed_at_ms.saturating_sub(consensus_submit_at_ms)
    );
    println!(
        "consensus_to_object_usable_ms={}",
        object_usable_at_ms.saturating_sub(consensus_committed_at_ms)
    );
    println!(
        "conflict_to_object_usable_ms={}",
        object_usable_at_ms.saturating_sub(conflict_injected_at_ms)
    );
    println!(
        "commit_round={}",
        commits
            .iter()
            .map(|(commit, _)| commit.leader.round)
            .max()
            .unwrap()
    );
    println!("old_version={}", target_ref.1.value());
    println!("new_version={}", bumped_ref.1.value());
    println!();

    for authority in authorities {
        authority.stop().await;
    }
}
