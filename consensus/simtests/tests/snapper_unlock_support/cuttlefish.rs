use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use consensus_core::{BlockAPI, CommittedSubDag};
use fastcrypto::{
    ed25519::{
        ED25519_SIGNATURE_LENGTH, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature,
    },
    traits::{KeyPair as _, Signer as _, ToFromBytes as _, VerifyingKey as _},
};
use futures::{StreamExt, stream::FuturesUnordered};
use mysten_metrics::monitored_mpsc::UnboundedReceiver;
use rand::{SeedableRng as _, rngs::StdRng};
use sui_config::local_ip_utils;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};

use super::common::{
    AUTHORITIES, MAX_WAIT, QUORUM, Scenario, ms, network_profile, start_authorities,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectKey {
    object_id: [u8; 32],
    version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnlockRequest {
    object: ObjectKey,
    auth_transaction: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnlockVote {
    request: UnlockRequest,
    authority: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UnlockCertificate {
    request: UnlockRequest,
    voters: BTreeSet<u32>,
}

fn encode_request(request: &UnlockRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(72);
    out.extend_from_slice(&request.object.object_id);
    out.extend_from_slice(&request.object.version.to_le_bytes());
    out.extend_from_slice(&request.auth_transaction);
    out
}

fn decode_request(data: &[u8]) -> Option<UnlockRequest> {
    if data.len() != 72 {
        return None;
    }
    Some(UnlockRequest {
        object: ObjectKey {
            object_id: data[0..32].try_into().ok()?,
            version: u64::from_le_bytes(data[32..40].try_into().ok()?),
        },
        auth_transaction: data[40..72].try_into().ok()?,
    })
}

fn encode_vote(vote: &UnlockVote) -> Vec<u8> {
    let mut out = encode_request(&vote.request);
    out.push(0);
    out.extend_from_slice(&vote.authority.to_le_bytes());
    out
}

fn decode_vote(data: &[u8]) -> Option<UnlockVote> {
    if data.len() != 77 || data[72] != 0 {
        return None;
    }
    Some(UnlockVote {
        request: decode_request(&data[..72])?,
        authority: u32::from_le_bytes(data[73..77].try_into().ok()?),
    })
}

fn assemble(votes: impl IntoIterator<Item = UnlockVote>) -> UnlockCertificate {
    let mut iter = votes.into_iter();
    let first = iter.next().expect("empty Cuttlefish quorum");
    let request = first.request;
    let mut voters = BTreeSet::from([first.authority]);
    for vote in iter {
        assert_eq!(
            vote.request, request,
            "Cuttlefish votes disagree on request"
        );
        assert!(
            voters.insert(vote.authority),
            "duplicate Cuttlefish voter"
        );
    }
    assert!(voters.len() >= QUORUM, "not enough Cuttlefish votes");
    UnlockCertificate { request, voters }
}

fn encode_certificate(cert: &UnlockCertificate) -> Vec<u8> {
    let mut out = b"CUTFULK\0".to_vec();
    out.extend_from_slice(&encode_request(&cert.request));
    out.extend_from_slice(&(cert.voters.len() as u32).to_le_bytes());
    for voter in &cert.voters {
        out.extend_from_slice(&voter.to_le_bytes());
    }
    out
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).expect("evaluation frame too large");
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let mut payload = vec![0u8; u32::from_le_bytes(len_bytes) as usize];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn spawn_server(
    authority: u32,
    signing_key: Arc<Ed25519KeyPair>,
) -> (sui_simulator::task::NodeId, SocketAddr) {
    let ip: IpAddr = local_ip_utils::get_new_ip()
        .parse()
        .expect("parse Cuttlefish simulated IP");
    let address = SocketAddr::new(ip, 12_000 + authority as u16);
    let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);

    let node = sui_simulator::runtime::Handle::current()
        .create_node()
        .ip(ip)
        .name(format!("cuttlefish-unlock-{authority}"))
        .init(move || {
            let signing_key = signing_key.clone();
            let ready_tx = ready_tx.clone();
            async move {
                let listener = TcpListener::bind(address)
                    .await
                    .expect("bind Cuttlefish UnlockVote RPC");
                ready_tx.send(true).ok();

                let (mut socket, _) = listener.accept().await.expect("accept UnlockRqt");
                let request = decode_request(
                    &read_frame(&mut socket)
                        .await
                        .expect("read Cuttlefish UnlockRqt"),
                )
                .expect("decode Cuttlefish UnlockRqt");

                let vote = UnlockVote { request, authority };
                let vote_bytes = encode_vote(&vote);
                let signature: Ed25519Signature = signing_key.sign(&vote_bytes);

                let mut response = vote_bytes;
                response.extend_from_slice(signature.as_ref());
                write_frame(&mut socket, &response)
                    .await
                    .expect("write signed Cuttlefish UnlockVote");
            }
        })
        .build();

    while !*ready_rx.borrow() {
        ready_rx
            .changed()
            .await
            .expect("Cuttlefish server exited before ready");
    }
    (node.id(), address)
}

async fn request_vote(
    address: SocketAddr,
    request: UnlockRequest,
    public_key: Ed25519PublicKey,
) -> UnlockVote {
    let mut socket = TcpStream::connect(address)
        .await
        .expect("connect to Cuttlefish UnlockVote RPC");
    write_frame(&mut socket, &encode_request(&request))
        .await
        .expect("send Cuttlefish UnlockRqt");

    let response = read_frame(&mut socket)
        .await
        .expect("receive signed Cuttlefish UnlockVote");
    assert!(response.len() > ED25519_SIGNATURE_LENGTH);

    let split = response.len() - ED25519_SIGNATURE_LENGTH;
    let (vote_bytes, signature_bytes) = response.split_at(split);
    let signature = Ed25519Signature::from_bytes(signature_bytes)
        .expect("decode Ed25519 UnlockVote signature");
    public_key
        .verify(vote_bytes, &signature)
        .expect("verify Cuttlefish UnlockVote signature");

    decode_vote(vote_bytes).expect("decode verified Cuttlefish UnlockVote")
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
    start: Instant,
) -> (CommittedSubDag, std::time::Duration) {
    let deadline = Instant::now() + MAX_WAIT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for Cuttlefish UnlockCert commit");
        let committed = timeout(remaining, receiver.recv())
            .await
            .expect("timed out waiting for Cuttlefish UnlockCert commit")
            .expect("consensus commit stream closed");

        if commit_contains_payload(&committed, payload) {
            return (committed, start.elapsed());
        }
    }
}

pub async fn run(scenario: Scenario) {
    let authorities = start_authorities().await;
    let mut commit_receivers = authorities
        .iter()
        .map(|authority| authority.commit_consumer_receiver())
        .collect::<Vec<_>>();

    let request = UnlockRequest {
        object: ObjectKey {
            object_id: [scenario.tag(); 32],
            version: 0,
        },
        auth_transaction: [scenario.tag().wrapping_add(7); 32],
    };

    let mut rng = StdRng::from_seed([0xC7; 32]);
    let signing_keys = (0..AUTHORITIES)
        .map(|_| Arc::new(Ed25519KeyPair::generate(&mut rng)))
        .collect::<Vec<_>>();
    let public_keys = signing_keys
        .iter()
        .map(|keypair| keypair.public().clone())
        .collect::<Vec<_>>();

    let mut server_nodes = Vec::with_capacity(AUTHORITIES);
    let mut addresses = Vec::with_capacity(AUTHORITIES);
    for authority in 0..AUTHORITIES {
        let (node_id, address) =
            spawn_server(authority as u32, signing_keys[authority].clone()).await;
        server_nodes.push(node_id);
        addresses.push(address);
    }

    let start = Instant::now();
    let mut requests = FuturesUnordered::new();
    for authority in 0..AUTHORITIES {
        requests.push(tokio::spawn(request_vote(
            addresses[authority],
            request,
            public_keys[authority].clone(),
        )));
    }

    let mut quorum_votes = Vec::with_capacity(QUORUM);
    while quorum_votes.len() < QUORUM {
        quorum_votes.push(
            requests
                .next()
                .await
                .expect("Cuttlefish request set ended before quorum")
                .expect("Cuttlefish vote task failed"),
        );
    }
    let vote_collection_elapsed = start.elapsed();
    let certificate = assemble(quorum_votes);

    while let Some(result) = requests.next().await {
        result.expect("remaining Cuttlefish vote task failed");
    }
    for node_id in server_nodes {
        sui_simulator::runtime::Handle::current().delete_node(node_id);
    }

    let payload = encode_certificate(&certificate);
    let consensus_submit_elapsed = start.elapsed();
    authorities[0]
        .transaction_client()
        .submit(vec![payload.clone()])
        .await
        .expect("Cuttlefish UnlockCert should enter Mysticeti");

    let mut commits = Vec::with_capacity(AUTHORITIES);
    for receiver in &mut commit_receivers {
        commits.push(wait_until_committed(receiver, &payload, start).await);
    }

    let consensus_committed_elapsed = commits
        .iter()
        .map(|(_, elapsed)| *elapsed)
        .max()
        .unwrap();
    let object_usable_elapsed = start.elapsed();
    let commit_round = commits
        .iter()
        .map(|(commit, _)| commit.leader.round)
        .max()
        .unwrap();

    println!(
        "SNAPPER_UNLOCK_SIM_RESULT protocol=cuttlefish scenario={} profile={} conflict_to_object_usable_ms={} unlock_vote_collection_ms={} unlockcert_consensus_ms={} consensus_to_object_usable_ms={} commit_round={}",
        scenario.code(),
        network_profile(),
        ms(object_usable_elapsed),
        ms(vote_collection_elapsed),
        ms(consensus_committed_elapsed - consensus_submit_elapsed),
        ms(object_usable_elapsed - consensus_committed_elapsed),
        commit_round,
    );

    for authority in authorities {
        authority.stop();
    }
}
