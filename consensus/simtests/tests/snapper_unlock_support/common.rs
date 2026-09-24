use std::{sync::Arc, time::Duration};

use consensus_config::{
    Authority, AuthorityName, Committee, ConsensusProtocolConfig, Epoch, NetworkKeyPair,
    ProtocolKeyPair, Stake,
};
use consensus_core::NoopTransactionVerifier;
use consensus_simtests::node::{AuthorityNode, Config, default_parameters};
use fastcrypto::traits::{KeyPair as _, ToFromBytes as _};
use mysten_metrics::RegistryService;
use mysten_network::Multiaddr;
use prometheus::Registry;
use rand::{SeedableRng as _, rngs::StdRng};
use sui_config::local_ip_utils;
use sui_simulator::{
    SimConfig,
    configs::{bimodal_latency_ms, env_config, uniform_latency_ms},
};
use tempfile::TempDir;
use tokio::time::sleep;
use typed_store::DBMetrics;

pub const AUTHORITIES: usize = 4;
pub const QUORUM: usize = 3;
pub const MAX_WAIT: Duration = Duration::from_secs(30);
pub const MYSTICETI_REMAINING_EPOCH_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug)]
pub enum Scenario {
    PreAck,
    NoCertificate,
    PostAck,
}

impl Scenario {
    pub fn code(self) -> &'static str {
        match self {
            Self::PreAck => "pre_ack",
            Self::NoCertificate => "no_certificate",
            Self::PostAck => "post_ack",
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Self::PreAck => 0xA1,
            Self::NoCertificate => 0xB1,
            Self::PostAck => 0xC1,
        }
    }
}

pub fn unlock_network_config() -> SimConfig {
    env_config(
        uniform_latency_ms(10..20),
        [
            ("stable", uniform_latency_ms(10..20)),
            (
                "regional_high_variance",
                bimodal_latency_ms(30..40, 300..800, 0.01),
            ),
            (
                "global_high_variance",
                bimodal_latency_ms(60..80, 500..1500, 0.01),
            ),
        ],
    )
}

pub fn network_profile() -> String {
    std::env::var("SUI_SIM_CONFIG").unwrap_or_else(|_| "stable".to_string())
}

pub fn ms(duration: Duration) -> u128 {
    duration.as_millis()
}

pub async fn start_authorities() -> Vec<AuthorityNode> {
    telemetry_subscribers::init_for_testing();
    let db_registry = Registry::new();
    DBMetrics::init(RegistryService::new(db_registry));

    let (committee, keypairs) = local_committee_and_keys(0, vec![1; AUTHORITIES]);
    let protocol_config = ConsensusProtocolConfig::for_testing();
    assert!(protocol_config.transaction_voting_enabled());

    let mut authorities = Vec::with_capacity(AUTHORITIES);
    for (authority_index, _) in committee.authorities() {
        let db_dir = Arc::new(TempDir::new().unwrap());
        let mut parameters = default_parameters();
        parameters.db_path = db_dir.path().to_path_buf();

        let node = AuthorityNode::new(Config {
            authority_index,
            db_dir,
            committee: committee.clone(),
            keypairs: keypairs.clone(),
            boot_counter: 0,
            clock_drift: 0,
            protocol_config: protocol_config.clone(),
            transaction_verifier: Arc::new(NoopTransactionVerifier {}),
            parameters,
            observer_network_keypair: None,
            observer_ip: None,
        });
        node.start().await.unwrap();
        node.spawn_committed_subdag_consumer().unwrap();
        authorities.push(node);
    }

    sleep(Duration::from_secs(1)).await;
    authorities
}

fn local_committee_and_keys(
    epoch: Epoch,
    authorities_stake: Vec<Stake>,
) -> (Committee, Vec<(NetworkKeyPair, ProtocolKeyPair)>) {
    let mut authorities = vec![];
    let mut key_pairs = vec![];
    let mut rng = StdRng::from_seed([0; 32]);

    for (i, stake) in authorities_stake.into_iter().enumerate() {
        let authority_keypair =
            fastcrypto::bls12381::min_sig::BLS12381KeyPair::generate(&mut rng);
        let protocol_keypair = ProtocolKeyPair::generate(&mut rng);
        let network_keypair = NetworkKeyPair::generate(&mut rng);
        authorities.push(Authority {
            stake,
            address: get_available_local_address(),
            hostname: format!("snapper_unlock_sim_{i}"),
            authority_name: AuthorityName::from_bytes(authority_keypair.public().as_bytes()),
            protocol_key: protocol_keypair.public(),
            network_key: network_keypair.public(),
        });
        key_pairs.push((network_keypair, protocol_keypair));
    }

    (Committee::new(epoch, authorities), key_pairs)
}

fn get_available_local_address() -> Multiaddr {
    let ip = local_ip_utils::get_new_ip();
    local_ip_utils::new_udp_address_for_testing(&ip)
}
