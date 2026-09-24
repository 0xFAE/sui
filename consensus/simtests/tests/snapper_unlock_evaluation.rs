// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `msim` version of the three-scenario owned-object recovery comparison.

#[cfg(msim)]
#[path = "snapper_unlock_support/common.rs"]
mod common;
#[cfg(msim)]
#[path = "snapper_unlock_support/cuttlefish.rs"]
mod cuttlefish;
#[cfg(msim)]
#[path = "snapper_unlock_support/mysticeti.rs"]
mod mysticeti;
#[cfg(msim)]
#[path = "snapper_unlock_support/snapper.rs"]
mod snapper;

#[cfg(msim)]
mod tests {
    use sui_macros::sim_test;

    use super::{
        common::{Scenario, unlock_network_config},
        cuttlefish, mysticeti, snapper,
    };

    #[sim_test(config = "unlock_network_config()")]
    async fn snapper_pre_ack_conflict() {
        snapper::run(Scenario::PreAck).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn snapper_no_certificate_equivocation() {
        snapper::run(Scenario::NoCertificate).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn snapper_post_ack_equivocation() {
        snapper::run(Scenario::PostAck).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn cuttlefish_pre_ack_conflict() {
        cuttlefish::run(Scenario::PreAck).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn cuttlefish_no_certificate_equivocation() {
        cuttlefish::run(Scenario::NoCertificate).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn cuttlefish_post_ack_equivocation() {
        cuttlefish::run(Scenario::PostAck).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn mysticeti_fpc_pre_ack_conflict() {
        mysticeti::run(Scenario::PreAck).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn mysticeti_fpc_no_certificate_equivocation() {
        mysticeti::run(Scenario::NoCertificate).await;
    }

    #[sim_test(config = "unlock_network_config()")]
    async fn mysticeti_fpc_post_ack_equivocation() {
        mysticeti::run(Scenario::PostAck).await;
    }
}
