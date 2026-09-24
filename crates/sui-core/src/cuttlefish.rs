// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Evaluation implementation of Cuttlefish baseline FastUnlock.
//!
//! This module follows Section 6 / Algorithms 1--2 of:
//!   Cuttlefish: Expressive Fast Path Blockchains with FastUnlock.
//!
//! It intentionally implements only the single-owned-object baseline FastUnlock
//! needed for the Snapper comparison. Multi-owner/collective-object support and
//! the Section 7 contention-mitigation extension are out of scope here.
//!
//! The consensus engine is treated as a black box.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CuttlefishObjectKey {
    pub object_id: [u8; 32],
    pub version: u64,
}

impl CuttlefishObjectKey {
    pub fn next_version(self) -> Self {
        Self {
            object_id: self.object_id,
            version: self
                .version
                .checked_add(1)
                .expect("Cuttlefish object version overflow"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CuttlefishCertificateId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CuttlefishUnlockStatus {
    Unlocked,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CuttlefishUnlockRequest {
    pub object: CuttlefishObjectKey,
    pub auth_transaction: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CuttlefishUnlockVote {
    pub request: CuttlefishUnlockRequest,
    pub certificate: Option<CuttlefishCertificateId>,
    pub authority: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CuttlefishUnlockCertificate {
    pub request: CuttlefishUnlockRequest,
    pub certificate: Option<CuttlefishCertificateId>,
    pub voters: BTreeSet<u32>,
}

const CUTTLEFISH_UNLOCK_CERT_MAGIC: &[u8; 8] = b"CUTFULK\0";

impl CuttlefishUnlockCertificate {
    /// Deterministic bytes submitted as one transaction to the consensus
    /// black box. This is evaluation framing, not a protocol change.
    pub fn encode_consensus_transaction(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 8 + 32 + 1 + 32 + 4 + 4 * self.voters.len());

        out.extend_from_slice(CUTTLEFISH_UNLOCK_CERT_MAGIC);
        out.extend_from_slice(&self.request.object.object_id);
        out.extend_from_slice(&self.request.object.version.to_le_bytes());
        out.extend_from_slice(&self.request.auth_transaction);

        match self.certificate {
            Some(certificate) => {
                out.push(1);
                out.extend_from_slice(&certificate.0);
            }
            None => out.push(0),
        }

        let voter_count = u32::try_from(self.voters.len()).expect("too many Cuttlefish voters");
        out.extend_from_slice(&voter_count.to_le_bytes());

        for authority in &self.voters {
            out.extend_from_slice(&authority.to_le_bytes());
        }

        out
    }

    pub fn decode_consensus_transaction(data: &[u8]) -> Option<Self> {
        fn take<const N: usize>(data: &[u8], offset: &mut usize) -> Option<[u8; N]> {
            let end = offset.checked_add(N)?;
            let bytes: [u8; N] = data.get(*offset..end)?.try_into().ok()?;
            *offset = end;
            Some(bytes)
        }

        if data.len() < CUTTLEFISH_UNLOCK_CERT_MAGIC.len()
            || &data[..CUTTLEFISH_UNLOCK_CERT_MAGIC.len()] != CUTTLEFISH_UNLOCK_CERT_MAGIC
        {
            return None;
        }

        let mut offset = CUTTLEFISH_UNLOCK_CERT_MAGIC.len();

        let object_id = take::<32>(data, &mut offset)?;
        let version = u64::from_le_bytes(take::<8>(data, &mut offset)?);
        let auth_transaction = take::<32>(data, &mut offset)?;

        let certificate = match *data.get(offset)? {
            0 => {
                offset += 1;
                None
            }
            1 => {
                offset += 1;
                Some(CuttlefishCertificateId(take::<32>(data, &mut offset)?))
            }
            _ => return None,
        };

        let voter_count = u32::from_le_bytes(take::<4>(data, &mut offset)?) as usize;

        let mut voters = BTreeSet::new();
        for _ in 0..voter_count {
            let authority = u32::from_le_bytes(take::<4>(data, &mut offset)?);
            if !voters.insert(authority) {
                return None;
            }
        }

        if offset != data.len() {
            return None;
        }

        Some(Self {
            request: CuttlefishUnlockRequest {
                object: CuttlefishObjectKey { object_id, version },
                auth_transaction,
            },
            certificate,
            voters,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CuttlefishResolution {
    ExecuteCertificate(CuttlefishCertificateId),
    NoopVersionBump {
        old_object: CuttlefishObjectKey,
        new_object: CuttlefishObjectKey,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CuttlefishError {
    NotEnoughVotes { got: usize, required: usize },
    DuplicateAuthority(u32),
    AlreadyConfirmed(CuttlefishObjectKey),
}

#[derive(Default)]
pub struct CuttlefishFastUnlockState {
    lock_db: BTreeMap<CuttlefishObjectKey, Option<CuttlefishCertificateId>>,
    unlock_db: BTreeMap<CuttlefishObjectKey, CuttlefishUnlockStatus>,
}

impl CuttlefishFastUnlockState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_lock(
        &mut self,
        object: CuttlefishObjectKey,
        certificate: Option<CuttlefishCertificateId>,
    ) {
        self.lock_db.insert(object, certificate);
    }

    pub fn lock_certificate(
        &self,
        object: &CuttlefishObjectKey,
    ) -> Option<CuttlefishCertificateId> {
        self.lock_db.get(object).copied().flatten()
    }

    pub fn unlock_status(&self, object: &CuttlefishObjectKey) -> Option<CuttlefishUnlockStatus> {
        self.unlock_db.get(object).copied()
    }

    pub fn fast_path_allowed(&self, object: &CuttlefishObjectKey) -> bool {
        self.unlock_status(object).is_none()
    }

    /// Algorithm 1: ProcessUnlockTx.
    pub fn process_unlock_request(
        &mut self,
        request: CuttlefishUnlockRequest,
        authority: u32,
        authenticated: bool,
    ) -> Option<CuttlefishUnlockVote> {
        if !authenticated {
            return None;
        }

        let certificate = self.lock_certificate(&request.object);

        self.unlock_db
            .insert(request.object, CuttlefishUnlockStatus::Unlocked);

        Some(CuttlefishUnlockVote {
            request,
            certificate,
            authority,
        })
    }

    /// Client-side assembly of 2f+1 votes over the same
    /// (UnlockRqt, Option(Cert)) fields.
    pub fn assemble_unlock_certificate(
        votes: impl IntoIterator<Item = CuttlefishUnlockVote>,
        quorum: usize,
    ) -> Result<CuttlefishUnlockCertificate, CuttlefishError> {
        let mut groups: BTreeMap<
            (
                CuttlefishObjectKey,
                [u8; 32],
                Option<CuttlefishCertificateId>,
            ),
            (CuttlefishUnlockRequest, BTreeSet<u32>),
        > = BTreeMap::new();

        for vote in votes {
            let key = (
                vote.request.object,
                vote.request.auth_transaction,
                vote.certificate,
            );

            let (_, voters) = groups
                .entry(key)
                .or_insert_with(|| (vote.request, BTreeSet::new()));

            if !voters.insert(vote.authority) {
                return Err(CuttlefishError::DuplicateAuthority(vote.authority));
            }
        }

        let best = groups
            .into_iter()
            .max_by_key(|(_, (_, voters))| voters.len());

        let Some(((.., certificate), (request, voters))) = best else {
            return Err(CuttlefishError::NotEnoughVotes {
                got: 0,
                required: quorum,
            });
        };

        if voters.len() < quorum {
            return Err(CuttlefishError::NotEnoughVotes {
                got: voters.len(),
                required: quorum,
            });
        }

        Ok(CuttlefishUnlockCertificate {
            request,
            certificate,
            voters,
        })
    }

    /// Algorithm 2: ProcessUnlockCert after consensus sequencing.
    pub fn process_unlock_certificate(
        &mut self,
        certificate: &CuttlefishUnlockCertificate,
        quorum: usize,
    ) -> Result<CuttlefishResolution, CuttlefishError> {
        if certificate.voters.len() < quorum {
            return Err(CuttlefishError::NotEnoughVotes {
                got: certificate.voters.len(),
                required: quorum,
            });
        }

        if self.unlock_status(&certificate.request.object)
            == Some(CuttlefishUnlockStatus::Confirmed)
        {
            return Err(CuttlefishError::AlreadyConfirmed(
                certificate.request.object,
            ));
        }

        let resolution = match certificate.certificate {
            Some(tx_certificate) => CuttlefishResolution::ExecuteCertificate(tx_certificate),
            None => CuttlefishResolution::NoopVersionBump {
                old_object: certificate.request.object,
                new_object: certificate.request.object.next_version(),
            },
        };

        self.unlock_db.insert(
            certificate.request.object,
            CuttlefishUnlockStatus::Confirmed,
        );

        Ok(resolution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(tag: u8, version: u64) -> CuttlefishObjectKey {
        CuttlefishObjectKey {
            object_id: [tag; 32],
            version,
        }
    }

    fn request(object: CuttlefishObjectKey) -> CuttlefishUnlockRequest {
        CuttlefishUnlockRequest {
            object,
            auth_transaction: [0xA5; 32],
        }
    }

    #[test]
    fn unlock_vote_disables_fast_path_for_that_version() {
        let object = object(1, 9);
        let request = request(object);
        let mut state = CuttlefishFastUnlockState::new();
        state.set_lock(object, None);

        assert!(state.fast_path_allowed(&object));

        let vote = state
            .process_unlock_request(request, 0, true)
            .expect("authorized unlock request should produce a vote");

        assert_eq!(vote.certificate, None);
        assert_eq!(
            state.unlock_status(&object),
            Some(CuttlefishUnlockStatus::Unlocked)
        );
        assert!(!state.fast_path_allowed(&object));
        assert!(state.fast_path_allowed(&object.next_version()));
    }

    #[test]
    fn no_commit_quorum_produces_noop_version_bump() {
        let object = object(2, 17);
        let request = request(object);
        let quorum = 3;

        let mut validators = (0..4)
            .map(|_| {
                let mut state = CuttlefishFastUnlockState::new();
                state.set_lock(object, None);
                state
            })
            .collect::<Vec<_>>();

        let votes = validators
            .iter_mut()
            .enumerate()
            .map(|(authority, state)| {
                state
                    .process_unlock_request(request, authority as u32, true)
                    .unwrap()
            })
            .take(quorum)
            .collect::<Vec<_>>();

        let unlock_cert = CuttlefishFastUnlockState::assemble_unlock_certificate(votes, quorum)
            .expect("three matching votes should form UnlockCert");

        assert_eq!(unlock_cert.certificate, None);

        for state in &mut validators {
            let resolution = state
                .process_unlock_certificate(&unlock_cert, quorum)
                .expect("consensus-sequenced UnlockCert should process");

            assert_eq!(
                resolution,
                CuttlefishResolution::NoopVersionBump {
                    old_object: object,
                    new_object: object.next_version(),
                }
            );
            assert_eq!(
                state.unlock_status(&object),
                Some(CuttlefishUnlockStatus::Confirmed)
            );
        }
    }

    #[test]
    fn preexisting_certificate_is_executed_instead_of_noop() {
        let object = object(3, 4);
        let request = request(object);
        let tx_cert = CuttlefishCertificateId([0xC7; 32]);
        let quorum = 3;

        let mut validators = (0..4)
            .map(|_| {
                let mut state = CuttlefishFastUnlockState::new();
                state.set_lock(object, Some(tx_cert));
                state
            })
            .collect::<Vec<_>>();

        let votes = validators
            .iter_mut()
            .enumerate()
            .map(|(authority, state)| {
                state
                    .process_unlock_request(request, authority as u32, true)
                    .unwrap()
            })
            .take(quorum)
            .collect::<Vec<_>>();

        let unlock_cert = CuttlefishFastUnlockState::assemble_unlock_certificate(votes, quorum)
            .expect("quorum should form UnlockCert");

        assert_eq!(unlock_cert.certificate, Some(tx_cert));

        let resolution = validators[0]
            .process_unlock_certificate(&unlock_cert, quorum)
            .expect("UnlockCert should process");

        assert_eq!(
            resolution,
            CuttlefishResolution::ExecuteCertificate(tx_cert)
        );
    }

    #[test]
    fn unauthenticated_request_does_not_lock_fast_path() {
        let object = object(4, 1);
        let request = request(object);
        let mut state = CuttlefishFastUnlockState::new();
        state.set_lock(object, None);

        assert_eq!(state.process_unlock_request(request, 0, false), None);
        assert!(state.fast_path_allowed(&object));
        assert_eq!(state.unlock_status(&object), None);
    }

    #[test]
    fn duplicate_authority_cannot_count_twice() {
        let object = object(5, 1);
        let request = request(object);

        let vote = CuttlefishUnlockVote {
            request,
            certificate: None,
            authority: 0,
        };

        let result = CuttlefishFastUnlockState::assemble_unlock_certificate(
            [
                vote,
                vote,
                CuttlefishUnlockVote {
                    authority: 1,
                    ..vote
                },
            ],
            3,
        );

        assert_eq!(result, Err(CuttlefishError::DuplicateAuthority(0)));
    }
    #[test]
    fn unlock_certificate_consensus_encoding_round_trips() {
        let object = object(6, 11);
        let request = request(object);
        let certificate = CuttlefishUnlockCertificate {
            request,
            certificate: Some(CuttlefishCertificateId([0xDD; 32])),
            voters: [0u32, 1, 3].into_iter().collect(),
        };

        let encoded = certificate.encode_consensus_transaction();
        let decoded = CuttlefishUnlockCertificate::decode_consensus_transaction(&encoded)
            .expect("valid encoded UnlockCert should decode");

        assert_eq!(decoded, certificate);

        let mut malformed = encoded.clone();
        malformed.push(0);
        assert_eq!(
            CuttlefishUnlockCertificate::decode_consensus_transaction(&malformed),
            None
        );
    }
}
