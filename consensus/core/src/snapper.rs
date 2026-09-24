// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use consensus_config::{AuthorityIndex, DIGEST_LENGTH, DefaultHashFunction};
use fastcrypto::hash::HashFunction;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Length of a Sui object identifier.
pub const SNAPPER_OBJECT_ID_LENGTH: usize = 32;

/// Marker used to distinguish evaluation transactions carrying Snapper metadata
/// from ordinary opaque consensus transactions.
const SNAPPER_TRANSACTION_MAGIC: [u8; 8] = *b"SNAP3F1\0";

/// An owned-object version tracked by Snapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapperObjectKey {
    pub object_id: [u8; SNAPPER_OBJECT_ID_LENGTH],
    pub version: u64,
}

/// Stable identifier for a transaction, computed from the transaction bytes.
///
/// We cannot identify a transaction by the block that introduces it because a
/// block may carry both the transaction and the stance ACKing that transaction;
/// using the block digest would create a circular dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapperTransactionId(pub [u8; DIGEST_LENGTH]);

impl SnapperTransactionId {
    pub fn from_transaction_bytes(data: &[u8]) -> Self {
        let mut hasher = DefaultHashFunction::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }
}

/// Experimental transaction envelope used by the Snapper evaluation.
///
/// Normal Sui transactions remain opaque to `consensus-core`. Evaluation
/// transactions carry only the owned-object metadata needed by the Snapper
/// unlocking layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapperTransactionEnvelope {
    magic: [u8; 8],
    pub owned_inputs: Vec<SnapperObjectKey>,
    pub payload: Vec<u8>,
}

impl SnapperTransactionEnvelope {
    pub fn new(owned_inputs: Vec<SnapperObjectKey>, payload: Vec<u8>) -> Self {
        Self {
            magic: SNAPPER_TRANSACTION_MAGIC,
            owned_inputs,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("Snapper transaction serialization should not fail")
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let envelope: Self = bcs::from_bytes(data).ok()?;
        (envelope.magic == SNAPPER_TRANSACTION_MAGIC).then_some(envelope)
    }

    pub fn transaction_id(data: &[u8]) -> SnapperTransactionId {
        SnapperTransactionId::from_transaction_bytes(data)
    }
}

/// A validator's current stance for one unresolved owned-object version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapperObjectStance {
    Transaction(SnapperTransactionId),
    Bottom,
}

/// A stance change recorded in a validator's DAG block.
///
/// Absence of an entry means that the author's previous stance persists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapperObjectStanceVote {
    pub object: SnapperObjectKey,
    pub stance: SnapperObjectStance,
}

/// How a current Bottom stance is interpreted from the validator's history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapperBottomVoteKind {
    Skip,
    Unlock,
}

/// Final resolution of an owned-object version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapperObjectDecision {
    Commit(SnapperTransactionId),
    Release,
}

/// How a Snapper object resolution was reached.
///
/// Evaluation metadata only; it is not consumed by the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapperResolutionPath {
    Fast,
    CommittedAnchor,
}

/// First local observation that an owned-object version has been resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapperResolutionObservation {
    pub decision: SnapperObjectDecision,
    pub path: SnapperResolutionPath,
    pub round: consensus_types::block::Round,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SnapperStateError {
    #[error(
        "illegal Snapper stance transition by authority {authority}: object {object:?}, from {from:?} to {to:?}"
    )]
    IllegalStanceTransition {
        authority: AuthorityIndex,
        object: SnapperObjectKey,
        from: SnapperObjectStance,
        to: SnapperObjectStance,
    },

    #[error("unknown Snapper transaction {0:?}")]
    UnknownTransaction(SnapperTransactionId),

    #[error(
        "conflicting Snapper decision for object {object:?}: existing {existing:?}, new {new:?}"
    )]
    ConflictingDecision {
        object: SnapperObjectKey,
        existing: SnapperObjectDecision,
        new: SnapperObjectDecision,
    },
}

/// Persistent in-memory state used by the Snapper 3f+1 unlocking layer.
///
/// DAG-local predicates such as `Stance(id,o,b)`, `CertVisible`, and
/// `HasCertTX` are evaluated by `TransactionVoteTracker`, because they depend
/// on concrete block ancestry. This type keeps only persistent protocol state.
pub struct SnapperState {
    own_authority: AuthorityIndex,

    candidates: BTreeMap<SnapperObjectKey, BTreeSet<SnapperTransactionId>>,

    transaction_inputs: BTreeMap<SnapperTransactionId, Vec<SnapperObjectKey>>,

    stances: BTreeMap<SnapperObjectKey, BTreeMap<AuthorityIndex, SnapperObjectStance>>,

    ever_acked: BTreeMap<SnapperObjectKey, BTreeSet<AuthorityIndex>>,

    decisions: BTreeMap<SnapperObjectKey, SnapperObjectDecision>,
}

impl SnapperState {
    pub fn new(own_authority: AuthorityIndex) -> Self {
        Self {
            own_authority,
            candidates: BTreeMap::new(),
            transaction_inputs: BTreeMap::new(),
            stances: BTreeMap::new(),
            ever_acked: BTreeMap::new(),
            decisions: BTreeMap::new(),
        }
    }

    pub fn own_authority(&self) -> AuthorityIndex {
        self.own_authority
    }

    /// Records a Snapper evaluation transaction and returns its stable id.
    ///
    /// Ordinary transactions return `None` and are ignored by Snapper.
    pub fn record_transaction(&mut self, data: &[u8]) -> Option<SnapperTransactionId> {
        let envelope = SnapperTransactionEnvelope::decode(data)?;
        let transaction = SnapperTransactionEnvelope::transaction_id(data);

        self.transaction_inputs
            .entry(transaction)
            .or_insert_with(|| envelope.owned_inputs.clone());

        for object in envelope.owned_inputs {
            self.candidates
                .entry(object)
                .or_default()
                .insert(transaction);
        }

        Some(transaction)
    }

    pub fn record_candidate(
        &mut self,
        object: SnapperObjectKey,
        transaction: SnapperTransactionId,
    ) {
        self.candidates
            .entry(object)
            .or_default()
            .insert(transaction);
    }

    pub fn owned_inputs(&self, transaction: SnapperTransactionId) -> Option<&[SnapperObjectKey]> {
        self.transaction_inputs.get(&transaction).map(Vec::as_slice)
    }

    pub fn transaction_ids(&self) -> impl Iterator<Item = SnapperTransactionId> + '_ {
        self.transaction_inputs.keys().copied()
    }

    pub fn objects(&self) -> impl Iterator<Item = SnapperObjectKey> + '_ {
        self.candidates.keys().copied()
    }

    pub fn candidates(
        &self,
        object: &SnapperObjectKey,
    ) -> impl Iterator<Item = &SnapperTransactionId> {
        self.candidates
            .get(object)
            .into_iter()
            .flat_map(|candidates| candidates.iter())
    }

    pub fn candidate_count(&self, object: &SnapperObjectKey) -> usize {
        self.candidates.get(object).map_or(0, BTreeSet::len)
    }

    pub fn is_conflicted(&self, object: &SnapperObjectKey) -> bool {
        self.candidate_count(object) >= 2
    }

    pub fn stance(
        &self,
        authority: AuthorityIndex,
        object: &SnapperObjectKey,
    ) -> Option<SnapperObjectStance> {
        self.stances
            .get(object)
            .and_then(|stances| stances.get(&authority))
            .copied()
    }

    pub fn own_stance(&self, object: &SnapperObjectKey) -> Option<SnapperObjectStance> {
        self.stance(self.own_authority, object)
    }

    pub fn previously_acked(&self, authority: AuthorityIndex, object: &SnapperObjectKey) -> bool {
        self.ever_acked
            .get(object)
            .is_some_and(|authorities| authorities.contains(&authority))
    }

    pub fn bottom_vote_kind(
        &self,
        authority: AuthorityIndex,
        object: &SnapperObjectKey,
    ) -> Option<SnapperBottomVoteKind> {
        if self.stance(authority, object) != Some(SnapperObjectStance::Bottom) {
            return None;
        }

        if self.previously_acked(authority, object) {
            Some(SnapperBottomVoteKind::Unlock)
        } else {
            Some(SnapperBottomVoteKind::Skip)
        }
    }

    pub fn apply_own_stance(
        &mut self,
        object: SnapperObjectKey,
        stance: SnapperObjectStance,
    ) -> Result<(), SnapperStateError> {
        self.apply_stance(self.own_authority, object, stance)
    }

    /// Honest validators may move only:
    ///
    /// none -> tx
    /// none -> Bottom
    /// tx   -> Bottom
    ///
    /// Repeating the same stance is harmless.
    pub fn apply_stance(
        &mut self,
        authority: AuthorityIndex,
        object: SnapperObjectKey,
        new_stance: SnapperObjectStance,
    ) -> Result<(), SnapperStateError> {
        let current = self.stance(authority, &object);

        match (current, new_stance) {
            (None, SnapperObjectStance::Transaction(transaction)) => {
                self.record_candidate(object, transaction);
                self.ever_acked.entry(object).or_default().insert(authority);
                self.stances
                    .entry(object)
                    .or_default()
                    .insert(authority, new_stance);
                Ok(())
            }

            (None, SnapperObjectStance::Bottom) => {
                self.stances
                    .entry(object)
                    .or_default()
                    .insert(authority, new_stance);
                Ok(())
            }

            (
                Some(SnapperObjectStance::Transaction(current_transaction)),
                SnapperObjectStance::Transaction(new_transaction),
            ) if current_transaction == new_transaction => Ok(()),

            (Some(SnapperObjectStance::Transaction(_)), SnapperObjectStance::Bottom) => {
                self.stances
                    .entry(object)
                    .or_default()
                    .insert(authority, SnapperObjectStance::Bottom);
                Ok(())
            }

            (Some(SnapperObjectStance::Bottom), SnapperObjectStance::Bottom) => Ok(()),

            (Some(from), to) => Err(SnapperStateError::IllegalStanceTransition {
                authority,
                object,
                from,
                to,
            }),
        }
    }

    pub fn decision(&self, object: &SnapperObjectKey) -> Option<SnapperObjectDecision> {
        self.decisions.get(object).copied()
    }

    pub fn decisions(
        &self,
    ) -> impl Iterator<Item = (SnapperObjectKey, SnapperObjectDecision)> + '_ {
        self.decisions
            .iter()
            .map(|(object, decision)| (*object, *decision))
    }

    pub fn is_resolved(&self, object: &SnapperObjectKey) -> bool {
        self.decisions.contains_key(object)
    }

    pub fn is_transaction_dead(&self, transaction: SnapperTransactionId) -> bool {
        let Some(inputs) = self.owned_inputs(transaction) else {
            return true;
        };

        inputs.iter().any(|object| {
            self.decision(object)
                .is_some_and(|decision| decision != SnapperObjectDecision::Commit(transaction))
        })
    }

    pub fn can_commit_transaction(&self, transaction: SnapperTransactionId) -> bool {
        let Some(inputs) = self.owned_inputs(transaction) else {
            return false;
        };

        inputs.iter().all(|object| match self.decision(object) {
            None => true,
            Some(SnapperObjectDecision::Commit(existing)) => existing == transaction,
            Some(SnapperObjectDecision::Release) => false,
        })
    }

    /// Commits a transaction on every owned input.
    ///
    /// The operation is atomic with respect to this in-memory state: all inputs
    /// are checked before any decision is written.
    pub fn commit_transaction(
        &mut self,
        transaction: SnapperTransactionId,
    ) -> Result<Vec<(SnapperObjectKey, SnapperObjectDecision)>, SnapperStateError> {
        let Some(inputs) = self.owned_inputs(transaction).map(|inputs| inputs.to_vec()) else {
            return Err(SnapperStateError::UnknownTransaction(transaction));
        };

        let new_decision = SnapperObjectDecision::Commit(transaction);
        for object in &inputs {
            if let Some(existing) = self.decision(object)
                && existing != new_decision
            {
                return Err(SnapperStateError::ConflictingDecision {
                    object: *object,
                    existing,
                    new: new_decision,
                });
            }
        }

        let mut changed = Vec::new();
        for object in inputs {
            if self.decision(&object).is_none() {
                self.decisions.insert(object, new_decision);
                changed.push((object, new_decision));
            }
        }
        Ok(changed)
    }

    pub fn release_object(
        &mut self,
        object: SnapperObjectKey,
    ) -> Result<Vec<(SnapperObjectKey, SnapperObjectDecision)>, SnapperStateError> {
        let new_decision = SnapperObjectDecision::Release;
        match self.decision(&object) {
            None => {
                self.decisions.insert(object, new_decision);
                Ok(vec![(object, new_decision)])
            }
            Some(existing) if existing == new_decision => Ok(vec![]),
            Some(existing) => Err(SnapperStateError::ConflictingDecision {
                object,
                existing,
                new: new_decision,
            }),
        }
    }

    /// Recovery closure for the local proposal history accumulated so far.
    ///
    /// Conflicted objects enter the set first; then all sibling owned inputs of
    /// their candidates are included, matching the closure used by the paper.
    pub fn current_recovery_objects(&self) -> BTreeSet<SnapperObjectKey> {
        let mut recovery = BTreeSet::new();

        for object in self.objects() {
            let has_dead_candidate = self
                .candidates(&object)
                .any(|transaction| self.is_transaction_dead(*transaction));
            if self.is_conflicted(&object) || has_dead_candidate {
                recovery.insert(object);
            }
        }

        loop {
            let before = recovery.len();
            let current = recovery.iter().copied().collect::<Vec<_>>();

            for object in current {
                let candidates = self.candidates.get(&object).cloned().unwrap_or_default();
                for transaction in candidates {
                    if let Some(inputs) = self.owned_inputs(transaction) {
                        recovery.extend(inputs.iter().copied());
                    }
                }
            }

            if recovery.len() == before {
                break;
            }
        }

        recovery
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(version: u64) -> SnapperObjectKey {
        SnapperObjectKey {
            object_id: [7; SNAPPER_OBJECT_ID_LENGTH],
            version,
        }
    }

    fn transaction_bytes(inputs: Vec<SnapperObjectKey>, seed: u8) -> Vec<u8> {
        SnapperTransactionEnvelope::new(inputs, vec![seed; 16]).encode()
    }

    #[test]
    fn envelope_round_trip() {
        let object = object(3);
        let envelope = SnapperTransactionEnvelope::new(vec![object], vec![1, 2, 3]);
        let encoded = envelope.encode();

        assert_eq!(SnapperTransactionEnvelope::decode(&encoded), Some(envelope));
        assert!(SnapperTransactionEnvelope::decode(b"ordinary transaction").is_none());
    }

    #[test]
    fn ack_then_bottom_is_unlock_vote() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);
        let bytes = transaction_bytes(vec![object], 1);
        let tx = state.record_transaction(&bytes).unwrap();

        state
            .apply_own_stance(object, SnapperObjectStance::Transaction(tx))
            .unwrap();
        state
            .apply_own_stance(object, SnapperObjectStance::Bottom)
            .unwrap();

        assert_eq!(
            state.bottom_vote_kind(authority, &object),
            Some(SnapperBottomVoteKind::Unlock)
        );
    }

    #[test]
    fn bottom_without_ack_is_skip_vote() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);

        state
            .apply_own_stance(object, SnapperObjectStance::Bottom)
            .unwrap();

        assert_eq!(
            state.bottom_vote_kind(authority, &object),
            Some(SnapperBottomVoteKind::Skip)
        );
    }

    #[test]
    fn recovery_closes_over_sibling_inputs() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let o0 = object(0);
        let o1 = object(1);

        let tx0 = state
            .record_transaction(&transaction_bytes(vec![o0, o1], 1))
            .unwrap();
        let tx1 = state
            .record_transaction(&transaction_bytes(vec![o0], 2))
            .unwrap();

        assert_ne!(tx0, tx1);

        let recovery = state.current_recovery_objects();
        assert!(recovery.contains(&o0));
        assert!(recovery.contains(&o1));
    }

    #[test]
    fn transaction_decision_is_atomic_across_owned_inputs() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let o0 = object(0);
        let o1 = object(1);
        let tx = state
            .record_transaction(&transaction_bytes(vec![o0, o1], 1))
            .unwrap();

        let changed = state.commit_transaction(tx).unwrap();
        assert_eq!(changed.len(), 2);
        assert_eq!(state.decision(&o0), Some(SnapperObjectDecision::Commit(tx)));
        assert_eq!(state.decision(&o1), Some(SnapperObjectDecision::Commit(tx)));
    }
}
