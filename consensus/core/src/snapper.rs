// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use consensus_config::AuthorityIndex;
use consensus_types::block::{BlockRef, TransactionIndex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Length of a Sui object identifier.
pub const SNAPPER_OBJECT_ID_LENGTH: usize = 32;

/// An owned-object version tracked by Snapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapperObjectKey {
    pub object_id: [u8; SNAPPER_OBJECT_ID_LENGTH],
    pub version: u64,
}

/// Identifies a transaction by the DAG block in which it was introduced and
/// its transaction index inside that block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapperTransactionRef {
    pub block_ref: BlockRef,
    pub transaction_index: TransactionIndex,
}

/// A validator's current stance for one unresolved owned-object version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapperObjectStance {
    Transaction(SnapperTransactionRef),
    Bottom,
}

/// A stance change recorded in a validator's DAG block.
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
    Commit(SnapperTransactionRef),
    Release,
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

    #[error(
        "conflicting Snapper decision for object {object:?}: existing {existing:?}, new {new:?}"
    )]
    ConflictingDecision {
        object: SnapperObjectKey,
        existing: SnapperObjectDecision,
        new: SnapperObjectDecision,
    },
}

/// In-memory state needed by the Snapper 3f+1 unlocking protocol.
///
/// This type deliberately contains no quorum/certificate logic yet. It only
/// tracks the information that later certificate detection needs:
///
/// - known candidates for each owned-object version;
/// - each validator's latest stance;
/// - whether each validator has ever ACKed a candidate;
/// - the local validator's stance;
/// - whether the object has already been resolved.
pub struct SnapperState {
    own_authority: AuthorityIndex,
    candidates: BTreeMap<SnapperObjectKey, BTreeSet<SnapperTransactionRef>>,
    stances: BTreeMap<SnapperObjectKey, BTreeMap<AuthorityIndex, SnapperObjectStance>>,
    ever_acked: BTreeMap<SnapperObjectKey, BTreeSet<AuthorityIndex>>,
    decisions: BTreeMap<SnapperObjectKey, SnapperObjectDecision>,
}

impl SnapperState {
    pub fn new(own_authority: AuthorityIndex) -> Self {
        Self {
            own_authority,
            candidates: BTreeMap::new(),
            stances: BTreeMap::new(),
            ever_acked: BTreeMap::new(),
            decisions: BTreeMap::new(),
        }
    }

    pub fn own_authority(&self) -> AuthorityIndex {
        self.own_authority
    }

    /// Records a transaction as a known candidate for an owned-object version.
    ///
    /// Candidate visibility is separate from ACKing: a transaction may be
    /// known and propagated through the DAG without the local validator
    /// supporting it.
    pub fn record_candidate(
        &mut self,
        object: SnapperObjectKey,
        transaction: SnapperTransactionRef,
    ) {
        self.candidates
            .entry(object)
            .or_default()
            .insert(transaction);
    }

    pub fn candidates(
        &self,
        object: &SnapperObjectKey,
    ) -> impl Iterator<Item = &SnapperTransactionRef> {
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

    /// Returns whether a current Bottom stance is a skip or unlock vote.
    ///
    /// Returns `None` unless the validator's current stance is Bottom.
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

    /// Applies a stance declaration made by this validator.
    ///
    /// Honest Snapper validators may move only:
    ///
    /// none -> tx
    /// none -> Bottom
    /// tx   -> Bottom
    ///
    /// Repeating the same stance is harmless. Direct tx -> tx' and
    /// Bottom -> tx transitions are rejected.
    pub fn apply_own_stance(
        &mut self,
        object: SnapperObjectKey,
        stance: SnapperObjectStance,
    ) -> Result<(), SnapperStateError> {
        self.apply_stance(self.own_authority, object, stance)
    }

    /// Applies a stance declaration from an authority.
    ///
    /// This currently enforces the honest stance automaton. When we wire this
    /// into block processing, invalid/equivocating peer declarations will be
    /// filtered before reaching this state.
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

    pub fn is_resolved(&self, object: &SnapperObjectKey) -> bool {
        self.decisions.contains_key(object)
    }

    /// Records an irreversible decision for an object version.
    ///
    /// Re-recording the same decision is idempotent; attempting to record a
    /// different decision is an error.
    pub fn record_decision(
        &mut self,
        object: SnapperObjectKey,
        decision: SnapperObjectDecision,
    ) -> Result<(), SnapperStateError> {
        match self.decisions.get(&object).copied() {
            None => {
                self.decisions.insert(object, decision);
                Ok(())
            }
            Some(existing) if existing == decision => Ok(()),
            Some(existing) => Err(SnapperStateError::ConflictingDecision {
                object,
                existing,
                new: decision,
            }),
        }
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

    fn transaction(index: TransactionIndex) -> SnapperTransactionRef {
        SnapperTransactionRef {
            block_ref: BlockRef::MIN,
            transaction_index: index,
        }
    }

    #[test]
    fn ack_then_bottom_is_unlock_vote() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);
        let tx = transaction(0);

        assert_eq!(state.own_stance(&object), None);
        assert!(!state.previously_acked(authority, &object));

        state
            .apply_own_stance(object, SnapperObjectStance::Transaction(tx))
            .unwrap();

        assert_eq!(
            state.own_stance(&object),
            Some(SnapperObjectStance::Transaction(tx))
        );
        assert!(state.previously_acked(authority, &object));
        assert_eq!(state.bottom_vote_kind(authority, &object), None);

        state
            .apply_own_stance(object, SnapperObjectStance::Bottom)
            .unwrap();

        assert_eq!(state.own_stance(&object), Some(SnapperObjectStance::Bottom));
        assert_eq!(
            state.bottom_vote_kind(authority, &object),
            Some(SnapperBottomVoteKind::Unlock)
        );
    }

    #[test]
    fn bottom_without_prior_ack_is_skip_vote() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);

        state
            .apply_own_stance(object, SnapperObjectStance::Bottom)
            .unwrap();

        assert!(!state.previously_acked(authority, &object));
        assert_eq!(
            state.bottom_vote_kind(authority, &object),
            Some(SnapperBottomVoteKind::Skip)
        );
    }

    #[test]
    fn bottom_cannot_return_to_transaction() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);
        let tx = transaction(0);

        state
            .apply_own_stance(object, SnapperObjectStance::Bottom)
            .unwrap();

        let error = state
            .apply_own_stance(object, SnapperObjectStance::Transaction(tx))
            .unwrap_err();

        assert!(matches!(
            error,
            SnapperStateError::IllegalStanceTransition {
                from: SnapperObjectStance::Bottom,
                to: SnapperObjectStance::Transaction(_),
                ..
            }
        ));
    }

    #[test]
    fn validator_cannot_switch_directly_between_transactions() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);
        let tx0 = transaction(0);
        let tx1 = transaction(1);

        state
            .apply_own_stance(object, SnapperObjectStance::Transaction(tx0))
            .unwrap();

        let error = state
            .apply_own_stance(object, SnapperObjectStance::Transaction(tx1))
            .unwrap_err();

        assert!(matches!(
            error,
            SnapperStateError::IllegalStanceTransition {
                from: SnapperObjectStance::Transaction(_),
                to: SnapperObjectStance::Transaction(_),
                ..
            }
        ));
    }

    #[test]
    fn candidate_visibility_is_separate_from_ack() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);
        let tx0 = transaction(0);
        let tx1 = transaction(1);

        state.record_candidate(object, tx0);
        state.record_candidate(object, tx1);

        assert_eq!(state.candidate_count(&object), 2);
        assert!(state.is_conflicted(&object));
        assert_eq!(state.own_stance(&object), None);
        assert!(!state.previously_acked(authority, &object));
    }

    #[test]
    fn decisions_are_irreversible() {
        let authority = AuthorityIndex::new_for_test(0);
        let mut state = SnapperState::new(authority);
        let object = object(0);
        let tx = transaction(0);

        state
            .record_decision(object, SnapperObjectDecision::Commit(tx))
            .unwrap();

        assert_eq!(
            state.decision(&object),
            Some(SnapperObjectDecision::Commit(tx))
        );
        assert!(state.is_resolved(&object));

        state
            .record_decision(object, SnapperObjectDecision::Commit(tx))
            .unwrap();

        assert!(matches!(
            state
                .record_decision(object, SnapperObjectDecision::Release)
                .unwrap_err(),
            SnapperStateError::ConflictingDecision { .. }
        ));
    }
}
