// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use consensus_config::Stake;
use consensus_types::block::{BlockRef, Round, TransactionIndex};
use mysten_common::ZipDebugEqIteratorExt;
use parking_lot::RwLock;
use tracing::info;

use crate::{
    BlockAPI as _, VerifiedBlock,
    block::{BlockTransactionVotes, GENESIS_ROUND, Transaction},
    block_verifier::BlockVerifier,
    context::Context,
    dag_state::DagState,
    snapper::{
        SnapperBottomVoteKind, SnapperObjectDecision, SnapperObjectKey, SnapperObjectStance,
        SnapperObjectStanceVote, SnapperState, SnapperTransactionEnvelope, SnapperTransactionId,
    },
    stake_aggregator::{QuorumThreshold, StakeAggregator},
};

/// TransactionVoteTracker has the following purposes:
/// 1. Keeps track of own votes on transactions, and allows the votes to be retrieved
///    later in core after acceptance of the blocks containing the transactions.
/// 2. Aggregates reject votes on transactions, and allows the aggregated votes
///    to be retrieved during post-commit finalization.
///
/// A transaction is rejected if a quorum of authorities vote to reject it. When this happens, it is
/// guaranteed that no validator can observe a certification of the transaction, with <= f malicious
/// stake.
#[derive(Clone)]
pub struct TransactionVoteTracker {
    // The state of blocks being voted on.
    vote_tracker_state: Arc<RwLock<VoteTrackerState>>,
    // Verify transactions during recovery.
    block_verifier: Arc<dyn BlockVerifier>,
    // The state of the DAG.
    dag_state: Arc<RwLock<DagState>>,
}

impl TransactionVoteTracker {
    pub fn new(
        context: Arc<Context>,
        block_verifier: Arc<dyn BlockVerifier>,
        dag_state: Arc<RwLock<DagState>>,
    ) -> Self {
        Self {
            vote_tracker_state: Arc::new(RwLock::new(VoteTrackerState::new(context))),
            block_verifier,
            dag_state,
        }
    }

    /// Recovers all blocks from DB after the given round.
    ///
    /// This is useful for initializing the vote tracker state
    /// for future commits and block proposals.
    pub(crate) fn recover_blocks_after_round(&self, after_round: Round) {
        let context = self.vote_tracker_state.read().context.clone();
        if !context.protocol_config.transaction_voting_enabled() {
            info!("Skipping vote tracker recovery in non-mysticeti fast path mode");
            return;
        }

        let store = self.dag_state.read().store().clone();

        let recovery_start_round = after_round + 1;
        info!(
            "Recovering vote tracker state from round {}",
            recovery_start_round,
        );

        let authorities = context
            .committee
            .authorities()
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        for authority_index in authorities {
            let blocks = store
                .scan_blocks_by_author(authority_index, recovery_start_round)
                .unwrap();
            info!(
                "Recovered and voting on {} blocks from authority {} {}",
                blocks.len(),
                authority_index,
                context.committee.authority(authority_index).hostname
            );
            self.recover_and_vote_on_blocks(blocks);
        }
    }

    /// Recovers and potentially votes on the given blocks.
    ///
    /// Because own votes on blocks are not stored, during recovery it is necessary to vote on
    /// input blocks that are above GC round and have not been included before, which can be
    /// included in a future proposed block.
    ///
    /// In addition, add_voted_blocks() will eventually process reject votes contained in the input blocks.
    pub(crate) fn recover_and_vote_on_blocks(&self, blocks: Vec<VerifiedBlock>) {
        let context = self.vote_tracker_state.read().context.clone();
        let should_vote_blocks = {
            let dag_state = self.dag_state.read();
            let gc_round = dag_state.gc_round();
            blocks
                .iter()
                // Must make sure the block is above GC round before calling has_been_included().
                .map(|b| b.round() > gc_round && !dag_state.has_been_included(&b.reference()))
                .collect::<Vec<_>>()
        };
        let voted_blocks = blocks
            .into_iter()
            .zip_debug_eq(should_vote_blocks)
            .map(|(b, should_vote)| {
                if !should_vote {
                    // Voting is unnecessary for blocks already included in own proposed blocks,
                    // or outside of local DAG GC bound.
                    (b, vec![])
                } else {
                    // Voting is needed for blocks above GC round and not yet included in own proposed blocks.
                    // A block proposal can include the input block later and retries own votes on it.
                    let reject_transaction_votes =
                        self.block_verifier.vote(&b).unwrap_or_else(|e| {
                            panic!(
                                "Failed to vote on block {} (own_index={}) during recovery: {}",
                                b.reference(),
                                context.own_index,
                                e
                            )
                        });
                    (b, reject_transaction_votes)
                }
            })
            .collect::<Vec<_>>();
        self.vote_tracker_state
            .write()
            .add_voted_blocks(voted_blocks);
    }

    /// Stores own reject votes on input blocks, and aggregates reject votes from the input blocks.
    pub fn add_voted_blocks(&self, voted_blocks: Vec<(VerifiedBlock, Vec<TransactionIndex>)>) {
        self.vote_tracker_state
            .write()
            .add_voted_blocks(voted_blocks);
    }

    /// Retrieves own votes on peer block transactions.
    pub(crate) fn get_own_votes(&self, block_refs: Vec<BlockRef>) -> Vec<BlockTransactionVotes> {
        let mut votes = vec![];
        let vote_tracker_state = self.vote_tracker_state.read();
        for block_ref in block_refs {
            if block_ref.round <= vote_tracker_state.gc_round {
                continue;
            }
            let vote_info = vote_tracker_state.votes.get(&block_ref).unwrap_or_else(|| {
                panic!(
                    "Ancestor block {} not found in vote tracker state",
                    block_ref
                )
            });
            if !vote_info.own_reject_txn_votes.is_empty() {
                votes.push(BlockTransactionVotes {
                    block_ref,
                    rejects: vote_info.own_reject_txn_votes.clone(),
                });
            }
        }
        votes
    }

    /// Processes the newly linked causal history for Snapper and returns local
    /// stance changes to include in the next proposed block.
    pub(crate) fn get_snapper_stance_votes(
        &self,
        proposal_round: Round,
        proposal_parents: &[BlockRef],
        block_refs: &[BlockRef],
        current_transactions: &[Transaction],
    ) -> Vec<SnapperObjectStanceVote> {
        self.vote_tracker_state.write().get_snapper_stance_votes(
            proposal_round,
            proposal_parents,
            block_refs,
            current_transactions,
        )
    }

    /// Applies the Snapper committed-anchor rule to a committed Mysticeti
    /// leader. Transaction certificates have priority over skip/unlock
    /// certificates, exactly as in ResolveOnCommitObj.
    pub(crate) fn resolve_snapper_committed_anchor(
        &self,
        anchor: BlockRef,
        committed_blocks: &[VerifiedBlock],
    ) -> Vec<(SnapperObjectKey, SnapperObjectDecision)> {
        self.vote_tracker_state
            .write()
            .resolve_snapper_committed_anchor(anchor, committed_blocks)
    }

    pub fn snapper_decision(&self, object: &SnapperObjectKey) -> Option<SnapperObjectDecision> {
        self.vote_tracker_state
            .read()
            .snapper_state
            .decision(object)
    }

    /// Retrieves transactions in the block that have received reject votes, and the total stake of the votes.
    /// TransactionIndex not included in the output has no reject votes.
    /// Returns None if no information is found for the block.
    pub(crate) fn get_reject_votes(
        &self,
        block_ref: &BlockRef,
    ) -> Option<Vec<(TransactionIndex, Stake)>> {
        let accumulated_reject_votes = self
            .vote_tracker_state
            .read()
            .votes
            .get(block_ref)?
            .reject_txn_votes
            .iter()
            .map(|(idx, stake_agg)| (*idx, stake_agg.stake()))
            .collect::<Vec<_>>();
        Some(accumulated_reject_votes)
    }

    /// Runs garbage collection on the internal state by removing data for blocks <= gc_round,
    /// and updates the GC round for the vote tracker.
    ///
    /// IMPORTANT: the gc_round used here can trail the latest gc_round from DagState.
    /// This is because the gc round here is determined by CommitFinalizer, which needs to process
    /// commits before the latest commit in DagState. Reject votes received by transactions below
    /// local DAG gc_round may still need to be accessed from CommitFinalizer.
    pub(crate) fn run_gc(&self, gc_round: Round) {
        let dag_state_gc_round = self.dag_state.read().gc_round();
        assert!(
            gc_round <= dag_state_gc_round,
            "TransactionVoteTracker cannot GC higher than DagState GC round ({} > {})",
            gc_round,
            dag_state_gc_round
        );
        self.vote_tracker_state.write().update_gc_round(gc_round);
    }
}

/// VoteTrackerState keeps track of votes received by each transaction and block,
/// and helps determine if votes reach a quorum. Reject votes can start accumulating
/// even before the target block is received by this authority.
struct VoteTrackerState {
    context: Arc<Context>,

    // Maps received blocks' refs to votes on those blocks from other blocks.
    // Even if a block has no reject votes on its transactions, it still has an entry here.
    votes: BTreeMap<BlockRef, VoteInfo>,

    // Highest round where blocks are GC'ed.
    gc_round: Round,

    // Snapper 3f+1 object-level state.
    snapper_state: SnapperState,

    // Blocks available to Snapper's DAG-local predicates. This is separate
    // from the legacy transaction vote map because committed-anchor recovery
    // may need to inspect blocks without changing legacy reject-vote state.
    snapper_blocks: BTreeMap<BlockRef, VerifiedBlock>,

    // Blocks whose Snapper transactions and stance declarations have already
    // been incorporated into snapper_state.
    snapper_processed_blocks: BTreeSet<BlockRef>,
}

impl VoteTrackerState {
    fn new(context: Arc<Context>) -> Self {
        let own_authority = context.own_index;
        Self {
            context,
            votes: BTreeMap::new(),
            gc_round: GENESIS_ROUND,
            snapper_state: SnapperState::new(own_authority),
            snapper_blocks: BTreeMap::new(),
            snapper_processed_blocks: BTreeSet::new(),
        }
    }

    fn get_snapper_stance_votes(
        &mut self,
        proposal_round: Round,
        proposal_parents: &[BlockRef],
        block_refs: &[BlockRef],
        current_transactions: &[Transaction],
    ) -> Vec<SnapperObjectStanceVote> {
        // Reconstruct all proposal-parent history needed after recovery, then
        // incorporate newly linked history.
        let mut to_process = block_refs.to_vec();
        for parent in proposal_parents {
            to_process.extend(self.snapper_causal_history_refs(*parent));
        }
        to_process.sort();
        to_process.dedup();
        self.process_snapper_blocks(&to_process);

        // Transactions carried by the block being built are reflexively
        // included by that block.
        for transaction in current_transactions {
            self.snapper_state.record_transaction(transaction.data());
        }

        // TryDecide precedes CastVotes in the protocol.
        let _ = self.snapper_try_fast_decisions();

        self.snapper_take_stance_changes(proposal_round, proposal_parents)
    }

    fn observe_snapper_blocks(&mut self, blocks: &[VerifiedBlock]) {
        for block in blocks {
            self.snapper_blocks
                .entry(block.reference())
                .or_insert_with(|| block.clone());
        }
    }

    fn process_snapper_blocks(&mut self, block_refs: &[BlockRef]) {
        let mut blocks = block_refs
            .iter()
            .filter(|block_ref| !self.snapper_processed_blocks.contains(block_ref))
            .filter_map(|block_ref| self.snapper_blocks.get(block_ref).cloned())
            .collect::<Vec<_>>();
        blocks.sort_by_key(|block| block.reference());

        for block in blocks {
            for transaction in block.transactions() {
                self.snapper_state.record_transaction(transaction.data());
            }

            for vote in block.snapper_object_stance_votes() {
                if let Err(error) =
                    self.snapper_state
                        .apply_stance(block.author(), vote.object, vote.stance)
                {
                    tracing::debug!(
                        "Ignoring invalid Snapper stance in block {}: {}",
                        block.reference(),
                        error
                    );
                }
            }

            self.snapper_processed_blocks.insert(block.reference());
        }
    }

    fn snapper_own_ancestor(&self, block: &VerifiedBlock) -> Option<BlockRef> {
        block
            .ancestors()
            .iter()
            .copied()
            .find(|ancestor| ancestor.author == block.author())
    }

    /// Stance(id,o,b): latest declaration for `o` in b's author's own chain.
    fn snapper_stance_at(
        &self,
        block_ref: BlockRef,
        object: &SnapperObjectKey,
    ) -> Option<SnapperObjectStance> {
        let author = block_ref.author;
        let mut current = Some(block_ref);

        while let Some(reference) = current {
            let block = self.snapper_blocks.get(&reference)?;
            if block.author() != author {
                return None;
            }

            if let Some(vote) = block
                .snapper_object_stance_votes()
                .iter()
                .rev()
                .find(|vote| &vote.object == object)
            {
                return Some(vote.stance);
            }

            current = self.snapper_own_ancestor(block);
        }

        None
    }

    /// AckedBefore(id,o,b): an earlier declaration in id's own chain ACKed a
    /// transaction for this object.
    fn snapper_acked_before(&self, block_ref: BlockRef, object: &SnapperObjectKey) -> bool {
        let Some(block) = self.snapper_blocks.get(&block_ref) else {
            return false;
        };
        let author = block.author();
        let mut current = self.snapper_own_ancestor(block);

        while let Some(reference) = current {
            let Some(block) = self.snapper_blocks.get(&reference) else {
                return false;
            };
            if block.author() != author {
                return false;
            }

            if block.snapper_object_stance_votes().iter().any(|vote| {
                vote.object == *object && matches!(vote.stance, SnapperObjectStance::Transaction(_))
            }) {
                return true;
            }

            current = self.snapper_own_ancestor(block);
        }

        false
    }

    fn snapper_causal_history_refs(&self, root: BlockRef) -> Vec<BlockRef> {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];

        while let Some(reference) = stack.pop() {
            if !visited.insert(reference) {
                continue;
            }
            let Some(block) = self.snapper_blocks.get(&reference) else {
                continue;
            };
            stack.extend(block.ancestors().iter().copied());
        }

        visited.into_iter().collect()
    }

    fn snapper_owned_inputs_for_tx(
        &self,
        transaction: SnapperTransactionId,
    ) -> Option<Vec<SnapperObjectKey>> {
        if let Some(inputs) = self.snapper_state.owned_inputs(transaction) {
            return Some(inputs.to_vec());
        }

        for block in self.snapper_blocks.values() {
            for tx in block.transactions() {
                let Some(envelope) = SnapperTransactionEnvelope::decode(tx.data()) else {
                    continue;
                };
                if SnapperTransactionEnvelope::transaction_id(tx.data()) == transaction {
                    return Some(envelope.owned_inputs);
                }
            }
        }

        None
    }

    /// Includes(b,tx): tx appears in b's reflexive causal history.
    fn snapper_includes(&self, root: BlockRef, transaction: SnapperTransactionId) -> bool {
        for reference in self.snapper_causal_history_refs(root) {
            let Some(block) = self.snapper_blocks.get(&reference) else {
                continue;
            };
            for tx in block.transactions() {
                if SnapperTransactionEnvelope::decode(tx.data()).is_some()
                    && SnapperTransactionEnvelope::transaction_id(tx.data()) == transaction
                {
                    return true;
                }
            }
        }
        false
    }

    fn snapper_visible_candidates(
        &self,
        root: BlockRef,
        object: &SnapperObjectKey,
    ) -> BTreeSet<SnapperTransactionId> {
        let mut candidates = BTreeSet::new();

        for reference in self.snapper_causal_history_refs(root) {
            let Some(block) = self.snapper_blocks.get(&reference) else {
                continue;
            };
            for tx in block.transactions() {
                let Some(envelope) = SnapperTransactionEnvelope::decode(tx.data()) else {
                    continue;
                };
                if envelope.owned_inputs.contains(object) {
                    candidates.insert(SnapperTransactionEnvelope::transaction_id(tx.data()));
                }
            }
        }

        candidates
    }

    /// RecoveryObjs(b), specialized to the owned-object evaluation path.
    ///
    /// Conflict is computed from b's causal history and then closed over all
    /// sibling owned inputs of the conflicting candidates.
    fn snapper_recovery_objects_at(&self, root: BlockRef) -> BTreeSet<SnapperObjectKey> {
        let mut candidates: BTreeMap<SnapperObjectKey, BTreeSet<SnapperTransactionId>> =
            BTreeMap::new();
        let mut inputs_by_tx: BTreeMap<SnapperTransactionId, Vec<SnapperObjectKey>> =
            BTreeMap::new();

        for reference in self.snapper_causal_history_refs(root) {
            let Some(block) = self.snapper_blocks.get(&reference) else {
                continue;
            };
            for tx in block.transactions() {
                let Some(envelope) = SnapperTransactionEnvelope::decode(tx.data()) else {
                    continue;
                };
                let transaction = SnapperTransactionEnvelope::transaction_id(tx.data());
                inputs_by_tx
                    .entry(transaction)
                    .or_insert_with(|| envelope.owned_inputs.clone());
                for object in envelope.owned_inputs {
                    candidates.entry(object).or_default().insert(transaction);
                }
            }
        }

        let mut recovery = candidates
            .iter()
            .filter_map(|(object, txs)| (txs.len() >= 2).then_some(*object))
            .collect::<BTreeSet<_>>();

        loop {
            let before = recovery.len();
            let current = recovery.iter().copied().collect::<Vec<_>>();
            for object in current {
                let txs = candidates.get(&object).cloned().unwrap_or_default();
                for transaction in txs {
                    if let Some(inputs) = inputs_by_tx.get(&transaction) {
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

    fn snapper_round_parents(&self, block_ref: BlockRef) -> Vec<BlockRef> {
        let Some(block) = self.snapper_blocks.get(&block_ref) else {
            return vec![];
        };
        let parent_round = block.round().saturating_sub(1);
        block
            .ancestors()
            .iter()
            .copied()
            .filter(|parent| parent.round == parent_round)
            .collect()
    }

    /// IsFastVoteTX(b,tx).
    fn snapper_is_fast_vote(&self, block_ref: BlockRef, transaction: SnapperTransactionId) -> bool {
        if !self.snapper_includes(block_ref, transaction) {
            return false;
        }

        let Some(inputs) = self.snapper_owned_inputs_for_tx(transaction) else {
            return false;
        };

        inputs.iter().all(|object| {
            self.snapper_stance_at(block_ref, object)
                == Some(SnapperObjectStance::Transaction(transaction))
        })
    }

    /// IsFastCertTX(b,tx).
    fn snapper_is_fast_cert(&self, block_ref: BlockRef, transaction: SnapperTransactionId) -> bool {
        if !self.snapper_is_fast_vote(block_ref, transaction) {
            return false;
        }

        let mut authors = BTreeSet::new();
        let mut stake = 0;
        for parent in self.snapper_round_parents(block_ref) {
            if self.snapper_is_fast_vote(parent, transaction) && authors.insert(parent.author) {
                stake += self.context.committee.stake(parent.author);
            }
        }

        self.context.committee.reached_quorum(stake)
    }

    /// HasCertTX(b,tx), reflexive.
    fn snapper_has_cert(&self, root: BlockRef, transaction: SnapperTransactionId) -> bool {
        self.snapper_causal_history_refs(root)
            .into_iter()
            .any(|reference| self.snapper_is_fast_cert(reference, transaction))
    }

    /// CertVisible for the block currently being proposed.
    ///
    /// This intentionally reads only the proposed block's parents and their
    /// causal histories; it never reads the stance being chosen for the new
    /// block.
    fn snapper_cert_visible(
        &self,
        proposal_round: Round,
        proposal_parents: &[BlockRef],
        transaction: SnapperTransactionId,
    ) -> bool {
        let parent_round = proposal_round.saturating_sub(1);
        let mut authors = BTreeSet::new();
        let mut stake = 0;

        for parent in proposal_parents
            .iter()
            .copied()
            .filter(|parent| parent.round == parent_round)
        {
            if self.snapper_is_fast_vote(parent, transaction) && authors.insert(parent.author) {
                stake += self.context.committee.stake(parent.author);
            }
        }

        if self.context.committee.reached_quorum(stake) {
            return true;
        }

        proposal_parents
            .iter()
            .copied()
            .any(|parent| self.snapper_has_cert(parent, transaction))
    }

    fn snapper_bottom_vote_kind_at(
        &self,
        block_ref: BlockRef,
        object: &SnapperObjectKey,
    ) -> Option<SnapperBottomVoteKind> {
        if self.snapper_stance_at(block_ref, object) != Some(SnapperObjectStance::Bottom) {
            return None;
        }

        if !self.snapper_recovery_objects_at(block_ref).contains(object) {
            return None;
        }

        if self.snapper_acked_before(block_ref, object) {
            Some(SnapperBottomVoteKind::Unlock)
        } else {
            Some(SnapperBottomVoteKind::Skip)
        }
    }

    /// IsSkipCertObj(b,o).
    fn snapper_is_skip_cert(&self, block_ref: BlockRef, object: &SnapperObjectKey) -> bool {
        let mut authors = BTreeSet::new();
        let mut stake = 0;

        for parent in self.snapper_round_parents(block_ref) {
            if self.snapper_bottom_vote_kind_at(parent, object) == Some(SnapperBottomVoteKind::Skip)
                && authors.insert(parent.author)
            {
                stake += self.context.committee.stake(parent.author);
            }
        }

        self.context.committee.reached_quorum(stake)
    }

    /// IsUnlockCertObj(b,o): both skip and unlock votes count toward the
    /// opposing quorum.
    fn snapper_is_unlock_cert(&self, block_ref: BlockRef, object: &SnapperObjectKey) -> bool {
        let mut authors = BTreeSet::new();
        let mut stake = 0;

        for parent in self.snapper_round_parents(block_ref) {
            if self.snapper_bottom_vote_kind_at(parent, object).is_some()
                && authors.insert(parent.author)
            {
                stake += self.context.committee.stake(parent.author);
            }
        }

        self.context.committee.reached_quorum(stake)
    }

    fn snapper_has_opposing_cert(&self, root: BlockRef, object: &SnapperObjectKey) -> bool {
        self.snapper_causal_history_refs(root)
            .into_iter()
            .any(|reference| {
                self.snapper_is_skip_cert(reference, object)
                    || self.snapper_is_unlock_cert(reference, object)
            })
    }

    /// TryFastDecideTX and TrySkipDecideObj.
    fn snapper_try_fast_decisions(&mut self) -> Vec<(SnapperObjectKey, SnapperObjectDecision)> {
        let mut changed = Vec::new();
        let rounds = self
            .snapper_blocks
            .keys()
            .map(|reference| reference.round)
            .filter(|round| *round > GENESIS_ROUND)
            .collect::<BTreeSet<_>>();

        for round in rounds {
            let round_blocks = self
                .snapper_blocks
                .keys()
                .copied()
                .filter(|reference| reference.round == round)
                .collect::<Vec<_>>();

            let transactions = self.snapper_state.transaction_ids().collect::<Vec<_>>();
            let mut fast_commits = Vec::new();

            for transaction in transactions {
                if !self.snapper_state.can_commit_transaction(transaction) {
                    continue;
                }

                let mut authors = BTreeSet::new();
                let mut stake = 0;
                for block_ref in &round_blocks {
                    if self.snapper_is_fast_cert(*block_ref, transaction)
                        && authors.insert(block_ref.author)
                    {
                        stake += self.context.committee.stake(block_ref.author);
                    }
                }

                if self.context.committee.reached_quorum(stake) {
                    fast_commits.push(transaction);
                }
            }

            for transaction in fast_commits {
                if let Ok(decisions) = self.snapper_state.commit_transaction(transaction) {
                    changed.extend(decisions);
                }
            }

            let objects = self.snapper_state.objects().collect::<Vec<_>>();
            let mut fast_releases = Vec::new();

            for object in objects {
                if self.snapper_state.is_resolved(&object) {
                    continue;
                }

                let mut authors = BTreeSet::new();
                let mut stake = 0;
                for block_ref in &round_blocks {
                    if self.snapper_is_skip_cert(*block_ref, &object)
                        && authors.insert(block_ref.author)
                    {
                        stake += self.context.committee.stake(block_ref.author);
                    }
                }

                if self.context.committee.reached_quorum(stake) {
                    fast_releases.push(object);
                }
            }

            for object in fast_releases {
                if let Ok(decisions) = self.snapper_state.release_object(object) {
                    changed.extend(decisions);
                }
            }
        }

        changed
    }

    /// CastVotes for the block currently being built.
    fn snapper_take_stance_changes(
        &mut self,
        proposal_round: Round,
        proposal_parents: &[BlockRef],
    ) -> Vec<SnapperObjectStanceVote> {
        let recovery = self.snapper_state.current_recovery_objects();
        let mut changes = Vec::new();

        // Phase 2: objects in recovery.
        for object in recovery.iter().copied() {
            if self.snapper_state.is_resolved(&object) {
                continue;
            }

            let should_bottom = match self.snapper_state.own_stance(&object) {
                None => true,
                Some(SnapperObjectStance::Bottom) => false,
                Some(SnapperObjectStance::Transaction(transaction)) => {
                    let dead = self.snapper_state.is_transaction_dead(transaction);
                    let sibling_abandoned = self
                        .snapper_state
                        .owned_inputs(transaction)
                        .map(|inputs| {
                            inputs.iter().any(|input| {
                                self.snapper_state.own_stance(input)
                                    != Some(SnapperObjectStance::Transaction(transaction))
                            })
                        })
                        .unwrap_or(true);
                    let certificate_visible =
                        self.snapper_cert_visible(proposal_round, proposal_parents, transaction);

                    dead || sibling_abandoned || !certificate_visible
                }
            };

            if should_bottom {
                self.snapper_state
                    .apply_own_stance(object, SnapperObjectStance::Bottom)
                    .expect("tx -> Bottom and none -> Bottom are legal Snapper transitions");
                changes.push(SnapperObjectStanceVote {
                    object,
                    stance: SnapperObjectStance::Bottom,
                });
            }
        }

        // Phase 3: uncontested ACKs.
        let objects = self.snapper_state.objects().collect::<Vec<_>>();
        for object in objects {
            if self.snapper_state.is_resolved(&object) || recovery.contains(&object) {
                continue;
            }

            let candidates = self
                .snapper_state
                .candidates(&object)
                .copied()
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                continue;
            }

            let transaction = candidates[0];
            if self.snapper_state.own_stance(&object).is_none() {
                let stance = SnapperObjectStance::Transaction(transaction);
                self.snapper_state
                    .apply_own_stance(object, stance)
                    .expect("none -> tx is a legal Snapper transition");
                changes.push(SnapperObjectStanceVote { object, stance });
            }
        }

        changes
    }

    /// FinalizeOnCommitTX + ResolveOnCommitObj for the owned-object
    /// evaluation path.
    fn resolve_snapper_committed_anchor(
        &mut self,
        anchor: BlockRef,
        committed_blocks: &[VerifiedBlock],
    ) -> Vec<(SnapperObjectKey, SnapperObjectDecision)> {
        self.observe_snapper_blocks(committed_blocks);

        let history = self.snapper_causal_history_refs(anchor);
        self.process_snapper_blocks(&history);

        let mut changed = self.snapper_try_fast_decisions();
        let recovery = self.snapper_recovery_objects_at(anchor);

        // FinalizeOnCommitTX: certified transactions outside recovery can be
        // finalized directly from the committed anchor.
        let transactions = self.snapper_state.transaction_ids().collect::<Vec<_>>();
        for transaction in transactions {
            if !self.snapper_state.can_commit_transaction(transaction)
                || self.snapper_state.is_transaction_dead(transaction)
                || !self.snapper_includes(anchor, transaction)
                || !self.snapper_has_cert(anchor, transaction)
            {
                continue;
            }

            let Some(inputs) = self.snapper_state.owned_inputs(transaction) else {
                continue;
            };
            if inputs.iter().any(|object| recovery.contains(object)) {
                continue;
            }

            if let Ok(decisions) = self.snapper_state.commit_transaction(transaction) {
                changed.extend(decisions);
            }
        }

        // ResolveOnCommitObj: certificate branch has priority. Only if no
        // viable transaction certificate is in the committed causal history
        // may a skip/unlock certificate release the object.
        for object in recovery {
            if self.snapper_state.is_resolved(&object) {
                continue;
            }

            let candidates = self.snapper_visible_candidates(anchor, &object);
            let certified = candidates
                .iter()
                .copied()
                .filter(|transaction| {
                    self.snapper_state.can_commit_transaction(*transaction)
                        && !self.snapper_state.is_transaction_dead(*transaction)
                        && self.snapper_has_cert(anchor, *transaction)
                })
                .collect::<Vec<_>>();

            if let Some(transaction) = certified.first().copied() {
                debug_assert!(
                    certified.len() == 1,
                    "two conflicting transactions should not both have Snapper certificates"
                );
                if let Ok(decisions) = self.snapper_state.commit_transaction(transaction) {
                    changed.extend(decisions);
                }
                continue;
            }

            if self.snapper_has_opposing_cert(anchor, &object)
                && let Ok(decisions) = self.snapper_state.release_object(object)
            {
                changed.extend(decisions);
            }
        }

        changed
    }

    fn add_voted_blocks(&mut self, voted_blocks: Vec<(VerifiedBlock, Vec<TransactionIndex>)>) {
        for (voted_block, reject_txn_votes) in voted_blocks {
            self.add_voted_block(voted_block, reject_txn_votes);
        }
    }

    fn add_voted_block(
        &mut self,
        voted_block: VerifiedBlock,
        reject_txn_votes: Vec<TransactionIndex>,
    ) {
        if voted_block.round() <= self.gc_round {
            // Ignore the block and own votes, since they are outside of vote tracker GC bound.
            return;
        }

        self.snapper_blocks
            .entry(voted_block.reference())
            .or_insert_with(|| voted_block.clone());

        // Count own reject votes against each peer authority.
        let peer_hostname = &self
            .context
            .committee
            .authority(voted_block.author())
            .hostname;
        self.context
            .metrics
            .node_metrics
            .certifier_own_reject_votes
            .with_label_values(&[peer_hostname])
            .inc_by(reject_txn_votes.len() as u64);

        // Initialize the entry for the voted block.
        let vote_info = self.votes.entry(voted_block.reference()).or_default();
        if vote_info.block.is_some() {
            // Input block has already been processed and added to the state.
            return;
        }
        vote_info.block = Some(voted_block.clone());
        vote_info.own_reject_txn_votes = reject_txn_votes;

        // Update reject votes from the input block.
        for block_votes in voted_block.transaction_votes() {
            if block_votes.block_ref.round <= self.gc_round {
                // Block is outside of GC bound.
                continue;
            }
            let vote_info = self.votes.entry(block_votes.block_ref).or_default();
            for reject in &block_votes.rejects {
                vote_info
                    .reject_txn_votes
                    .entry(*reject)
                    .or_default()
                    .add_unique(voted_block.author(), &self.context.committee);
            }
        }
    }

    /// Updates the GC round and cleans up obsolete internal state.
    fn update_gc_round(&mut self, gc_round: Round) {
        self.gc_round = gc_round;
        while let Some((block_ref, _)) = self.votes.first_key_value() {
            if block_ref.round <= self.gc_round {
                self.votes.pop_first();
            } else {
                break;
            }
        }
        self.snapper_processed_blocks
            .retain(|block_ref| block_ref.round > self.gc_round);

        self.context
            .metrics
            .node_metrics
            .certifier_gc_round
            .set(self.gc_round as i64);
    }
}

/// VoteInfo keeps track of votes received for each transaction of this block,
/// possibly even before the block is received by this authority.
#[derive(Default)]
struct VoteInfo {
    // Content of the block.
    // None if the blocks has not been received.
    block: Option<VerifiedBlock>,
    // Rejection votes by this authority on this block.
    // This field is written when the block is first received and its transactions are voted on.
    // It is read from core after the block is accepted.
    own_reject_txn_votes: Vec<TransactionIndex>,
    // Accumulates reject votes per transaction in this block.
    reject_txn_votes: BTreeMap<TransactionIndex, StakeAggregator<QuorumThreshold>>,
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use consensus_config::{AuthorityIndex, Parameters};

    use crate::{
        TestBlock, Transaction, VerifiedBlock, block::BlockTransactionVotes, context::Context,
        metrics::test_metrics,
    };

    use super::*;

    // 4 authorities with stakes [1, 2, 3, 4], total 10.
    #[tokio::test]
    async fn test_reject_vote_tracking() {
        telemetry_subscribers::init_for_testing();
        let (committee, _keypairs) =
            consensus_config::local_committee_and_keys(0, vec![1, 2, 3, 4]);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let context = Arc::new(Context::new(
            0,
            Some(AuthorityIndex::new_for_test(0)),
            committee,
            Parameters {
                db_path: temp_dir.path().to_path_buf(),
                ..Default::default()
            },
            consensus_config::ConsensusProtocolConfig::for_testing(),
            test_metrics(),
            Arc::new(crate::Clock::default()),
        ));

        let transactions = vec![Transaction::new(vec![0u8; 16]); 4];

        // Round 1: create a block from each authority.
        let round_1_blocks: Vec<VerifiedBlock> = (0..4)
            .map(|author| {
                VerifiedBlock::new_for_test(
                    TestBlock::new(1, author)
                        .set_transactions(transactions.clone())
                        .build(),
                )
            })
            .collect();

        // Add round 1 blocks with own reject votes:
        // - reject txn 0 of block from authority 0
        // - reject txns 1 and 2 of block from authority 1
        // - no rejects for blocks from authorities 2 and 3
        let mut state = VoteTrackerState::new(context.clone());
        state.add_voted_blocks(vec![
            (round_1_blocks[0].clone(), vec![0]),
            (round_1_blocks[1].clone(), vec![1, 2]),
            (round_1_blocks[2].clone(), vec![]),
            (round_1_blocks[3].clone(), vec![]),
        ]);

        // Verify own reject votes are stored correctly.
        let vote_info_0 = state.votes.get(&round_1_blocks[0].reference()).unwrap();
        assert_eq!(vote_info_0.own_reject_txn_votes, vec![0]);
        let vote_info_1 = state.votes.get(&round_1_blocks[1].reference()).unwrap();
        assert_eq!(vote_info_1.own_reject_txn_votes, vec![1, 2]);
        let vote_info_2 = state.votes.get(&round_1_blocks[2].reference()).unwrap();
        assert!(vote_info_2.own_reject_txn_votes.is_empty());

        // No reject votes have been aggregated yet (round 1 blocks have no transaction_votes).
        assert!(vote_info_0.reject_txn_votes.is_empty());
        assert!(vote_info_1.reject_txn_votes.is_empty());

        // Round 2: authorities 0, 1, 2 create blocks that reject transactions in round 1 blocks.
        let ancestors: Vec<BlockRef> = round_1_blocks.iter().map(|b| b.reference()).collect();

        // Authority 0 (stake 1) rejects txn 0 of block[0] and txn 1 of block[1].
        let block_r2_a0 = VerifiedBlock::new_for_test(
            TestBlock::new(2, 0)
                .set_ancestors_raw(ancestors.clone())
                .set_transactions(transactions.clone())
                .set_transaction_votes(vec![
                    BlockTransactionVotes {
                        block_ref: round_1_blocks[0].reference(),
                        rejects: vec![0],
                    },
                    BlockTransactionVotes {
                        block_ref: round_1_blocks[1].reference(),
                        rejects: vec![1],
                    },
                ])
                .build(),
        );

        // Authority 1 (stake 2) rejects txn 0 of block[0] and txns 1,2 of block[1].
        let block_r2_a1 = VerifiedBlock::new_for_test(
            TestBlock::new(2, 1)
                .set_ancestors_raw(ancestors.clone())
                .set_transactions(transactions.clone())
                .set_transaction_votes(vec![
                    BlockTransactionVotes {
                        block_ref: round_1_blocks[0].reference(),
                        rejects: vec![0],
                    },
                    BlockTransactionVotes {
                        block_ref: round_1_blocks[1].reference(),
                        rejects: vec![1, 2],
                    },
                ])
                .build(),
        );

        // Authority 2 (stake 3) rejects txn 2 of block[1] only.
        let block_r2_a2 = VerifiedBlock::new_for_test(
            TestBlock::new(2, 2)
                .set_ancestors_raw(ancestors.clone())
                .set_transactions(transactions.clone())
                .set_transaction_votes(vec![BlockTransactionVotes {
                    block_ref: round_1_blocks[1].reference(),
                    rejects: vec![2],
                }])
                .build(),
        );

        state.add_voted_blocks(vec![
            (block_r2_a0, vec![]),
            (block_r2_a1, vec![]),
            (block_r2_a2, vec![]),
        ]);

        // Verify aggregated reject votes for block[0]:
        // txn 0: authority 0 (stake 1) + authority 1 (stake 2) = 3
        let reject_votes_0 = &state
            .votes
            .get(&round_1_blocks[0].reference())
            .unwrap()
            .reject_txn_votes;
        assert_eq!(reject_votes_0.len(), 1);
        assert_eq!(reject_votes_0.get(&0).unwrap().stake(), 3);

        // Verify aggregated reject votes for block[1]:
        // txn 1: authority 0 (stake 1) + authority 1 (stake 2) = 3
        // txn 2: authority 1 (stake 2) + authority 2 (stake 3) = 5
        let reject_votes_1 = &state
            .votes
            .get(&round_1_blocks[1].reference())
            .unwrap()
            .reject_txn_votes;
        assert_eq!(reject_votes_1.len(), 2);
        assert_eq!(reject_votes_1.get(&1).unwrap().stake(), 3);
        assert_eq!(reject_votes_1.get(&2).unwrap().stake(), 5);

        // block[2] and block[3] have no reject votes from others.
        let reject_votes_2 = &state
            .votes
            .get(&round_1_blocks[2].reference())
            .unwrap()
            .reject_txn_votes;
        assert!(reject_votes_2.is_empty());
    }
}

#[cfg(test)]
mod snapper_protocol_tests {
    use super::*;
    use crate::{TestBlock, snapper::SNAPPER_OBJECT_ID_LENGTH};

    fn object(tag: u8) -> SnapperObjectKey {
        SnapperObjectKey {
            object_id: [tag; SNAPPER_OBJECT_ID_LENGTH],
            version: 0,
        }
    }

    fn transaction(object: SnapperObjectKey, seed: u8) -> Transaction {
        Transaction::new(SnapperTransactionEnvelope::new(vec![object], vec![seed; 16]).encode())
    }

    fn transaction_id(transaction: &Transaction) -> SnapperTransactionId {
        SnapperTransactionEnvelope::transaction_id(transaction.data())
    }

    fn block(
        round: Round,
        author: u32,
        parents: &[VerifiedBlock],
        transactions: Vec<Transaction>,
        stance_votes: Vec<SnapperObjectStanceVote>,
    ) -> VerifiedBlock {
        let mut builder = TestBlock::new(round, author).set_transactions(transactions);
        if !parents.is_empty() {
            builder =
                builder.set_ancestors(parents.iter().map(|block| block.reference()).collect());
        }
        VerifiedBlock::new_for_test(
            builder
                .set_snapper_object_stance_votes(stance_votes)
                .build(),
        )
    }

    fn add_and_process(state: &mut VoteTrackerState, blocks: &[VerifiedBlock]) {
        state.add_voted_blocks(blocks.iter().map(|block| (block.clone(), vec![])).collect());
        let refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        state.process_snapper_blocks(&refs);
    }

    #[test]
    fn snapper_fast_commit_requires_quorum_of_certificate_blocks() {
        let context = Arc::new(Context::new_for_test(4).0);
        let mut state = VoteTrackerState::new(context);
        let object = object(1);
        let tx = transaction(object, 1);
        let tx_id = transaction_id(&tx);

        let r1 = vec![
            block(1, 0, &[], vec![tx], vec![]),
            block(1, 1, &[], vec![], vec![]),
            block(1, 2, &[], vec![], vec![]),
            block(1, 3, &[], vec![], vec![]),
        ];

        let ack = SnapperObjectStanceVote {
            object,
            stance: SnapperObjectStance::Transaction(tx_id),
        };
        let r2 = (0..4)
            .map(|author| block(2, author, &r1, vec![], vec![ack]))
            .collect::<Vec<_>>();
        let r3 = (0..4)
            .map(|author| block(3, author, &r2, vec![], vec![]))
            .collect::<Vec<_>>();

        let all = r1.iter().chain(&r2).chain(&r3).cloned().collect::<Vec<_>>();
        add_and_process(&mut state, &all);

        let decisions = state.snapper_try_fast_decisions();
        assert_eq!(
            state.snapper_state.decision(&object),
            Some(SnapperObjectDecision::Commit(tx_id))
        );
        assert!(!decisions.is_empty());
    }

    #[test]
    fn snapper_fast_skip_releases_object() {
        let context = Arc::new(Context::new_for_test(4).0);
        let mut state = VoteTrackerState::new(context);
        let object = object(2);
        let tx0 = transaction(object, 1);
        let tx1 = transaction(object, 2);

        let r1 = vec![
            block(1, 0, &[], vec![tx0], vec![]),
            block(1, 1, &[], vec![tx1], vec![]),
            block(1, 2, &[], vec![], vec![]),
            block(1, 3, &[], vec![], vec![]),
        ];
        let bottom = SnapperObjectStanceVote {
            object,
            stance: SnapperObjectStance::Bottom,
        };
        let r2 = (0..4)
            .map(|author| block(2, author, &r1, vec![], vec![bottom]))
            .collect::<Vec<_>>();
        let r3 = (0..4)
            .map(|author| block(3, author, &r2, vec![], vec![]))
            .collect::<Vec<_>>();

        let all = r1.iter().chain(&r2).chain(&r3).cloned().collect::<Vec<_>>();
        add_and_process(&mut state, &all);

        state.snapper_try_fast_decisions();
        assert_eq!(
            state.snapper_state.decision(&object),
            Some(SnapperObjectDecision::Release)
        );
    }

    #[test]
    fn committed_anchor_prioritizes_hidden_tx_certificate_over_unlock_certificate() {
        let context = Arc::new(Context::new_for_test(4).0);
        let mut state = VoteTrackerState::new(context);
        let object = object(3);
        let tx0 = transaction(object, 1);
        let tx1 = transaction(object, 2);
        let tx0_id = transaction_id(&tx0);

        let r1 = vec![
            block(1, 0, &[], vec![tx0], vec![]),
            block(1, 1, &[], vec![], vec![]),
            block(1, 2, &[], vec![], vec![]),
            block(1, 3, &[], vec![], vec![]),
        ];

        let ack = SnapperObjectStanceVote {
            object,
            stance: SnapperObjectStance::Transaction(tx0_id),
        };
        let bottom = SnapperObjectStanceVote {
            object,
            stance: SnapperObjectStance::Bottom,
        };

        let r2a = block(2, 0, &r1, vec![], vec![ack]);
        let r2b = block(2, 1, &r1, vec![], vec![ack]);
        let r2c = block(2, 2, &r1, vec![], vec![ack]);
        let r2d = block(2, 3, &r1, vec![tx1], vec![bottom]);

        // A3 sees only the three ACKing round-2 blocks and therefore forms a
        // transaction certificate for tx0.
        let r3a = block(
            3,
            0,
            &[r2a.clone(), r2b.clone(), r2c.clone()],
            vec![],
            vec![],
        );

        // B3 and C3 saw the conflict after ACKing tx0, so Bottom is an unlock
        // vote. D3 remains a skip vote.
        let r3b = block(
            3,
            1,
            &[r2b.clone(), r2c.clone(), r2d.clone()],
            vec![],
            vec![bottom],
        );
        let r3c = block(
            3,
            2,
            &[r2c.clone(), r2b.clone(), r2d.clone()],
            vec![],
            vec![bottom],
        );
        let r3d = block(
            3,
            3,
            &[r2d.clone(), r2b.clone(), r2c.clone()],
            vec![],
            vec![],
        );

        // U4 sees B3,C3,D3: two unlocks plus one skip form an unlock
        // certificate, but U4 does not see A3's transaction certificate.
        let r4u = block(
            4,
            3,
            &[r3b.clone(), r3c.clone(), r3d.clone()],
            vec![],
            vec![],
        );
        let r4a = block(
            4,
            0,
            &[r3a.clone(), r3b.clone(), r3c.clone()],
            vec![],
            vec![],
        );
        let r4b = block(
            4,
            1,
            &[r3a.clone(), r3b.clone(), r3c.clone()],
            vec![],
            vec![],
        );

        let anchor = block(
            5,
            0,
            &[r4a.clone(), r4b.clone(), r4u.clone()],
            vec![],
            vec![],
        );

        let all = r1
            .iter()
            .cloned()
            .chain([r2a, r2b, r2c, r2d])
            .chain([r3a.clone(), r3b, r3c, r3d])
            .chain([r4u.clone(), r4a, r4b])
            .chain([anchor.clone()])
            .collect::<Vec<_>>();
        add_and_process(&mut state, &all);

        assert!(state.snapper_is_fast_cert(r3a.reference(), tx0_id));
        assert!(state.snapper_is_unlock_cert(r4u.reference(), &object));

        state.resolve_snapper_committed_anchor(anchor.reference(), &all);
        assert_eq!(
            state.snapper_state.decision(&object),
            Some(SnapperObjectDecision::Commit(tx0_id))
        );
    }

    #[test]
    fn committed_anchor_releases_on_unlock_when_no_tx_certificate_exists() {
        let context = Arc::new(Context::new_for_test(4).0);
        let mut state = VoteTrackerState::new(context);
        let object = object(4);
        let tx0 = transaction(object, 1);
        let tx1 = transaction(object, 2);
        let tx0_id = transaction_id(&tx0);

        let r1a = block(1, 0, &[], vec![tx0], vec![]);
        let r1b = block(1, 1, &[], vec![], vec![]);
        let r1c = block(1, 2, &[], vec![], vec![]);
        let r1d = block(1, 3, &[], vec![tx1], vec![]);

        let ack = SnapperObjectStanceVote {
            object,
            stance: SnapperObjectStance::Transaction(tx0_id),
        };
        let bottom = SnapperObjectStanceVote {
            object,
            stance: SnapperObjectStance::Bottom,
        };

        let r2a = block(
            2,
            0,
            &[r1a.clone(), r1b.clone(), r1c.clone()],
            vec![],
            vec![ack],
        );
        let r2b = block(
            2,
            1,
            &[r1a.clone(), r1b.clone(), r1c.clone()],
            vec![],
            vec![ack],
        );
        let r2c = block(
            2,
            2,
            &[r1a.clone(), r1c.clone(), r1d.clone()],
            vec![],
            vec![bottom],
        );
        let r2d = block(
            2,
            3,
            &[r1a.clone(), r1c.clone(), r1d.clone()],
            vec![],
            vec![bottom],
        );

        let r3a = block(
            3,
            0,
            &[r2a.clone(), r2c.clone(), r2d.clone()],
            vec![],
            vec![bottom],
        );
        let r3b = block(
            3,
            1,
            &[r2b.clone(), r2c.clone(), r2d.clone()],
            vec![],
            vec![bottom],
        );
        let r3c = block(
            3,
            2,
            &[r2a.clone(), r2c.clone(), r2d.clone()],
            vec![],
            vec![],
        );

        let unlock_cert = block(
            4,
            0,
            &[r3a.clone(), r3b.clone(), r3c.clone()],
            vec![],
            vec![],
        );
        let anchor = block(5, 0, &[unlock_cert.clone()], vec![], vec![]);

        let all = [
            r1a,
            r1b,
            r1c,
            r1d,
            r2a,
            r2b,
            r2c,
            r2d,
            r3a,
            r3b,
            r3c,
            unlock_cert.clone(),
            anchor.clone(),
        ];
        add_and_process(&mut state, &all);

        assert!(state.snapper_is_unlock_cert(unlock_cert.reference(), &object));
        assert!(!state.snapper_has_cert(anchor.reference(), tx0_id));

        state.resolve_snapper_committed_anchor(anchor.reference(), &all);
        assert_eq!(
            state.snapper_state.decision(&object),
            Some(SnapperObjectDecision::Release)
        );
    }
}
