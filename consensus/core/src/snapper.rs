// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use consensus_types::block::{BlockRef, TransactionIndex};
use serde::{Deserialize, Serialize};

/// Length of a Sui object identifier.
pub const SNAPPER_OBJECT_ID_LENGTH: usize = 32;

/// An owned-object version tracked by Snapper.
///
/// We deliberately keep this type independent of `sui-types`: consensus-core
/// currently treats transactions as opaque bytes, and Snapper's consensus
/// machinery only needs a stable object identifier and version.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapperObjectKey {
    pub object_id: [u8; SNAPPER_OBJECT_ID_LENGTH],
    pub version: u64,
}

/// Identifies a transaction by the DAG block in which it was introduced and
/// its transaction index inside that block.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapperTransactionRef {
    pub block_ref: BlockRef,
    pub transaction_index: TransactionIndex,
}

/// A validator's current stance for one unresolved owned-object version.
///
/// `Bottom` is intentionally not split into skip and unlock here. Both are the
/// same current stance. Snapper classifies a `Bottom` declaration as:
///
/// - a skip vote if the validator never previously ACKed a candidate; or
/// - an unlock vote if the validator previously ACKed a candidate.
///
/// That classification must therefore be derived from the validator's DAG
/// history rather than encoded in the vote itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapperObjectStance {
    Transaction(SnapperTransactionRef),
    Bottom,
}

/// A stance change recorded in a validator's DAG block.
///
/// A validator only needs to emit an entry when its stance changes. If an
/// object has no entry in a later block, the previous stance remains in force.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapperObjectStanceVote {
    pub object: SnapperObjectKey,
    pub stance: SnapperObjectStance,
}
