// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use serde::{Deserialize, Serialize};

use crate::{proofs::ProofOfEqualityOfDiscreteLogs, PaillierModulusSizedNumber};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub decryption_shares: Vec<PaillierModulusSizedNumber>,
    pub proof: ProofOfEqualityOfDiscreteLogs,
}
