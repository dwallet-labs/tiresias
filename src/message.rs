// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{proofs::ProofOfEqualityOfDiscreteLogs, PaillierModulusSizedNumber};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub decryption_shares: Vec<PaillierModulusSizedNumber>,
    pub proof: ProofOfEqualityOfDiscreteLogs,
}
