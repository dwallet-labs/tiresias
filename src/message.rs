use serde::{Deserialize, Serialize};

use crate::{proofs::ProofOfEqualityOfDiscreteLogs, PaillierModulusSizedNumber};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub(crate) decryption_shares: Vec<PaillierModulusSizedNumber>,
    pub(crate) proof: ProofOfEqualityOfDiscreteLogs,
}
