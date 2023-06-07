use crate::proofs::ProofOfEqualityOfDiscreteLogs;
use crate::PaillierModulusSizedNumber;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub(crate) decryption_shares: Vec<PaillierModulusSizedNumber>,
    pub(crate) proof: ProofOfEqualityOfDiscreteLogs,
}
