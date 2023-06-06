#[cfg(feature = "benchmarking")]
pub(crate) use decryption_key_share::benchmark_decryption_share;

use crate::{proofs::ProofOfEqualityOfDiscreteLogs, PaillierModulusSizedNumber};

mod decryption_key_share;
mod precomputed_values;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Message {
    decryption_shares: Vec<PaillierModulusSizedNumber>,
    proof: ProofOfEqualityOfDiscreteLogs,
}
