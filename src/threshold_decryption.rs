#[cfg(feature = "benchmarking")]
pub(crate) use decryption_key_share::benchmark_decryption_share;

use crate::{PaillierModulusSizedNumber, ProofOfEqualityOfDiscreteLogs};

mod decryption_key_share;
mod precomputed_values;

#[derive(Clone)]
pub struct Message {
    decryption_shares: Vec<PaillierModulusSizedNumber>,
    proof: ProofOfEqualityOfDiscreteLogs,
}
