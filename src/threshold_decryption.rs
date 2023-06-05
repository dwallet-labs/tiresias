#[cfg(feature = "benchmarking")]
pub(crate) use decryption_key_share::benchmark_decryption_share;

use crate::{PaillierModulusSizedNumber, ProofOfEqualityOfDiscreteLogs};

mod decryption_key_share;
mod precomputed_values;

pub struct Message {
    decryption_shares: Vec<PaillierModulusSizedNumber>,
    proof: ProofOfEqualityOfDiscreteLogs,
}
