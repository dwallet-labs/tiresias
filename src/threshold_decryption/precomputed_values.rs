use crypto_bigint::CheckedMul;

use crate::PaillierModulusSizedNumber;

/// This struct holds precomputed values that are computationally expensive to compute
#[derive(Clone)]
pub(in crate::threshold_decryption) struct PrecomputedValues {
    // The precomputed value $n!$ divided into factors of the Paillier modulus size for efficient
    // exponentiation
    pub(in crate::threshold_decryption) n_factorial: Vec<PaillierModulusSizedNumber>,
}

impl PrecomputedValues {
    pub(in crate::threshold_decryption) fn new(n: u16) -> PrecomputedValues {
        let n_factorial = Self::combine_small_factors_to_modulus_sized_factors((2..=n).collect());

        PrecomputedValues { n_factorial }
    }

    fn combine_small_factors_to_modulus_sized_factors(
        small_factors: Vec<u16>,
    ) -> Vec<PaillierModulusSizedNumber> {
        let (mut modulus_sized_factors, last_factor) = small_factors.iter().fold(
            (vec![], PaillierModulusSizedNumber::ONE),
            |(factors, factor_acc), factor| {
                let factor = PaillierModulusSizedNumber::from(*factor);

                let mul_res = factor_acc.checked_mul(&factor);

                if bool::from(mul_res.is_some()) {
                    (factors, mul_res.unwrap())
                } else {
                    // We overflowed, so let's start next factor
                    let mut factors = factors;
                    factors.push(factor_acc);
                    (factors, factor)
                }
            },
        );

        modulus_sized_factors.push(last_factor);

        modulus_sized_factors
    }
}
