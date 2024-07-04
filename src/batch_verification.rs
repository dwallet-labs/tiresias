// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    MultiExponentiateBoundedExp, Random, Uint,
};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid Params")]
    InvalidParams(),
    #[error("at least one equation is wrong")]
    EquationsVerificationError(),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Performs batch verification of multiple equations.
///
/// Returns `Ok(())` if (and `Err(())` otherwise):
///     - for every equation `i`:
///         - the product of all `bases_lhs[i]` raised to their corresponding `exponents_lhs[i]`
///           equals the product of all `bases_lhs[i]` raised to their corresponding
///           `exponents_lhs[i]`
///
/// Batch verification optimizes the above verification procedure by validating a randomly-sampled
/// linear-combination of the equations, which gives a complete result with soundness of the
/// computational security parameter.
///
/// Assumes `bases_lhs`, `bases_rhs`, `exponent_lhs`, `exponent_rhs` are of the same size,
/// and that there is more than one equation.
/// An error is returned otherwise.
pub fn batch_verification<
    const LIMBS: usize,
    const EXP_LIMBS: usize,
    const COMPUTATIONAL_SECURITY_LIMBS: usize,
>(
    // the bases of the left and right sides of the equations.
    bases_lhs: Vec<Vec<Uint<LIMBS>>>,
    bases_rhs: Vec<Vec<Uint<LIMBS>>>,
    // vectors of the exponents of the left and right sides of the equations as the largest type,
    // with their corresponding bit-size.
    exponents_lhs: Vec<(Uint<EXP_LIMBS>, usize)>,
    exponents_rhs: Vec<(Uint<EXP_LIMBS>, usize)>,
    residue_params: DynResidueParams<LIMBS>,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let number_of_equations = bases_lhs.len();

    if number_of_equations <= 1 {
        return Err(Error::InvalidParams());
    }

    if bases_rhs.len() != number_of_equations {
        return Err(Error::InvalidParams());
    }

    let randomizers: Vec<Uint<COMPUTATIONAL_SECURITY_LIMBS>> = (1..=number_of_equations)
        .map(|_| Uint::<COMPUTATIONAL_SECURITY_LIMBS>::random(rng))
        .collect();

    if batch_equation_side(
        bases_lhs,
        exponents_lhs,
        residue_params,
        randomizers.clone(),
    ) == batch_equation_side(bases_rhs, exponents_rhs, residue_params, randomizers)
    {
        return Ok(());
    }
    Err(Error::EquationsVerificationError())
}

fn batch_equation_side<
    const LIMBS: usize,
    const EXP_LIMBS: usize,
    const COMPUTATIONAL_SECURITY_LIMBS: usize,
>(
    bases: Vec<Vec<Uint<LIMBS>>>,
    exponents: Vec<(Uint<EXP_LIMBS>, usize)>,
    residue_params: DynResidueParams<LIMBS>,
    randomizers: Vec<Uint<COMPUTATIONAL_SECURITY_LIMBS>>,
) -> Uint<LIMBS> {
    let number_of_columns = bases
        .iter()
        .map(|equation_bases| equation_bases.len())
        .max()
        .unwrap();

    let batched_columns: Vec<DynResidue<LIMBS>> = (0..number_of_columns)
        .map(|i| {
            let bases_and_exponents: Vec<_> = bases
                .iter()
                .map(|equation_bases| {
                    DynResidue::new(
                        &equation_bases.get(i).copied().unwrap_or(Uint::<LIMBS>::ONE),
                        residue_params,
                    )
                })
                .zip(randomizers.clone())
                .collect();

            let batched_column = DynResidue::multi_exponentiate_bounded_exp(
                bases_and_exponents.as_slice(),
                Uint::<COMPUTATIONAL_SECURITY_LIMBS>::BITS,
            );

            if i < exponents.len() {
                let (exponent, exponent_bits) = exponents.get(i).unwrap();

                batched_column.pow_bounded_exp(exponent, *exponent_bits)
            } else {
                batched_column
            }
        })
        .collect();

    batched_columns
        .into_iter()
        .reduce(|a, b| a * b)
        .unwrap()
        .retrieve()
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        modular::runtime_mod::{DynResidue, DynResidueParams},
        U128, U256,
    };
    use rand_core::OsRng;

    use crate::batch_verification::batch_verification;

    #[test]
    fn verifies() {
        let n = U128::from_be_hex("4DD56101AF5B55B18DAD7647B3FA946B");
        let generator = U128::from_be_hex("2A76991A1D8A454D91FD32C889F7B80D");

        let first_exponent = U256::from(3u8);
        let second_exponent: U256 =
            U256::from_be_hex("00000000000000000000000000000000321ED0D30F99801F6A4A20E8380D7747");

        let s1: U256 =
            U256::from_be_hex("000000000000000000000000000000003CCB64B223EDE3CB13583B46097D9045");
        let t1: U256 =
            U256::from_be_hex("000000000000000000000000000000001902A423A50EFAAC13DAC792BB20F536");

        let s2: U256 =
            U256::from_be_hex("0000000000000000000000000000000012ABD38C6022105D69D0A758EBD1F705");
        let t2: U256 =
            U256::from_be_hex("0000000000000000000000000000000025B6BAD17FC578099DD91D1EE3E28454");

        let rhs_exponent1 = first_exponent
            .wrapping_mul(&s1)
            .wrapping_add(&second_exponent.wrapping_mul(&t1));

        let rhs_exponent2 = first_exponent
            .wrapping_mul(&s2)
            .wrapping_add(&second_exponent.wrapping_mul(&t2));

        let residue_params = DynResidueParams::new(&n);
        let g = DynResidue::new(&generator, residue_params);
        let h1 = g.pow(&s1).retrieve();
        let a1 = g.pow(&t1).retrieve();
        let h2 = g.pow(&s1).retrieve();
        let a2 = g.pow(&t1).retrieve();

        assert!(
            batch_verification::<{ U128::LIMBS }, { U256::LIMBS }, { U128::LIMBS }>(
                vec![vec![h1, a1], vec![h2, a2]],
                vec![vec![generator], vec![generator]],
                vec![(first_exponent, 3), (second_exponent, 128)],
                vec![(rhs_exponent1, 256), (rhs_exponent2, 256)],
                residue_params,
                &mut OsRng
            )
            .is_ok()
        );
    }
}
