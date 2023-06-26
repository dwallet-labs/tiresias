// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{
    Limb,
    modular::runtime_mod::{DynResidue, DynResidueParams},
    subtle::{ConditionallySelectable, ConstantTimeEq}, Uint, Word,
};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_multiexp;

/// Performs constant-time modular multi-exponentiation using Montgomery's ladder.
/// `exponent_bits` represents the number of bits to take into account for the exponent.
///
/// See: Straus, E. G. Problems and solutions: Addition chains of vectors. American Mathematical
/// Monthly 71 (1964), 806–808.
///
/// This gives roughly a 4x improvement
pub fn multi_exponentiate<const LIMBS: usize, const RHS_LIMBS: usize>(
    bases_and_exponents: Vec<(Uint<LIMBS>, Uint<RHS_LIMBS>)>,
    exponent_bits: usize,
    residue_params: DynResidueParams<LIMBS>,
) -> Uint<LIMBS> {
    if exponent_bits == 0 {
        return Uint::<LIMBS>::ONE;
    }

    const WINDOW: usize = 4;
    const WINDOW_MASK: Word = (1 << WINDOW) - 1;

    let powers_and_exponents: Vec<([DynResidue<LIMBS>; 1 << WINDOW], Uint<RHS_LIMBS>)> =
        bases_and_exponents
            .into_iter()
            .map(|(base, exponent)| {
                let base = DynResidue::new(&base, residue_params);

                // powers[i] contains x^i
                let mut powers = [DynResidue::one(residue_params); 1 << WINDOW];
                powers[1] = base;

                let mut i = 2;
                while i < powers.len() {
                    powers[i] = powers[i - 1] * base;
                    i += 1;
                }
                (powers, exponent)
            })
            .collect();

    let starting_limb = (exponent_bits - 1) / Limb::BITS;
    let starting_bit_in_limb = (exponent_bits - 1) % Limb::BITS;
    let starting_window = starting_bit_in_limb / WINDOW;
    let starting_window_mask = (1 << (starting_bit_in_limb % WINDOW + 1)) - 1;

    let mut z = DynResidue::one(residue_params);

    let mut limb_num = starting_limb + 1;
    while limb_num > 0 {
        limb_num -= 1;

        let mut window_num = if limb_num == starting_limb {
            starting_window + 1
        } else {
            Limb::BITS / WINDOW
        };
        while window_num > 0 {
            window_num -= 1;

            if limb_num != starting_limb || window_num != starting_window {
                let mut i = 0;
                while i < WINDOW {
                    i += 1;
                    z = z.square();
                }
            }

            powers_and_exponents.iter().for_each(|(powers, exponent)| {
                let w = exponent.as_limbs()[limb_num].0;
                let mut idx = (w >> (window_num * WINDOW)) & WINDOW_MASK;

                if limb_num == starting_limb && window_num == starting_window {
                    idx &= starting_window_mask;
                }

                // Constant-time lookup in the array of powers
                let mut power = *powers[0].as_montgomery();
                let mut i = 1;
                while i < 1 << WINDOW {
                    let choice = <Limb as ConstantTimeEq>::ct_eq(&Limb(i as Word), &Limb(idx));

                    power = <Uint<LIMBS> as ConditionallySelectable>::conditional_select(
                        &power,
                        powers[i].as_montgomery(),
                        choice,
                    );

                    i += 1;
                }

                z *= DynResidue::from_montgomery(power, residue_params);
            });
        }
    }

    z.retrieve()
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        modular::runtime_mod::{DynResidue, DynResidueParams},
        U256,
    };

    use crate::multiexp::multi_exponentiate;

    #[test]
    fn test_multi_exp() {
        let params = DynResidueParams::new(&U256::from_be_hex(
            "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B",
        ));

        let base = U256::from(2u8);

        let exponent = U256::from(33u8);

        let res = multi_exponentiate(vec![(base, exponent)], U256::BITS, params);

        let base_to_exp =
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000200000000");

        assert_eq!(res, base_to_exp);

        let base2 =
            U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");

        let exponent2 =
            U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");

        let base2_to_exp2 =
            U256::from_be_hex("3681BC0FEA2E5D394EB178155A127B0FD2EF405486D354251C385BDD51B9D421");

        let res = multi_exponentiate(vec![(base2, exponent2)], U256::BITS, params);

        assert_eq!(res, base2_to_exp2);

        let expected = (DynResidue::new(&base_to_exp, params)
            * DynResidue::new(&base2_to_exp2, params))
        .retrieve();

        let res = multi_exponentiate(
            vec![(base, exponent), (base2, exponent2)],
            U256::BITS,
            params,
        );

        assert_eq!(res, expected);
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;
    use crypto_bigint::Random;
    use rand_core::OsRng;

    use crate::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

    use super::*;

    pub(crate) fn benchmark_multiexp(c: &mut Criterion) {
        let mut g = c.benchmark_group("multi-exponentiation");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();

        for i in [1, 2, 3, 4, 10, 100] {
            let bases_and_exponents: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)> =
                (1..=i)
                    .map(|_| {
                        let x = PaillierModulusSizedNumber::random(&mut OsRng);
                        let p = PaillierModulusSizedNumber::random(&mut OsRng);
                        (x, p)
                    })
                    .collect();

            let params = DynResidueParams::new(&n2);

            g.bench_function(
                format!(
                    "multi_exponentiate() for {i} bases,
            PaillierModulusSizedNumber^PaillierModulusSizedNumber"
                ),
                |b| {
                    b.iter(|| {
                        multi_exponentiate(
                            bases_and_exponents.clone(),
                            PaillierModulusSizedNumber::BITS,
                            params,
                        )
                    })
                },
            );
        }

        g.finish();
    }
}
