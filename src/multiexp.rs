use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Limb, Uint, Word};

/// Performs modular multi-exponentiation using Montgomery's ladder.
/// `exponent_bits` represents the number of bits to take into account for the exponent.
///
/// See: Straus, E. G. Problems and solutions: Addition chains of vectors. American Mathematical Monthly 71 (1964), 806–808.
///
/// This gives roughly a 2x improvement
///
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
            .iter()
            .map(|(base, exponent)| {
                let base = DynResidue::new(base, residue_params);

                // powers[i] contains x^i
                let mut powers = [DynResidue::one(residue_params); 1 << WINDOW];
                powers[1] = base;

                let mut i = 2;
                while i < powers.len() {
                    powers[i] = powers[i - 1] * base;
                    i += 1;
                }
                (powers, *exponent)
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

                // TODO: when ConditionallySelectable becomes available, use it instead
                // This code is non-constant time for now (?)
                let power = powers[usize::try_from(idx).unwrap()]; // TODO: is this a safe conversion?

                z *= power;
            });
        }
    }

    z.retrieve()
}

#[cfg(test)]
mod tests {
    use crate::multiexp::multi_exponentiate;
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use crypto_bigint::U256;

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
