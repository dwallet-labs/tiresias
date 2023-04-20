use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding, NonZero};
use crypto_bigint::{U1024, U2048, U4096};

fn encrypt(encryption_key: U2048, plaintext: U2048, randomness: U2048) -> U4096 {
    let N = encryption_key;
    let N2: U4096 = N.square();
    let N2_mod = DynResidueParams::new(&N2);

    let m = DynResidue::new(&U2048::ZERO.concat(&plaintext), N2_mod);
    let r = DynResidue::new(&U2048::ZERO.concat(&randomness), N2_mod);
    let N = DynResidue::new(&U2048::ZERO.concat(&N), N2_mod);
    let one = DynResidue::one(N2_mod);

    let mut ciphertext = ((m * N) + one); // $ (m*N + 1) $
    let N: U2048 = encryption_key;
    let N: U4096 = U2048::ZERO.concat(&N);
    ciphertext *= (r.pow(&N)); // $ * (r^N) $

    ciphertext.retrieve()
}

// TODO: now we are panicking if the decryption key is 0, I think it's better to return an option.
fn decrypt(encryption_key: &U2048, decryption_key: &U4096, ciphertext: &U4096) -> U2048 {
    let N = encryption_key;
    let N2: U4096 = N.square();

    let N = U2048::ZERO.concat(&N);
    let N2_mod = DynResidueParams::new(&N2);

    let c = DynResidue::new(&ciphertext, N2_mod);
    let d = decryption_key;

    let plaintext = c.pow(&d); // $ c^d mod N^2 = (1 + N)^{m*d mod N} mod N^2 = (1 + m*d*N) mod N^2 $
    let plaintext = (plaintext - DynResidue::one(N2_mod)).retrieve(); // $ c^d mod N^2 - 1 = m*d*N mod N^2 $
    let plaintext = plaintext / NonZero::new(N).unwrap(); // $ (c^d mod N^2 - 1) / N = m*d*N / N mod N^2 = m*d mod N $
    let plaintext = U2048::from_le_slice(&plaintext.to_le_bytes()[0..256]); // Trim zero-padding post-division and convert to U2048

    // Finally take mod N
    let N = encryption_key;
    let N_mod = DynResidueParams::new(&N);
    let plaintext = DynResidue::new(&plaintext, N_mod).retrieve();

    plaintext
}

// fn decryption_share(encryption_key: &U2048, decryption_key_share: &U2048, ciphertext: &U4096) -> U2048 {
//         return c^{d_i}
// }

// fn combine_decryption_shares(decryption_shares: Vec<U2048>) -> U2048 {
//   sums up all decryption shares, assumes linear (additive) sharing.
// }

// shamir secret sharing in Z_{N*phi(n)} where phi(n) = ((p-1) * (q-1))

// fn partial_decryption<T: Num + Pow<T, Output = T> + Clone>(

//     decryption_key: &T,
//     ciphertext: &T,
// ) -> T {
//     ciphertext.clone().pow(decryption_key.clone()) // $ c^d mod N^2= (1 + N)^{m*d mod N} mod N^2 = (1 + m*d*N) mod N^2 $
// }
//
// fn decrypt_from_partial_decryptions<T: Num + Pow<T, Output = T> + Clone>(
//     partial_decryptions: HashMap<u8, T>,
//     lagrange_coeffecients: HashMap<u8, T>,
// ) -> T {
//     partial_decryptions
//         .iter()
//         .fold(T::one(), |acc, (i, partial_decryption)| {
//             acc * (partial_decryption
//                 .clone()
//                 .pow(lagrange_coeffecients.get(i).unwrap().clone())) // TODO: properly handle the case where lagrange_coeffecients isn't defined for i (no item in map)
//         })
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::CheckedSub;

    use crate::paillier::tests::CIPHERTEXT;
    use crate::paillier::tests::D;
    use crate::paillier::tests::N;
    use crate::paillier::tests::PLAINTEXT;
    use crate::paillier::tests::RANDOMNESS;

    #[test]
    fn decrypts() {
        assert_eq!(PLAINTEXT, decrypt(&N, &D, &CIPHERTEXT));
    }
}
