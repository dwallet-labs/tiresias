// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::{rand_core::CryptoRngCore, NonZero};
use group::GroupElement;
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use subtle::{Choice, CtOption};

use crate::{
    encryption_key::PublicParameters, CiphertextSpaceGroupElement, EncryptionKey,
    LargeBiPrimeSizedNumber, LargePrimeSizedNumber, PaillierModulusSizedNumber,
    PlaintextSpaceGroupElement, PLAINTEXT_SPACE_SCALAR_LIMBS,
};

/// A paillier decryption key.
/// Holds both the `secret_key` and its corresponding `encryption_key`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKey {
    pub encryption_key: EncryptionKey,
    pub secret_key: PaillierModulusSizedNumber,
}

impl DecryptionKey {
    /// Generates a new Paillier Key Pair.
    pub fn generate(
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(PublicParameters, DecryptionKey)> {
        let p: LargePrimeSizedNumber = crypto_primes::generate_safe_prime_with_rng(rng, Some(1024));
        let q: LargePrimeSizedNumber = crypto_primes::generate_safe_prime_with_rng(rng, Some(1024));

        let n: LargeBiPrimeSizedNumber = p * q;
        // phi = (p-1)(q-1)
        let phi: LargeBiPrimeSizedNumber = (p.wrapping_sub(&LargePrimeSizedNumber::ONE))
            * (q.wrapping_sub(&LargePrimeSizedNumber::ONE));
        // With safe primes this can never fail since we have gcd(pq,4p'q') where p,q,p',q' are all
        // odd primes. So the only option is that p'=q or q'=p. 2p+1 has 1025 bits.
        let (phi_inv, _) = phi.inv_odd_mod(&n);
        let secret_key = phi * phi_inv;
        let public_parameters = PublicParameters::new(n)?;
        let encryption_key = PaillierModulusSizedNumber::from(secret_key);

        let decryption_key = Self::new(encryption_key, &public_parameters)?;

        Ok((public_parameters, decryption_key))
    }
}

impl AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>
    for DecryptionKey
{
    type SecretKey = PaillierModulusSizedNumber;

    /// Create a `DecryptionKey` from a previously generated `secret_key` and its corresponding
    /// `encryption_key`. Performs no validations.
    fn new(
        secret_key: Self::SecretKey,
        public_parameters: &PublicParameters,
    ) -> homomorphic_encryption::Result<Self> {
        let encryption_key = EncryptionKey::new(public_parameters)?;

        Ok(DecryptionKey {
            encryption_key,
            secret_key,
        })
    }

    fn decrypt(
        &self,
        ciphertext: &CiphertextSpaceGroupElement,
        public_parameters: &PublicParameters,
    ) -> CtOption<PlaintextSpaceGroupElement> {
        let n = NonZero::new(
            public_parameters
                .plaintext_space_public_parameters()
                .modulus
                .resize(),
        )
        .unwrap();

        // $D(c,d)=\left(\frac{(c^{d}\mod(N^{2}))-1}{N}\right)\mod(N)$
        let plaintext: PaillierModulusSizedNumber =
            (crate::PaillierModulusSizedNumber::from(ciphertext.scalar_mul(&self.secret_key))
                .wrapping_sub(&PaillierModulusSizedNumber::ONE)
                / n)
                % n;

        CtOption::new(
            PlaintextSpaceGroupElement::new(
                (&plaintext).into(),
                public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap(),
            Choice::from(1u8),
        )
    }
}

impl AsRef<EncryptionKey> for DecryptionKey {
    fn as_ref(&self) -> &EncryptionKey {
        &self.encryption_key
    }
}

#[cfg(test)]
mod tests {
    use group::{secp256k1, GroupElement};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };
    use rand_core::OsRng;

    use super::*;
    use crate::{
        encryption_key::PublicParameters,
        test_exports::{CIPHERTEXT, N, PLAINTEXT, SECRET_KEY},
        CiphertextSpaceGroupElement, CiphertextSpaceValue, LargeBiPrimeSizedNumber,
        PlaintextSpaceGroupElement,
    };

    #[test]
    fn decrypts() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        let plaintext = PlaintextSpaceGroupElement::new(
            PLAINTEXT,
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                CIPHERTEXT,
                public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        assert_eq!(
            decryption_key
                .decrypt(&ciphertext, &public_parameters)
                .unwrap(),
            plaintext
        );

        let plaintext = PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(42u8),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, ciphertext) = decryption_key
            .encryption_key
            .encrypt(&plaintext, &public_parameters, &mut OsRng)
            .unwrap();

        assert_eq!(
            decryption_key
                .decrypt(&ciphertext, &public_parameters,)
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn encrypt_decrypts() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        homomorphic_encryption::tests::encrypt_decrypts(
            decryption_key,
            &public_parameters,
            &mut OsRng,
        );
    }

    #[test]
    fn evaluates() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        homomorphic_encryption::tests::evaluates::<
            { secp256k1::SCALAR_LIMBS },
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            secp256k1::Scalar,
            EncryptionKey,
            DecryptionKey,
        >(
            decryption_key,
            &secp256k1::scalar::PublicParameters::default(),
            &public_parameters,
            &mut OsRng,
        );
    }

    #[test]
    fn generated_key_encrypts_decrypts() {
        let rng = &mut OsRng;
        let (public_parameters, decryption_key) = DecryptionKey::generate(rng).unwrap();

        let plaintext = PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(42u8),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, ciphertext) = decryption_key
            .encryption_key
            .encrypt(&plaintext, &public_parameters, rng)
            .unwrap();

        assert_eq!(
            decryption_key
                .decrypt(&ciphertext, &public_parameters,)
                .unwrap(),
            plaintext
        );
    }
}
