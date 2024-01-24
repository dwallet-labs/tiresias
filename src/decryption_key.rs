// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::NonZero;
use group::GroupElement;
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use subtle::{Choice, CtOption};

use crate::{
    encryption_key, encryption_key::PublicParameters, AsNaturalNumber, AsRingElement,
    CiphertextSpaceGroupElement, CiphertextSpaceValue, EncryptionKey, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber, PaillierRingElement, PlaintextSpaceGroupElement,
    RandomnessSpaceGroupElement, RandomnessSpaceValue, PLAINTEXT_SPACE_SCALAR_LIMBS,
};

/// A paillier decryption key.
/// Holds both the `secret_key` and its corresponding `encryption_key`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKey {
    encryption_key: EncryptionKey,
    secret_key: PaillierModulusSizedNumber,
}

impl AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>
    for DecryptionKey
{
    type SecretKey = PaillierModulusSizedNumber;

    fn new(
        secret_key: Self::SecretKey,
        public_parameters: &encryption_key::PublicParameters,
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

        // $ D(c,d)=\left(\frac{(c^{d}\mod(N^{2}))-1}{N}\right)\mod(N) $
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
    use group::GroupElement;
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };
    use rand_core::OsRng;

    use super::*;
    use crate::{
        encryption_key::PublicParameters,
        tests::{CIPHERTEXT, N, PLAINTEXT, RANDOMNESS, SECRET_KEY},
        CiphertextSpaceGroupElement, CiphertextSpaceValue, LargeBiPrimeSizedNumber,
        PlaintextSpaceGroupElement, RandomnessSpaceValue,
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
            public_parameters,
            &mut OsRng,
        );
    }

    #[test]
    fn evaluates() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        homomorphic_encryption::tests::encrypt_decrypts(
            decryption_key,
            public_parameters,
            &mut OsRng,
        );
    }
}
