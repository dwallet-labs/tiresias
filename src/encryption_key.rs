// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::NonZero;
use group::GroupElement;
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    error::SanityCheckError,
    group::{CiphertextSpaceGroupElement, PlaintextSpaceGroupElement, RandomnessSpaceGroupElement},
    CiphertextSpacePublicParameters, CiphertextSpaceValue, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber, PlaintextSpacePublicParameters, RandomnessSpacePublicParameters,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
};

/// A Paillier public encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey;

impl AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS> for EncryptionKey {
    type PlaintextSpaceGroupElement = PlaintextSpaceGroupElement;
    type RandomnessSpaceGroupElement = RandomnessSpaceGroupElement;
    type CiphertextSpaceGroupElement = CiphertextSpaceGroupElement;
    type PublicParameters = PublicParameters;

    /// Create a new `EncryptionKey` Object.
    /// Parameter `public_parameters` is here for legacy reasons.
    fn new(_public_parameters: &Self::PublicParameters) -> homomorphic_encryption::Result<Self> {
        // Public Parameters are passed during each encryption operation.
        Ok(EncryptionKey {})
    }

    fn encrypt_with_randomness(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &PublicParameters,
    ) -> Self::CiphertextSpaceGroupElement {
        // Validity checks are performed in public parameter instantiation, given correct public
        // parameters Paillier encryption is a bijection and thus always succeeds, so `.unwrap()`s

        // are safe here $ c1 = (m*N + 1) * $
        let ciphertext_first_part = (plaintext.value()
            * *public_parameters
                .plaintext_space_public_parameters()
                .modulus)
            .wrapping_add(&PaillierModulusSizedNumber::ONE);
        let ciphertext_first_part = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                ciphertext_first_part,
                public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        // $ c2 = (r^N) $
        let randomness = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                (&LargeBiPrimeSizedNumber::from(randomness)).into(),
                public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext_second_part = randomness.scalar_mul(
            &public_parameters
                .plaintext_space_public_parameters()
                .modulus,
        );

        // $ c = c1 * c2 = (m*N + 1) * (r^N) mod N^2 $ [Note that the equation is translated into
        // additive notation, to work with the group traits]
        ciphertext_first_part + ciphertext_second_part
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct PublicParameters(
    homomorphic_encryption::GroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    >,
);

impl PublicParameters {
    pub fn new(paillier_associate_bi_prime: LargeBiPrimeSizedNumber) -> crate::Result<Self> {
        // todo: verify zk-proof that the modulus was correctly generated

        let paillier_associate_bi_prime_modulus =
            Option::from(NonZero::new(paillier_associate_bi_prime)).ok_or(
                crate::Error::SanityCheckError(SanityCheckError::InvalidParams()),
            )?;

        Ok(Self(homomorphic_encryption::GroupsPublicParameters {
            plaintext_space_public_parameters: PlaintextSpacePublicParameters {
                modulus: paillier_associate_bi_prime_modulus,
            },
            randomness_space_public_parameters: RandomnessSpacePublicParameters::new(
                paillier_associate_bi_prime,
            )?,
            ciphertext_space_public_parameters: CiphertextSpacePublicParameters::new(
                paillier_associate_bi_prime.square(),
            )?,
        }))
    }
}

impl Serialize for PublicParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.plaintext_space_public_parameters()
            .modulus
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let paillier_associate_bi_prime = LargeBiPrimeSizedNumber::deserialize(deserializer)?;

        PublicParameters::new(paillier_associate_bi_prime)
            .map_err(|_| serde::de::Error::custom("invalid paillier associate bi-prime"))
    }
}

impl
    AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
        >,
    > for PublicParameters
{
    fn as_ref(
        &self,
    ) -> &homomorphic_encryption::GroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    > {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_exports::{CIPHERTEXT, N, PLAINTEXT, RANDOMNESS},
        RandomnessSpaceValue,
    };

    #[test]
    fn encrypts() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let encryption_key = EncryptionKey::new(&public_parameters).unwrap();

        let plaintext = PlaintextSpaceGroupElement::new(
            PLAINTEXT,
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let randomness = RandomnessSpaceGroupElement::new(
            RandomnessSpaceValue::new(
                RANDOMNESS,
                public_parameters.randomness_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.randomness_space_public_parameters(),
        )
        .unwrap();

        assert_eq!(
            PaillierModulusSizedNumber::from(encryption_key.encrypt_with_randomness(
                &plaintext,
                &randomness,
                &public_parameters
            )),
            CIPHERTEXT
        )
    }
}
