// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    Encoding, NonZero, RandomMod, Uint,
};
use group::{BoundedGroupElement, GroupElement as _, Samplable};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// An element of the [Multiplicative group of integers modulo N](https://en.wikipedia.org/wiki/Multiplicative_group_of_integers_modulo_n)
/// where `N = PQ` $\mathbb{Z}_N^*$ for the randomness space of the Paillier cryptosystem
/// or $\mathbb{Z}_N^{2*}$ for the ciphertext space.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct GroupElement<const LIMBS: usize>(pub(crate) DynResidue<LIMBS>);

impl<const LIMBS: usize> Samplable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> group::Result<Self> {
        // Montgomery form only works for odd modulus, and this is assured in `DynResidue`
        // instantiation; therefore, the modulus of an instance can never be zero and it is safe to
        // `unwrap()`.
        let modulus = NonZero::new(*public_parameters.params.modulus()).unwrap();

        // Classic rejection-sampling technique.
        loop {
            let value = Value::new(Uint::<LIMBS>::random_mod(rng, &modulus), public_parameters)?;

            match Self::new(value, public_parameters) {
                Err(group::Error::InvalidGroupElement) => {
                    continue;
                }
                Ok(sampled_element) => {
                    return Ok(sampled_element);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// The value of a group element of the multiplicative group of integers modulo `n` $\mathbb{Z}_n^*$
#[derive(PartialEq, Eq, Clone, Debug, Copy, Serialize, Deserialize)]
pub struct Value<const LIMBS: usize>(Uint<LIMBS>)
where
    Uint<LIMBS>: Encoding;

impl<const LIMBS: usize> Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(
        value: Uint<LIMBS>,
        public_parameters: &PublicParameters<LIMBS>,
    ) -> group::Result<Self> {
        let element = DynResidue::<LIMBS>::new(&value, public_parameters.params);

        Ok(Self(*element.as_montgomery()))
    }
}

impl<const LIMBS: usize> ConstantTimeEq for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Uint::<LIMBS>::conditional_select(&a.0, &b.0, choice))
    }
}

/// The public parameters of the multiplicative group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicParameters<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub(crate) params: DynResidueParams<LIMBS>,
}

impl<const LIMBS: usize> Serialize for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.params.modulus().serialize(serializer)
    }
}

impl<'de, const LIMBS: usize> Deserialize<'de> for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let modulus = Uint::<LIMBS>::deserialize(deserializer)?;

        PublicParameters::new(modulus).map_err(Error::custom)
    }
}

impl<const LIMBS: usize> PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(modulus: Uint<LIMBS>) -> group::Result<Self> {
        #[allow(deprecated)]
        let params = DynResidueParams::<LIMBS>::new_checked(&modulus);

        if params.is_none().into() {
            return Err(group::Error::UnsupportedPublicParameters);
        }

        Ok(Self {
            params: params.unwrap(),
        })
    }
}

impl<const LIMBS: usize> group::GroupElement for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Value<LIMBS>;
    type PublicParameters = PublicParameters<LIMBS>;

    fn value(&self) -> Self::Value {
        self.0.into()
    }

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        let element = DynResidue::<LIMBS>::from_montgomery(value.0, public_parameters.params);

        // `element` is valid if and only if it has an inverse if and only if it is not co-primed to
        // the modulus $N$ or $N^2$. In the Paillier randomness and ciphertext groups, every square
        // number except for zero that is not co-primed to $N^2$ yields factorization of
        // $N$. Therefore checking that a square number is not zero sufficiently assures
        // they belong to the quadratic-residue group, which is required for the ciphertext group,
        // and that it is a valid group element, which is required for both groups.
        //
        // Note that if we'd have perform this check prior to squaring, it wouldn't have suffice;
        // take e.g. g = N != 0 -> g^2 = N^2 mod N^2 = 0 (accepting this value would have allowed
        // bypassing of the proof).

        if element.square() == DynResidue::<LIMBS>::zero(public_parameters.params) {
            Err(group::Error::InvalidGroupElement)
        } else {
            Ok(Self(element))
        }
    }

    fn neutral(&self) -> Self {
        GroupElement(DynResidue::<LIMBS>::one(*self.0.params()))
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        // This is inefficient, but in a hidden-order group, we can't do better than this as we
        // can't take the scalar modulus the order.
        Self(self.0.pow(scalar))
    }

    fn scalar_mul_bounded<const SCALAR_LIMBS: usize>(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        scalar_bits: usize,
    ) -> Self {
        // This is inefficient, but in a hidden-order group, we can't do better than this as we
        // can't take the scalar modulus the order.
        Self(self.0.pow_bounded_exp(scalar, scalar_bits))
    }

    fn double(&self) -> Self {
        Self(self.0.square())
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        PublicParameters {
            params: *value.0.params(),
        }
    }
}

impl<const LIMBS: usize> Neg for GroupElement<LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // In a group, every element has its inverse;
        // because `self` is an element within the group,
        // `invert()` is guaranteed to succeed and we
        // skip the check.
        Self(self.0.invert().0)
    }
}

impl<const LIMBS: usize> Neg for &GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn neg(self) -> Self::Output {
        GroupElement::<LIMBS>(self.0.invert().0)
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        // We are trying to adapt a multiplicative group to
        // the `GroupElement` trait which is in an additive notation -
        // so the abstract group operation "add" is mapped to the group operation (x \mod N) of the
        // multiplicative group of integers modulo N.
        Self(self.0 * rhs.0)
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<const LIMBS: usize> Sub<Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        // Subtraction is actually division in the multiplicative group,
        // which is defined as multiplication by the inverse of `rhs` - which we get from `neg()`
        Self(self.0 * rhs.neg().0)
    }
}

impl<'r, const LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * rhs.neg().0)
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add_assign(&mut self, rhs: &'r Self) {
        *self = *self + rhs
    }
}

impl<const LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs
    }
}

impl<'r, const LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub_assign(&mut self, rhs: &'r Self) {
        *self = *self - rhs
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<Uint<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<&Uint<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<Uint<RHS_LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<&Uint<RHS_LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<const LIMBS: usize> Mul<GroupElement<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: GroupElement<LIMBS>) -> Self::Output {
        self.scalar_mul(&Uint::<LIMBS>::from(&rhs))
    }
}

impl<const LIMBS: usize> Mul<&GroupElement<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &GroupElement<LIMBS>) -> Self::Output {
        self.scalar_mul(&Uint::<LIMBS>::from(rhs))
    }
}

impl<const LIMBS: usize> Mul<GroupElement<LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: GroupElement<LIMBS>) -> Self::Output {
        self.scalar_mul(&Uint::<LIMBS>::from(&rhs))
    }
}

impl<const LIMBS: usize> Mul<&GroupElement<LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &GroupElement<LIMBS>) -> Self::Output {
        self.scalar_mul(&Uint::<LIMBS>::from(rhs))
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.value()
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.value()
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.0
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.0
    }
}

impl<const LIMBS: usize> From<DynResidue<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: DynResidue<LIMBS>) -> Self {
        Value(*value.as_montgomery())
    }
}

impl<'r, const LIMBS: usize> From<&'r DynResidue<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &'r DynResidue<LIMBS>) -> Self {
        Value(*value.as_montgomery())
    }
}

impl<const LIMBS: usize> BoundedGroupElement<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        (*public_parameters.params.modulus()) / NonZero::new(Uint::<LIMBS>::from(2u8)).unwrap()
    }
}
