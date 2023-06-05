use std::iter;
use std::ops::{Add, Mul};

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::Random;

/// Polynomial of some degree $n$
///
/// Polynomial has a form: $f(x) = a_0 + a_1 x^1 + \dots{} + a_{n-1} x^{n-1} + a_n x^n$
///
/// Coefficients $a_i$ and indeterminate $x$ are within a ring,
/// and this type is generic for any concrete type that implements ring arithmetic operations.
pub struct Polynomial<T>
where
    T: Copy + Add<T, Output = T> + Mul<T, Output = T>,
{
    coefficients: Vec<T>,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid Params")]
    InvalidParams(),
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T> Polynomial<T>
where
    T: Copy + Add<T, Output = T> + Mul<T, Output = T>,
{
    /// Constructs polynomial $f(x)$ from list of coefficients $a_0, \dots, a_n$ in the ring
    ///
    /// ## Order
    ///
    /// $a_i$ should corresponds to polynomial $i^{\text{th}}$ coefficient $f(x) = \dots{} + a_i x^i + \dots$
    ///
    /// ## Polynomial degree
    ///
    /// Note that it's not guaranteed that constructed polynomial degree equals to `coefficients.len()-1`
    /// as it's allowed to end with zero coefficients. Actual polynomial degree equals to index of last
    /// non-zero coefficient or zero if all the coefficients are zero.
    pub fn from_coefficients(coefficients: Vec<T>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(Error::InvalidParams());
        }

        Ok(Self { coefficients })
    }

    /// Sample a random polynomial of given `degree`
    pub fn sample(degree: u16, rng: &mut impl CryptoRngCore) -> Result<Self>
    where
        T: Random,
    {
        Self::from_coefficients(
            iter::repeat_with(|| T::random(rng))
                .take(usize::from(degree + 1))
                .collect(),
        )
    }

    /// Samples random polynomial of degree $n$ with a fixed constant term (i.e. $a_0 =
    /// \text{constant\\_term}$). In SSS, the constant term is the shared secret, and the other coefficients are used as randomizers to hide the secret.
    pub fn sample_with_constant_term(
        degree: u16,
        constant_term: T,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self>
    where
        T: Random,
    {
        let mut coefficients = Self::sample(degree, rng)?.coefficients;
        coefficients[0] = constant_term;

        Self::from_coefficients(coefficients)
    }

    /// Takes scalar $x$ and evaluates $f(x)$
    pub fn evaluate(&self, x: &T) -> T {
        // Iterate through the coefficients, tail to head, and iteratively evaluate the polynomial by multiplying by `x` and adding the coefficient
        // Beginning with the last coefficient, every such iteration increases the power of all previously evaluated parts, until we finish with the constant term which isn't multiplied by `x`.
        let mut reversed_coefficients = self.coefficients.iter().rev();
        let last_coefficient = reversed_coefficients.next().unwrap();

        reversed_coefficients.fold(
            *last_coefficient,
            |partially_evaluated_polynomial, coefficient| {
                partially_evaluated_polynomial * (*x) + (*coefficient)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crypto_bigint::{Wrapping, U64};
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn evaluates() {
        let polynomial = Polynomial::from_coefficients(vec![
            Wrapping(U64::from(1u8)),
            Wrapping(U64::from(2u8)),
            Wrapping(U64::from(3u8)),
        ])
        .unwrap();

        assert_eq!(
            polynomial.evaluate(&Wrapping(U64::from(0u8))),
            Wrapping(U64::from(1u8))
        );

        assert_eq!(
            polynomial.evaluate(&Wrapping(U64::from(5u8))),
            Wrapping(U64::from(86u8))
        );
    }

    #[test]
    fn samples() {
        let degree = 10;
        let polynomial: Polynomial<Wrapping<U64>> = Polynomial::sample(degree, &mut OsRng).unwrap();

        assert_eq!(
            polynomial
                .coefficients
                .iter()
                .map(|x| x.0)
                .filter(|x| x != &U64::ZERO)
                .collect::<HashSet<_>>()
                .len(),
            usize::from(degree + 1)
        );
    }
}
