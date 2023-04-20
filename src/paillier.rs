mod encryption_key;

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding};
use crypto_bigint::{U1024, U2048, U4096};

fn u2048_to_u4096(x: U2048) -> U4096 {
    U2048::ZERO.concat(&x)
}
