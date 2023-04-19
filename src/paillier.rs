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
fn decrypt(encryption_key: &U2048, decryption_key: &U2048, ciphertext: &U4096) -> U2048 {
    let N = encryption_key;
    let N2: U4096 = N.square();

    let N = U2048::ZERO.concat(&N);
    let N2_mod = DynResidueParams::new(&N2);

    let c = DynResidue::new(&ciphertext, N2_mod);
    let d = U2048::ZERO.concat(&decryption_key);

    let plaintext = c.pow(&d); // $ c^d mod N^2 = (1 + N)^{m*d mod N} mod N^2 = (1 + m*d*N) mod N^2 $
    let plaintext = (plaintext - DynResidue::one(N2_mod)).retrieve(); // $ c^d mod N^2 - 1 = m*d*N mod N^2 $
    let plaintext = plaintext / NonZero::new(N).unwrap(); // $ (c^d mod N^2 - 1) / N = m*d*N / N mod N^2 = m*d mod N $
    let plaintext = U2048::from_le_slice(&plaintext.to_le_bytes()[0..256]); // Trim zero-padding post-division and convert to U2048

    // TODO: do we need to multiply by d^-1? because we said we might be able to have d mod N  = 1.
    let N = encryption_key;
    let N_mod = DynResidueParams::new(&N);

    let d_inv = DynResidue::new(&decryption_key, N_mod).invert().0;

    let plaintext = DynResidue::new(&plaintext, N_mod);
    let plaintext = plaintext * d_inv; // $ (m * d) * d^-1 = m $

    plaintext.retrieve()
}

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
    use hex::FromHex;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::identities::One;
    use std::num::Wrapping;

    const N: U2048 = U2048::from_be_hex("688af41d058f34c33676d5363e360934a558c6267aa65078d851f77d95f79d1af1072a2972ab079913b8b34f548061ffa39a79a6ab8a85c430016eea36a84b0af5805174bd9cf50305f3137d1b856ad5f1a8e8bbb6868f39772122f4b13a9815001215ae9140a0d740cd2a3f9360b01d51489172b5e7a512f63d9ce4fd702dd2627ae6d0c29c616f899a5d04d39f027c3f7150896a89386488ff0d9254f27a7925558f3a09f67f90b71ac6a3c5ddd0a9d646187b7896faceae17f7a104284239802cfdd7df341f6f96f71e2ff5930fb821e1aba8f5ca35c4721a877065f86c70b24c0400d87e73aa17be857e35ec6474d86f9754df1850d03d642476f27aefaf");
    const N2: U4096 = U4096::from_be_hex("2ab131c3ac95af26bddc41926b7a0eb06929a592c822aa37862b053eee2541a33d36011840c98094cc67c3c947d0369e479a35fd2d09e167c66e57f43e011aa42ac1f655e858156517019727c9a3b8280dc86ef93ab2f7ae6f78cc3d121bb6353fef7fc8b99a3558ae4739c487146fedaf589b09f785bcb032ce967dbdca4a5eb988f2fbfe20d33e3de6a819f876caf7198133b97bf91453072e0c000244327d5cf74174a516571daef0d127511256c4f60baac8de3d77f7832b5e40c4deb67513dcf3a062b29019f56bbab9283e28d37a248bba1b9f1e593fcadeffaa3c59f93f6fff3debea3caddfd49440ca2354e9e3f2ca871544c24b87acbfad46b877cc24eca1f71e42b522b34931c98b7b3f19f7b31d19dcca509a38772fa9b945dbd747536ed1b1181f81ec5c5b205309b731b2e1bb80b88a8b9c8c4d688d870dcd22307b4c2fd2e626ea7dc11a89e87bf204459c6cc0cfbadddf6d1f7529202d3388e3a77d31fc3f62a487d3620d24308914e54eea93dcb78e63eb94f636a55e314d254ded6220f19c173f936ed0ab24a2d78deda14ce029ecbcc5b85b18b113146a33dd222d76080b10a5cdab768e9def88a349678ce8cea42bed69349e66d52eacdd0de8cbecbae9d984a16a14d02ee57aaea4b3b13db58ce22e96d34a4cf14da416ad4ecdef8b603558ac03f6fbe6b3d7ca2ddadbe2108e1ba922d5842f3439a1");
    const p: U1024 = U1024::from_be_hex("8a711d0dc766df96f04202722e66062c0e7f430bc6d7364fb6b1fc4e18bddf39b349b494680ad10e3b7506792093af6fffcad3752a41a235850c3c7e12e22da68f8ab4355c412ee2a36e1632c4f902dc4ae8dae074c5e32414b3709382deb3ac1b19937b0de3a894c6c3cd06ba214ae6d3e7fbc071ba1385baa8348312617f4f");
    const q: U1024 = U1024::from_be_hex("c150c3c10a32e29aeec36c63d47a9717edd029db149da8c769772826f9e4f484e2706a85ca9f56e9b82f74ba20de8a65d47bbd74b24449f38e8d3134120c1dbf494d1e5ff351f759085ef39a86a02f596671c9b44605ffaa09dc0417bb3219cb7cd9022247f15980efdffe8b76182680f084eb6be3cfb227e713b736c88871a1");
    const randomness: U2048 = U2048::from_be_hex("fc46fd936d00f7ae72ef0f653ef0d73d237d4eff7b8f2d88b2c743ccc7dc0855a88bdd72719ae1cc8e68aa982dcaee75d6438c0c700f65e452f0f5b5780d63741c9d50f13b5f5d08b0586c73e0feb784a3b02df4667acd0e280d94610ff0030329f2ec8840e4f72cb6d193043fa3233d38cb974a9b3ae404ec5afdd0430b9abfb0911e44cf8228c8b355c8cb43846572ef1e39a19f132f89356b85c170c086f7a5d17a407469ebe8286a9cf7f0e77f3ef4635142409e8206d6660c0852effa88327cbecf33ee56c6b59582d7bbf50b828f3ef8cb9c99b330067646497f3ca607972f3132534342f51e8e1ae992166e9e5d02952525c09b4456c11366cf5ff747");
    const plaintext: U2048 = U2048::from_be_hex("bd2d37809159ba2c26aa79ac73821e10f6519182b2a4688d7b04b07654159ecb3b145eb83779d26dd657eb70e6524df44b928596ecfbf71944f8e1aabb749d7a79de2afd9aa7120ef488bfc27540a5bab80d23e00082548359717f22e5e6e327cd35801e9799ecbbbaaa4cb3064a99dc324ad6f201bb8023ad8a010b92b525160a000b93db8fc9fbae0cc32355db1b1ec3b59a910fe6cda61c89ffbfd3315542aa28334214145fc4cd6f0d5072a1d928d975606357fa71fe724aa7039278fb732301e0e38eba7bade5cd3f4e8ae87a2d59d514f5df3251a64ff61297b57087faac3e92437df294ede6db902790b347890bc9a31b72cdaa938c271270627f5bb4");
    const ciphertext: U4096 = U4096::from_be_hex("2956387b66ced8f341358e2be72bab5dbb0441a462d0c75812cf56561b57f52638a6c26fd163c9388046e921b528581983bef3ca7e94c603f77de7d729380dc02945e49668065923b58483221214e0c316495402a0d67d8ff8dcbbabd2bc99dba8fb2ea3e4ac9eb938dfb0af40959ee1627fa6b64714f4f498579520d7cf7a74beb2476cdababb42cdacf79b82a591e1b9e2e11f19f039959da5105fd1b4fd4464db9a2310cf58cfa1001cc0f3f0fb5b4bcc597637f202e41d685e0025a3bbc70e7ea3e64d92ea5e88351a91a97595f0ffec2cdbf705f2d1f2c78c110a77f1c1cf559ebe1b34eb8e695dfaa694d939b94dda13a1faf7a864c517d6df3de47249c079ef247d04a9ada0f092733905cf2deffe6f8413a5c19c6ffd503d8b9a21b36ba52b37f96c455ece688e2d699808a11fb1c5799fb85f8398a443b12e5f58927e120be72962b9ebfa00ab7817912ad7c0c29883edf2910f940228eb917d1f44ac769e90d7f24ac2b6b98823eb2331f9eff8401a156ccf9fe9a5da2013a195cc2f223ec13336256391bcae873ded8c60a5ff92de54697720cc7e0d1adfeb478f19fe546d9aa67b622c6db4babd0bc79cbdbc862b35a579193adf9fac67ebe511418cbc504b144e46038ea1bb3f4ec2ea7750807c7dd50490454ebf0dd68344fef7e7df15d75648d107d5ebb5fcc71d21dcf57c5e8bda89b8698ea5bcae86d959");

    #[test]
    fn test_encryption() {
        assert_eq!(encrypt(N, plaintext, randomness), ciphertext);
    }

    #[test]
    fn decrypts() {
        let (lo, hi) =
            (p.checked_sub(&U1024::ONE).unwrap()).mul_wide(&q.checked_sub(&U1024::ONE).unwrap());

        let phi = hi.concat(&lo); // decryption key

        assert_eq!(plaintext, decrypt(&N, &phi, &ciphertext));
    }

    // fn dec_numbigint(n: BigUint, d: BigUint, c: BigUint) -> BigUint {
    //     let m = c.modpow(&d, &n.pow(2));
    //     let m = (m - BigUint::one()) / n.clone();
    //     m.mod_floor(&n)
    //
    //     m * d.inv
    // }
    //
    // #[test]
    // fn dec_numbigint_test() {
    //     let other_n: BigUint = BigUint::from_bytes_be(&<[u8; 256]>::from_hex("688af41d058f34c33676d5363e360934a558c6267aa65078d851f77d95f79d1af1072a2972ab079913b8b34f548061ffa39a79a6ab8a85c430016eea36a84b0af5805174bd9cf50305f3137d1b856ad5f1a8e8bbb6868f39772122f4b13a9815001215ae9140a0d740cd2a3f9360b01d51489172b5e7a512f63d9ce4fd702dd2627ae6d0c29c616f899a5d04d39f027c3f7150896a89386488ff0d9254f27a7925558f3a09f67f90b71ac6a3c5ddd0a9d646187b7896faceae17f7a104284239802cfdd7df341f6f96f71e2ff5930fb821e1aba8f5ca35c4721a877065f86c70b24c0400d87e73aa17be857e35ec6474d86f9754df1850d03d642476f27aefaf").unwrap());
    //     let other_n2: BigUint = BigUint::from_bytes_be(&<[u8; 512]>::from_hex("2ab131c3ac95af26bddc41926b7a0eb06929a592c822aa37862b053eee2541a33d36011840c98094cc67c3c947d0369e479a35fd2d09e167c66e57f43e011aa42ac1f655e858156517019727c9a3b8280dc86ef93ab2f7ae6f78cc3d121bb6353fef7fc8b99a3558ae4739c487146fedaf589b09f785bcb032ce967dbdca4a5eb988f2fbfe20d33e3de6a819f876caf7198133b97bf91453072e0c000244327d5cf74174a516571daef0d127511256c4f60baac8de3d77f7832b5e40c4deb67513dcf3a062b29019f56bbab9283e28d37a248bba1b9f1e593fcadeffaa3c59f93f6fff3debea3caddfd49440ca2354e9e3f2ca871544c24b87acbfad46b877cc24eca1f71e42b522b34931c98b7b3f19f7b31d19dcca509a38772fa9b945dbd747536ed1b1181f81ec5c5b205309b731b2e1bb80b88a8b9c8c4d688d870dcd22307b4c2fd2e626ea7dc11a89e87bf204459c6cc0cfbadddf6d1f7529202d3388e3a77d31fc3f62a487d3620d24308914e54eea93dcb78e63eb94f636a55e314d254ded6220f19c173f936ed0ab24a2d78deda14ce029ecbcc5b85b18b113146a33dd222d76080b10a5cdab768e9def88a349678ce8cea42bed69349e66d52eacdd0de8cbecbae9d984a16a14d02ee57aaea4b3b13db58ce22e96d34a4cf14da416ad4ecdef8b603558ac03f6fbe6b3d7ca2ddadbe2108e1ba922d5842f3439a1").unwrap());
    //     let other_p: BigUint = BigUint::from_bytes_be(&<[u8; 128]>::from_hex("8a711d0dc766df96f04202722e66062c0e7f430bc6d7364fb6b1fc4e18bddf39b349b494680ad10e3b7506792093af6fffcad3752a41a235850c3c7e12e22da68f8ab4355c412ee2a36e1632c4f902dc4ae8dae074c5e32414b3709382deb3ac1b19937b0de3a894c6c3cd06ba214ae6d3e7fbc071ba1385baa8348312617f4f").unwrap());
    //     let other_q: BigUint = BigUint::from_bytes_be(&<[u8; 128]>::from_hex("c150c3c10a32e29aeec36c63d47a9717edd029db149da8c769772826f9e4f484e2706a85ca9f56e9b82f74ba20de8a65d47bbd74b24449f38e8d3134120c1dbf494d1e5ff351f759085ef39a86a02f596671c9b44605ffaa09dc0417bb3219cb7cd9022247f15980efdffe8b76182680f084eb6be3cfb227e713b736c88871a1").unwrap());
    //     let other_randomness: BigUint = BigUint::from_bytes_be(&<[u8; 256]>::from_hex("fc46fd936d00f7ae72ef0f653ef0d73d237d4eff7b8f2d88b2c743ccc7dc0855a88bdd72719ae1cc8e68aa982dcaee75d6438c0c700f65e452f0f5b5780d63741c9d50f13b5f5d08b0586c73e0feb784a3b02df4667acd0e280d94610ff0030329f2ec8840e4f72cb6d193043fa3233d38cb974a9b3ae404ec5afdd0430b9abfb0911e44cf8228c8b355c8cb43846572ef1e39a19f132f89356b85c170c086f7a5d17a407469ebe8286a9cf7f0e77f3ef4635142409e8206d6660c0852effa88327cbecf33ee56c6b59582d7bbf50b828f3ef8cb9c99b330067646497f3ca607972f3132534342f51e8e1ae992166e9e5d02952525c09b4456c11366cf5ff747").unwrap());
    //     let other_plaintext: BigUint = BigUint::from_bytes_be(&<[u8; 256]>::from_hex("bd2d37809159ba2c26aa79ac73821e10f6519182b2a4688d7b04b07654159ecb3b145eb83779d26dd657eb70e6524df44b928596ecfbf71944f8e1aabb749d7a79de2afd9aa7120ef488bfc27540a5bab80d23e00082548359717f22e5e6e327cd35801e9799ecbbbaaa4cb3064a99dc324ad6f201bb8023ad8a010b92b525160a000b93db8fc9fbae0cc32355db1b1ec3b59a910fe6cda61c89ffbfd3315542aa28334214145fc4cd6f0d5072a1d928d975606357fa71fe724aa7039278fb732301e0e38eba7bade5cd3f4e8ae87a2d59d514f5df3251a64ff61297b57087faac3e92437df294ede6db902790b347890bc9a31b72cdaa938c271270627f5bb4").unwrap());
    //     let other_ciphertext: BigUint = BigUint::from_bytes_be(&<[u8; 512]>::from_hex("2956387b66ced8f341358e2be72bab5dbb0441a462d0c75812cf56561b57f52638a6c26fd163c9388046e921b528581983bef3ca7e94c603f77de7d729380dc02945e49668065923b58483221214e0c316495402a0d67d8ff8dcbbabd2bc99dba8fb2ea3e4ac9eb938dfb0af40959ee1627fa6b64714f4f498579520d7cf7a74beb2476cdababb42cdacf79b82a591e1b9e2e11f19f039959da5105fd1b4fd4464db9a2310cf58cfa1001cc0f3f0fb5b4bcc597637f202e41d685e0025a3bbc70e7ea3e64d92ea5e88351a91a97595f0ffec2cdbf705f2d1f2c78c110a77f1c1cf559ebe1b34eb8e695dfaa694d939b94dda13a1faf7a864c517d6df3de47249c079ef247d04a9ada0f092733905cf2deffe6f8413a5c19c6ffd503d8b9a21b36ba52b37f96c455ece688e2d699808a11fb1c5799fb85f8398a443b12e5f58927e120be72962b9ebfa00ab7817912ad7c0c29883edf2910f940228eb917d1f44ac769e90d7f24ac2b6b98823eb2331f9eff8401a156ccf9fe9a5da2013a195cc2f223ec13336256391bcae873ded8c60a5ff92de54697720cc7e0d1adfeb478f19fe546d9aa67b622c6db4babd0bc79cbdbc862b35a579193adf9fac67ebe511418cbc504b144e46038ea1bb3f4ec2ea7750807c7dd50490454ebf0dd68344fef7e7df15d75648d107d5ebb5fcc71d21dcf57c5e8bda89b8698ea5bcae86d959").unwrap());
    //
    //     let phi = (other_p - BigUint::one()) * (other_q - BigUint::one());
    //
    //     assert_eq!(
    //         other_plaintext.to_str_radix(16),
    //         dec_numbigint(other_n, phi, other_ciphertext).to_str_radix(16)
    //     );
    // }
}
