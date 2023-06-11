#[cfg(feature = "benchmarking")]
use criterion::criterion_group;
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Concat, Limb, Uint, U1024, U128,
};
pub use decryption_key::DecryptionKey;
pub use decryption_key_share::DecryptionKeyShare;
pub use encryption_key::EncryptionKey;
pub use error::{Error, Result};
pub use message::Message;
pub use precomputed_values::PrecomputedValues;

mod decryption_key;
mod decryption_key_share;
mod encryption_key;
mod error;
mod message;
mod precomputed_values;

pub mod proofs;
pub mod secret_sharing;

/// A type alias for an unsigned integer of the size of the computation security parameter $\kappa$.
/// Set to a U128 for 128-bit security.
pub type ComputationalSecuritySizedNumber = U128;

type StatisticalSecuritySizedNumber = U128;

/// A type alias for an unsigned integer of the size of the Paillier large prime factors.
/// Set to a U1024 for 112-bit security.
pub type LargePrimeSizedNumber = U1024;

/// A type alias for an unsigned integer of the size of the Paillier associated bi-prime `n` ($N$)
/// (double the size of the Paillier large prime factors). Set to a U2048 for 112-bit security.
pub type LargeBiPrimeSizedNumber = <LargePrimeSizedNumber as Concat>::Output;

/// A type alias for an unsigned integer of the size of the Paillier modulus ($N^2$) (double the
/// size of the Paillier associated bi-prime `n` ($N$)). Set to a U4096 for 112-bit security.
pub type PaillierModulusSizedNumber = <LargeBiPrimeSizedNumber as Concat>::Output;

pub(crate) type PaillierRingElement = DynResidue<{ PaillierModulusSizedNumber::LIMBS }>;
pub(crate) type PaillierPlaintextRingElement = DynResidue<{ LargeBiPrimeSizedNumber::LIMBS }>;

const fn secret_sharing_polynomial_coefficient_size_upper_bound(nlog_n: usize) -> usize {
    nlog_n + 2 * PaillierModulusSizedNumber::BITS + StatisticalSecuritySizedNumber::BITS
}

const fn secret_key_share_size_upper_bound(nlog_n: usize) -> usize {
    2 * nlog_n + 2 * PaillierModulusSizedNumber::BITS + StatisticalSecuritySizedNumber::BITS
}

pub const MAX_PLAYERS: usize = 1024;
pub const MAX_PLAYERS_LOG: usize = 10;
pub const SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND: usize =
    secret_sharing_polynomial_coefficient_size_upper_bound(MAX_PLAYERS * MAX_PLAYERS_LOG);
pub const SECRET_KEY_SHARE_SIZE_UPPER_BOUND: usize =
    secret_key_share_size_upper_bound(MAX_PLAYERS * MAX_PLAYERS_LOG);

pub type SecretSharingPolynomialCoefficientSizedNumber = Uint<
    { SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND.next_power_of_two() / Limb::BITS },
>;

pub type SecretKeyShareSizedNumber =
    Uint<{ SECRET_KEY_SHARE_SIZE_UPPER_BOUND.next_power_of_two() / Limb::BITS }>;

// ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber should be bigger than SecretKeyShareSizedNumber by 2*ComputationalSecuritySizedNumber::BITS
// However, this will necessarily be the case due to us taking `.next_power_of_two()` in secret_key_share_size_upper_bound()
// I.e. the resultant size is already large enough to account for both; the actual computations (e.g., sampling randomness of a given bit-length)
// must be done carefully, account for the real size of these variables; but that does not mean that we're not able to use the same underlying Uint type for both.
pub(crate) type ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber = SecretKeyShareSizedNumber;

/// Retrieve the minimal natural number in the congruence class.
pub(crate) trait AsNaturalNumber<T> {
    fn as_natural_number(&self) -> T;
}

/// Represent this natural number as the minimal member of the congruence class. i.e. as a member of
/// the ring $\mathbb{Z}_{n}$
pub(crate) trait AsRingElement<T> {
    fn as_ring_element(&self, n: &Self) -> T;
}

impl AsNaturalNumber<PaillierModulusSizedNumber> for PaillierRingElement {
    fn as_natural_number(&self) -> PaillierModulusSizedNumber {
        self.retrieve()
    }
}

impl AsRingElement<PaillierRingElement> for PaillierModulusSizedNumber {
    fn as_ring_element(&self, n: &Self) -> PaillierRingElement {
        let ring_params = DynResidueParams::new(n);
        DynResidue::new(self, ring_params)
    }
}

impl AsNaturalNumber<LargeBiPrimeSizedNumber> for PaillierPlaintextRingElement {
    fn as_natural_number(&self) -> LargeBiPrimeSizedNumber {
        self.retrieve()
    }
}

impl AsRingElement<PaillierPlaintextRingElement> for LargeBiPrimeSizedNumber {
    fn as_ring_element(&self, n: &Self) -> PaillierPlaintextRingElement {
        let ring_params = DynResidueParams::new(n);
        DynResidue::new(self, ring_params)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::NonZero;

    use super::*;

    pub(crate) const N: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    pub(crate) const N2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("5960383b5378ad0607f0f270ce7fb6dcaba6506f9fc56deeffaf605c9128db8ccf063e2e8221a8bdf82c027741a0303b08eb71fa6225a03df18f24c473dc6d4d3d30eb9c52a233bbfe967d04011b95e8de5bc482c3c217bcfdeb4df6f57af6ba9c6d66c69fb03a70a41fe1e87975c85343ef7d572ca06a0139706b23ed2b73ad72cb1b7e2e41840115651897c8757b3da9af3a60eebb6396ffd193738b4f04aa6ece638cef1bf4e9c45cf57f8debeda8598cbef732484752f5380737ba75ee00bf1b146817b9ab336d0ce5540395377347c653d1c9d272127ff12b9a0721b8ef13ecd8a8379f1b9a358de2af2c4cd97564dbd5328c2fc13d56ee30c8a101d333f5406afb1f4417b49d7a629d5076726877df11f05c998ae365e374a0141f0b99802214532c97c1ebf9faf6e277a8f29dbd8f3eab72266e60a77784249694819e42877a5e826745c97f84a5f37002b74d83fc064cf094be0e706a6710d47d253c4532e6aa4a679a75fa1d860b39085dab03186c67248e6c92223682f58bd41b67143e299329ce3a8045f3a0124c3d0ef9f0f49374d89b37d9c3321feb2ab4117df4f68246724ce41cd765326457968d848afcc0735531e5de7fea88cf2eb35ac68710c6e79d5ad25df6c0393c0267f56e8eac90a52637abe3e606769e70b20560eaf70e0d531b11dca299104fa933f887d85fb5f72386c196e40f559baee356b9");
    pub(crate) const PLAINTEXT: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("23f6379f4b0435dd50c0eb12454495c99db09aed97fe498c0dba7c51f6c52ab7b8d8ba47896ee0c43d567a1b3611cb2d53ee74574acc9c4520106c0f6e5d0376817febb477bb729405387b6ae6e213b3b34c0eb0cbe5dff49452979ab7f0b514560b5c9b659732efd0d67a3d7b7512a5d97f1bde1c2263f741838a7c62d78133396715c9568c0524e20a3147cda4510ef2f32cefa6fb92caf3a26da63aba3693efce706303fe399b6c86664b1ccaa9fe6e1505d82c4dd9b0a60ea29ec88a91bf2656a3927ad39d561bfe4009f94398a9a7782383f063adeb922275efd950ef3739dee7854bbf93f939a947e3aec7344135e6b0623aff35e802311c10ede8b0d4");
    pub(crate) const RANDOMNESS: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("4aba7692cfc2e1a30d46dc393c4d406837df82896da97268b377b8455ce9364d93ff7d0c051eed84f2335eeae95eaf5182055a9738f62d37d06cf4b24c663006513c823418d63db307a96a1ec6c4089df23a7cc69c4c64f914420955a3468d93087feedea153e05d94d184e823796dd326f8f6444405665b9a6af3a5fedf4d0e787792667e6e73e4631ea2cbcf7baa58fff7eb25eb739c31fadac1cd066d97bcd822af06a1e4df4a2ab76d252ddb960bbdc333fd38c912d27fa775e598d856a87ce770b1379dde2fbfce8d82f8692e7e1b33130d556c97b690d0b5f7a2f8652b79a8f07a35d3c4b9074be68daa04f13e7c54124d9dd4fe794a49375131d9c0b1");
    pub(crate) const CIPHERTEXT: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("0d1a2a781bf90133552b120beb2745bbe02b47cc4e5cc65b6eb5294770bd44b52ce581c4aec199687283360ab0c46bb3f0bb33733dbbf2d7e95a7c600ed20e990e8c3133f7ec238c0b47882363df7748757717443a3d1f9e85f0fb27e665844f591a0f922f42436688a72a71bdf7e93c764a84aff5b813c034787f5cf35a7102fe3be8c670ac26b83b08dabca47d9156ce09d7349ac73d269b7355d5266720654b83b09857add1a6c0be4677115f461ea15907e1472d3d7dcde351f9eff7e43968ae7012a67eeca940c25d3dd5694c5bbf1ed702bfd2094e424bb17bbf00270ded29320cd2e50af2283121ecf5f8593de49b18e465f3b1e1a39daca4d7382e4a610bdbd21dfd343108085b6e2c743f295df3785d3766b56c36efc0ea10ba3de8c16c43fcc051e7c27d835a481c0fdd48819ca9398043689027b00b275ca048018788a5133b280981afb0d6da7e64f3cf5f9e39e501fe7b80807b872ece22f6e4b6b0d8279656ceef614c87ce7ee314a339ef44c3adc4f5e5451b2649c215a358c0682095e19d52ed454d5f4e364397928996823cb02c61f8304561cb21e3bd0f4399f283b0b1ded686ace5dc653b240760c6437323fab45418b904d2eef8ab0639b4cba7cccee58f471413505ca0f8bb5a859769ad9465ddac949d22114cacaeadb72962816c49f50adc6338da7a54bdda29f8e6e667d832bd9c9f9841be8b18");
    pub(crate) const SECRET_KEY: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
    pub(crate) const BASE: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");

    #[test]
    fn as_natural_number_and_as_natural_number_circles_correctly() {
        let x = PaillierModulusSizedNumber::from_be_hex("19BB1B2E0015AA04BEE4F8321819448A2C809DF799C6627668DAA936E3A367CF87BEC43C47551221E40724FE115FF8A4E72D5D46A0E98A934C45CD6904DA0F07499D798EE611497C9493354A9A48C35ECB6318CA55B8322E4295E67F8BC0BE1E0923685E1727B7925920D4F0E9CC30C2A10135DB447EDAD3BCE87C3416252C8B4DF32C24029E0269E7103E80D02DD5A42A99B69A613C6274255DF0599B0DED35A8969463636C6D56D67A05AE11F347A5D5B81896DF5F8A52E6EA7F05359A9FEFC90297BDD298DD77714D3557325DF1C52F42470606ECBFA5E964C0A782AE19CED2E20C73F0438EB597CAE4159B5E5333C97272D8EFEDB49CEB98078E92D990076E6E4101FD97588E4BBAA9DD5D19C671424108EE7FA5F2D74F9F3DEAB4A0AC89CF9833FD9BA1F66719978D7BD13DD2ECDE2BDC9628B1AC1E0A0C44B1408E8869A8B2245DF2A877E01730500AD15466A808E6D9636EEA7A7A0A06568413408E588C52451D189774D84547FBB4171255D6E0BFC9B63C56D582E02FA0F110EEAA2B728E51BC85F529805EBA5E1D6B7323597F1647B0A3DC6D61448C1C062CADE9831DB9E3029322D79D04BB3287B7C5D857AE11802B68921FBC403E390ED693DEAD66E1A728B7F7432408EB2ED9EB9BC3B2BCD8EB2CD44D41A5EBFB32F55BAF47D3AC048F5D1F60B2CB61C0F4E3C178DC7723B8298E9D52771DCF1DABA4088EF74B");
        let x = x % NonZero::new(N2).unwrap();

        assert_eq!(x.as_ring_element(&N2).as_natural_number(), x);
    }
}

#[cfg(feature = "benchmarking")]
criterion_group!(
    benches,
    // proofs::benchmark_proof_of_equality_of_discrete_logs,
    decryption_key_share::benchmark_decryption_share,
);
