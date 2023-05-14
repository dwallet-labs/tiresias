use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Uint, U1024, U128};

/* Types & Trait (impls) around `crypto_bigint` for internal use */

pub(crate) type ComputationalSecuritySizedNumber = U128;
pub(crate) type LargePrimeSizedNumber = U1024;
pub(crate) type LargeBiPrimeSizedNumber = <LargePrimeSizedNumber as Concat>::Output;
pub(crate) type PaillierModulusSizedNumber = <LargeBiPrimeSizedNumber as Concat>::Output;
pub(crate) type PaillierRingElement = DynResidue<{ PaillierModulusSizedNumber::LIMBS }>;
pub(crate) type ProofOfEqualityOfDiscreteLogsRandomizerSizedNumber = Uint<
    {
        PaillierModulusSizedNumber::LIMBS
            + <ComputationalSecuritySizedNumber as Concat>::Output::LIMBS
    },
>;

pub(crate) trait AsNaturalNumber {
    fn as_natural_number(&self) -> PaillierModulusSizedNumber;
}

pub(crate) trait AsRingElement {
    fn as_ring_element(&self, n: &Self) -> PaillierRingElement;
}

impl AsNaturalNumber for PaillierRingElement {
    fn as_natural_number(&self) -> PaillierModulusSizedNumber {
        self.retrieve()
    }
}

impl AsRingElement for PaillierModulusSizedNumber {
    fn as_ring_element(&self, n: &Self) -> PaillierRingElement {
        let ring_params = DynResidueParams::new(n);
        DynResidue::new(self, ring_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::NonZero;

    #[test]
    fn as_natural_number_and_as_natural_number_circles_correctly() {
        let n = PaillierModulusSizedNumber::from_be_hex("5960383b5378ad0607f0f270ce7fb6dcaba6506f9fc56deeffaf605c9128db8ccf063e2e8221a8bdf82c027741a0303b08eb71fa6225a03df18f24c473dc6d4d3d30eb9c52a233bbfe967d04011b95e8de5bc482c3c217bcfdeb4df6f57af6ba9c6d66c69fb03a70a41fe1e87975c85343ef7d572ca06a0139706b23ed2b73ad72cb1b7e2e41840115651897c8757b3da9af3a60eebb6396ffd193738b4f04aa6ece638cef1bf4e9c45cf57f8debeda8598cbef732484752f5380737ba75ee00bf1b146817b9ab336d0ce5540395377347c653d1c9d272127ff12b9a0721b8ef13ecd8a8379f1b9a358de2af2c4cd97564dbd5328c2fc13d56ee30c8a101d333f5406afb1f4417b49d7a629d5076726877df11f05c998ae365e374a0141f0b99802214532c97c1ebf9faf6e277a8f29dbd8f3eab72266e60a77784249694819e42877a5e826745c97f84a5f37002b74d83fc064cf094be0e706a6710d47d253c4532e6aa4a679a75fa1d860b39085dab03186c67248e6c92223682f58bd41b67143e299329ce3a8045f3a0124c3d0ef9f0f49374d89b37d9c3321feb2ab4117df4f68246724ce41cd765326457968d848afcc0735531e5de7fea88cf2eb35ac68710c6e79d5ad25df6c0393c0267f56e8eac90a52637abe3e606769e70b20560eaf70e0d531b11dca299104fa933f887d85fb5f72386c196e40f559baee356b9");
        let x = PaillierModulusSizedNumber::from_be_hex("19BB1B2E0015AA04BEE4F8321819448A2C809DF799C6627668DAA936E3A367CF87BEC43C47551221E40724FE115FF8A4E72D5D46A0E98A934C45CD6904DA0F07499D798EE611497C9493354A9A48C35ECB6318CA55B8322E4295E67F8BC0BE1E0923685E1727B7925920D4F0E9CC30C2A10135DB447EDAD3BCE87C3416252C8B4DF32C24029E0269E7103E80D02DD5A42A99B69A613C6274255DF0599B0DED35A8969463636C6D56D67A05AE11F347A5D5B81896DF5F8A52E6EA7F05359A9FEFC90297BDD298DD77714D3557325DF1C52F42470606ECBFA5E964C0A782AE19CED2E20C73F0438EB597CAE4159B5E5333C97272D8EFEDB49CEB98078E92D990076E6E4101FD97588E4BBAA9DD5D19C671424108EE7FA5F2D74F9F3DEAB4A0AC89CF9833FD9BA1F66719978D7BD13DD2ECDE2BDC9628B1AC1E0A0C44B1408E8869A8B2245DF2A877E01730500AD15466A808E6D9636EEA7A7A0A06568413408E588C52451D189774D84547FBB4171255D6E0BFC9B63C56D582E02FA0F110EEAA2B728E51BC85F529805EBA5E1D6B7323597F1647B0A3DC6D61448C1C062CADE9831DB9E3029322D79D04BB3287B7C5D857AE11802B68921FBC403E390ED693DEAD66E1A728B7F7432408EB2ED9EB9BC3B2BCD8EB2CD44D41A5EBFB32F55BAF47D3AC048F5D1F60B2CB61C0F4E3C178DC7723B8298E9D52771DCF1DABA4088EF74B");
        let x = x % NonZero::new(n).unwrap();

        assert_eq!(x.as_ring_element(&n).as_natural_number(), x);
    }
}
