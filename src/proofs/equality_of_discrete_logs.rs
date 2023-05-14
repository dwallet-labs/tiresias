use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{NonZero, Pow, Random};

use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::proofs::{ProofError, TranscriptProtocol};
use crate::{
    AsNaturalNumber, AsRingElement, ComputationalSecuritySizedNumber, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber, PaillierRingElement,
    ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
};

/// A proof of equality of the discrete logs of `self.a` and `self.b`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfEqualityOfDiscreteLogs {
    a: NonZero<PaillierModulusSizedNumber>, // $a \in \mathbb{Z}_{N^2}^*$.
    b: NonZero<PaillierModulusSizedNumber>, // $b \in \mathbb{Z}_{N^2}^*$.
    g_hat: PaillierModulusSizedNumber,      // $\hat{g} \in \mathbb{Z}_{N^2}$.
    h_hat: PaillierModulusSizedNumber,      // $\hat{h} \in \mathbb{Z}_{N^2}$.
    w: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber, // $w \in \mathbb{Z}$.
}

impl ProofOfEqualityOfDiscreteLogs {
    /// create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs of $a = g^d$ and $b = g^d$ in zero-knowledge (i.e. without revealing the secret discrete log `d`).
    pub fn prove(
        n: &LargeBiPrimeSizedNumber, // TODO: is there a more generalized version of this proof that isn't Paillier-specific? i.e. maybe the ring we are proving on shouldn't be $Z_{N^2|$ but a generic $Z_n$?
        d: &PaillierModulusSizedNumber,
        g: &PaillierModulusSizedNumber,
        h: &PaillierModulusSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let n2 = n.square();
        let g = g.as_ring_element(&n2);
        let h = h.as_ring_element(&n2);

        // Sample $r \leftarrow [0,2^{2\kappa}N^2)$, where k is the security parameter.
        // Note that we use 4096-bit instead of N^2 and that's even better
        let r = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random(rng);

        let g_hat = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&g, &r)
        .as_natural_number();
        let h_hat = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&h, &r)
        .as_natural_number();

        let a: PaillierModulusSizedNumber = g.pow(&d).as_natural_number();
        let b: PaillierModulusSizedNumber = h.pow(&d).as_natural_number();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &a);
        transcript.append_statement(b"b", &b);
        transcript.append_statement(b"g_hat", &g_hat);
        transcript.append_statement(b"h_hat", &h_hat);

        let u: ComputationalSecuritySizedNumber = transcript.challenge(b"u");

        // $u$ is a 128-bit number, multiplied by a 4096-bit $d$ => (4096 + 128)-bit number.
        // $r$ is a (256+4096)-bit number, so to get $ w = r - u*d $, which will never overflow (r is sampled randomly, the probability for r to be < ud < 1/2^128 which is the computational security parameter.
        // This results in a  a (4096 + 256)-bit number $w$
        let w = r.wrapping_sub(&((u * d).into()));

        ProofOfEqualityOfDiscreteLogs {
            a: NonZero::new(a).unwrap(),
            b: NonZero::new(b).unwrap(),
            g_hat,
            h_hat,
            w,
        }
    }

    /// verify that `self` represents a valid proof of equality of discrete logs of `self.a` and `self.b`.
    pub fn verify(
        &self,
        n: &LargeBiPrimeSizedNumber,
        g: &PaillierModulusSizedNumber,
        h: &PaillierModulusSizedNumber,
    ) -> Result<(), ProofError> {
        let n2 = n.square();
        let g = g.as_ring_element(&n2);
        let h = h.as_ring_element(&n2);
        let a = self.a.as_ring_element(&n2);
        let b = self.b.as_ring_element(&n2);

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &self.a);
        transcript.append_statement(b"b", &self.b);
        transcript.append_statement(b"g_hat", &self.g_hat);
        transcript.append_statement(b"h_hat", &self.h_hat);

        let u: ComputationalSecuritySizedNumber = transcript.challenge(b"u");

        let g_to_the_power_of_w = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&g, &self.w);
        let h_to_the_power_of_w = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&h, &self.w);

        let a_to_the_power_of_u = a.pow_bounded_exp(&u.into(), 128);
        let b_to_the_power_of_u = b.pow_bounded_exp(&u.into(), 128);

        if (g_to_the_power_of_w * a_to_the_power_of_u).as_natural_number() == self.g_hat
            && (h_to_the_power_of_w * b_to_the_power_of_u).as_natural_number() == self.h_hat
        {
            Ok(())
        } else {
            Err(ProofError {})
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::rand_core::OsRng;
    use crypto_bigint::{U2048, U4096, U4352};

    use super::*;

    const N: U2048 = U2048::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    const D: U4096 = U4096::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");

    const G: U4096 = U4096::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");
    const H: U4096 = U4096::from_be_hex("55552F74112BCD4B09E3DD1FA4848236DC83A33A0B5600F12071355D5C96B3EC2221BF357D843F0ECCE17FA392D14F8FA935F3C4121B7223A3B1EA6659E237CE7C346FC755037D116355FA19CCEDE6AF4BFAE051852BF2EAFE53F9F67E38B53B654670CC3D1124FF6FC6E9C53EE8B7BAD11CE14437CBAAB0C10762D15E2B1F85FC5A0144AD6DF3B61D921F0F91389953156538EF9314392D8AEEB0872B4E96AB2184452EA9446040DF0EB23F2C0CB3E6837B371E297B815BB5BAF42D2CFD73503200902636390601F24A9EDBE693DBF5FFADFBC67F062B25AF67B9C427618FA3E8BEC5A40F36E8CCFDFE0AEA294251F1AA53A9E2E2A6DB137A95BEED8C954C2A8B0A69B55579EECCFC93126CF70963C5ACD0B6B91BCF7E3CFFE09A576C991A0029226B1CC86C5B867CB0AC023E7372588D818DC2D582E521BF73A7DE59084C76C011C02773FC0A2E11AE81768AC7DF56ACE8749A49FEFCB0BB8BEC8F9B34EBF29F7267C5537147A53B89A0495EA256EA07DBA005A890A11C30F5CDB85D4B1F0BC3202BF5AA5F6A9AF7CC3A53A188B15D42F2BA7EEBED470016EBDACF6F994EA739DCC301245377508CB4D1A6556E153BD43E4B19A84B5444CC13ABA3F093D60B077D5956A94FFD7964AD1EE1572B8521D77622B21975484A54390B18E94BE87DDCD3AA0B842DAAA77144EEBBD79C34BAB481E51C21E5E4897C2576EA4DB8F51C");

    #[test]
    fn valid_proof_verifies() {
        let proof = ProofOfEqualityOfDiscreteLogs::prove(&N, &D, &G, &H, &mut OsRng);

        assert!(proof.verify(&N, &G, &H).is_ok());
    }

    /* These tests may look silly, for we are trying to create a non-zero from zero,
    but keeping them here is important - as trying to change e.g. the type of a from NonZero<PaillierModulusSizedNumber> to PaillierModulusSizedNumber will cause a compilation error here,
    and then the following warning should cease this immediately:
        WARNING: NonZero is crucial here: this assures to the verifier that the element is not zero and therefore in the multiplicative group -
                 without this, the proof is broken - don't change!
        // TODO: should I keep these kind of comments?
    */
    #[test]
    #[should_panic]
    fn cannot_construct_proof_with_zero_a() {
        ProofOfEqualityOfDiscreteLogs {
            a: NonZero::new(PaillierModulusSizedNumber::ZERO).unwrap(),
            b: NonZero::new(PaillierModulusSizedNumber::ONE).unwrap(),
            g_hat: PaillierModulusSizedNumber::ZERO,
            h_hat: PaillierModulusSizedNumber::ZERO,
            w: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ZERO,
        };
    }

    #[test]
    #[should_panic]
    fn cannot_construct_proof_with_zero_b() {
        ProofOfEqualityOfDiscreteLogs {
            a: NonZero::new(PaillierModulusSizedNumber::ONE).unwrap(),
            b: NonZero::new(PaillierModulusSizedNumber::ZERO).unwrap(),
            g_hat: PaillierModulusSizedNumber::ZERO,
            h_hat: PaillierModulusSizedNumber::ZERO,
            w: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ZERO,
        };
    }

    #[test]
    fn invalid_proof_fails_verification() {
        /* ןרדא generate a random proof and make sure it fails */
        let a = U4096::from_be_hex("391875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let b = U4096::from_be_hex("458884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let g_hat = U4096::from_be_hex("1B8DC8C817CAF6ABF6B3BE337E6D723BABFC968213DFC5BE5E9B524B380A58BE0ADB12576177AFC3604D6DC28303D5F5A0B54303B033AA73C10DA59008C6B5806CE3C781096BBB32CBC3E5FF70B62A1D6F0525152E70F8FA5751249EF7B3E21DBB6DD735C11CA6282863B4FDA8FE2C993F03C3D5E008F28218FA57647F0526BCF355CB2D589DA8D2CEED3E2013B55A803300544368AF573184CC7472C9B33CB39B541E2D388384BA86E913A62B6C61D65755FD75CD79B7ACBF41EF8755E8C50C1E9D5D01B0FFCAEA990194EA41FC4591032C79517B10F2DBB23868300B222BE6DFA7B974A7BCAC395CAE72D655F2EDBFF6D6407DF874600CE7688EBFE440336681EA1A44395F67D1CC9D1C092B889D3049465D0FC21C74FA3642018A73C9510FDF6C89CE0AAC3DCC089A3092BC029F518548B2D158FBBDCEA4634D0EEDBA32E2A095886F995F5C3D6C146371F633145823DA4AAA022A62CF7F9D76597F6A550F41FEA5EC7310ED59E1134F5F86B84AFAD4911270361370B3313CD46F01CEDDCAEA1A580F5A4D3C58888F5802BEC2FED81AC7733D3399A5E6D9D3EF8B136906694709E0C0348EF083A0106AC41979289A41B0356362A85BA40A6AEA0191A83E5C48CE580FAA9AE1DE8462E8CEBDCB3BC879C5F5AFB4F2B136E057BFB314AB19CC64018F933647FA18BD4CB6F75BE614708EF748EDBA2A1BEDB115E8BBEB2B96CC");
        let h_hat = U4096::from_be_hex("2EAA0D625BD67781CFFCC4563365C37CDCEC8782B451703D4130F7B05E4D080EFF1668E8E96125EE991C45076AB92EFA40232A2C150A96A8DB72F9FB1E7EC57924A13465113ECF9CA575C312C11841C83935B81137B3172C5AB86CCF7EE400D525F5FDA24194F6BCEB4ECDA99EDCE509DDA1B5106EECE1962FFA65FE6B359E5524685ECB5C785B8B0F91744BB2B50EBEE981099AC4B66F6CCF01B1D16F6611D0846EAA44E20C4895CC77CC4CECD1A2AA34CCC97AE0D91C9438FBD0A59A66AB669BD35D78869DD9801C0B13CBBF202F8E21C21B4B76C006DE01A93DC708DE5777B1F305598DEC6552F92DB4166D10B784C6E897579265CA6C48721947F5CF0FC2B65C1EF15A0A62AF54478DD2E3275942A6D2E628C7FD56F1522DD6B251ECD129B93CDC76167A16B52711AB02315EA7D53C0F5F15403AC7BDC1DB3D65D714DA38ED350590D4ACB2B8CC6F4597C4CBCE311F8EA71B3B5783A3C57BACAA7D065EA12190DD982ADC78ECBE0F864016EDB59E9097D6D0DBECAA5F9E8272F1204246059AE42348DC978AF8F0E82BC13940559A7900AE10F343253F97611493EFA673FF74C695476A90FAD5AE734885C86C895F1CFF3E4731A3569F2295B119A46D48632BEB2576D0C0435E49C61FDFA0960C31E79D6BEFF0A1676F8F15A45B3E74B1905035DC3414B812B4253896CB04EDD6C9C4B9822FC2A2A567DEDB3F8730BBD2BD");
        let w = U4352::from_be_hex("D09B42E9E0E7923F33FB1A81A72545DBF6710C72D43F1CDA195A2461A414BE228F4DA35BF1056AC4E58D04167D66C0E69417ED428CE39CE810BFA0AA589917E22C2D9519EC475BDCBDE46B5898E730F3B15D58E5906848106909B5A423F3DCA73F7C130424442E171CDFD7F58A808D974766A576D90C72119084A91156989E8DBB100329B81F1EC8E592CF84802FACC1049ED522C83D13E52CC45630DD70A2045F657E209496B4218CD6B394BBDC799CABB393BF8A3AEC3379BF40F19FA40C5EC4A375C6946A56778F3CAFA43D319F1116E36D88D447A89EF2D7BD822E15FB09F1C4E3B00FEB167C715DF1318DC0D1C3ACE3B739C0E1C886E43AB49EFFD1E697CE0F8F68BA31468DED59B466F0249A9AE395A1FC4533164AD7F543D1195C11F99B9D18E08464A10CB6CC42FD39E838B0CD5512435F1CC1A29D4B60A013700D5D5E95459C354A140533B7FA938A9E7E6E7ECFB233BC80A40E495577F901DE5229B73823473EACCFC058320F98CA2D124E47E5412BA8C88517077DE964830A487E80C8A4A49343B7000AE2D702998F8CB3A812BB01971BC47BA514A5723382AFD3AF3EC5F9D9C17FC33157C49B8E84453B80F636C92600D31A4EEF6E92694B99C02489443351319CC576B763E4C293A0CDDF620A38DB381D252D8FDD2DF239B67404586DA8C34A4A993351AAC1188DF6D26CDAEF1B3A46599C3A310376C7FFB2CA75AE4A32E539D34615269A9D2BE93C4CF8B557677E04737AA0395E392AE6A804");
        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            a: NonZero::new(a).unwrap(),
            b: NonZero::new(b).unwrap(),
            g_hat,
            h_hat,
            w,
        };

        assert!(invalid_proof.verify(&N, &G, &H).is_err());

        /* Now generate a valid proof, and make sure that if we change any field it fails */
        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(&N, &D, &G, &H, &mut OsRng);

        let mut invalid_proof = valid_proof.clone();

        // TODO: can this be better written with rstest?
        invalid_proof.a = NonZero::new(U4096::ONE).unwrap();
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.a = NonZero::new(a).unwrap();
        assert!(invalid_proof.verify(&N, &G, &H).is_err());

        invalid_proof.b = NonZero::new(U4096::ONE).unwrap();
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.b = NonZero::new(b).unwrap();
        assert!(invalid_proof.verify(&N, &G, &H).is_err());

        invalid_proof.g_hat = U4096::ZERO;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.g_hat = U4096::ONE;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.g_hat = g_hat;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());

        invalid_proof.h_hat = U4096::ZERO;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.h_hat = U4096::ONE;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.h_hat = h_hat;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());

        invalid_proof.w = U4352::ZERO;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.w = U4352::ONE;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
        invalid_proof.w = w;
        assert!(invalid_proof.verify(&N, &G, &H).is_err());
    }
}
