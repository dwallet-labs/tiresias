#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_proof_of_equality_of_discrete_logs;
use crypto_bigint::{rand_core::CryptoRngCore, Pow, Random};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    proofs::{ProofError, TranscriptProtocol},
    AsNaturalNumber, AsRingElement, ComputationalSecuritySizedNumber, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber, PaillierRingElement,
    ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
};

/// A proof of equality of discrete logs
/// This is an optimized form of the proof which does not include the base (squared) & ciphertext
/// (squared) randomizers. Instead, it includes the challenge, from which the verifier can recover
/// the randomizers and verify the challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProofOfEqualityOfDiscreteLogs {
    // The challenge $u \in \mathbb{Z}$.
    challenge: ComputationalSecuritySizedNumber,
    // The response $w \in \mathbb{Z}$.
    response: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
}

const TRANSCRIPT_LABEL: &[u8; 34] = b"Proof of Equality of Discrete Logs";
const TRANSCRIPT_N_SQUARED: &[u8; 11] = b"N (squared)";
const TRANSCRIPT_G_BASE_SQUARED: &[u8; 16] = b"g_base (squared)";
const TRANSCRIPT_CIPHERTEXT_BIQUADRATED: &[u8; 24] = b"ciphertext (biquadrated)";
const TRANSCRIPT_PERSONAL_VERIFICATION_KEY_SQUARED: &[u8; 35] =
    b"personal verification key (squared)";
const TRANSCRIPT_DECRYPTION_SHARE_SQUARED: &[u8; 26] = b"decryption share (squared)";
const TRANSCRIPT_G_BASE_RANDOMIZED: &[u8; 27] = b"g base (squared) randomized";
const TRANSCRIPT_CIPHERTEXT_BIQUADRATED_RANDOMIZED: &[u8; 35] =
    b"ciphertext (biquadrated) randomized";
const TRANSCRIPT_CHALLENGE: &[u8; 9] = b"challenge";

impl ProofOfEqualityOfDiscreteLogs {
    /// Create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs of
    /// $a = g^d$ and $b = h^d$ in zero-knowledge (i.e. without revealing the secret discrete log
    /// `d`).
    pub(crate) fn prove(
        // Paillier modulus (Encryption public key)
        n2: &PaillierModulusSizedNumber,
        // Witness $d$ (the secret-key share in threshold decryption)
        secret_key_share: &PaillierModulusSizedNumber,
        // Global verification key $g$
        g_base: &PaillierModulusSizedNumber,
        // Ciphertext $h$
        ciphertext: &PaillierModulusSizedNumber,
        // Personal (public) verification key $a$ ($a = g^d$).
        personal_verification_key: &PaillierModulusSizedNumber,
        // Decryption share $b = h^d$
        decryption_share: &PaillierModulusSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let g_base_squared = g_base
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);
        let ciphertext_biquadrated = ciphertext
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(4u8), 3);
        let personal_verification_key_squared = personal_verification_key
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);
        let decryption_share_squared = decryption_share
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);

        // Sample $r \leftarrow [0,2^{2\kappa}N^2)$, where k is the security parameter.
        // Note that we use 4096-bit instead of $N^2$ and it does not affect the security.
        let randomizer = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random(rng);

        let g_base_squared_randomized = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&g_base_squared, &randomizer)
        .as_natural_number();
        let ciphertext_biquadrated_randomized = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(
            &ciphertext_biquadrated, &randomizer
        )
        .as_natural_number();

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);

        transcript.append_statement(TRANSCRIPT_N_SQUARED, n2);
        transcript.append_statement(
            TRANSCRIPT_G_BASE_SQUARED,
            &g_base_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_CIPHERTEXT_BIQUADRATED,
            &ciphertext_biquadrated.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_PERSONAL_VERIFICATION_KEY_SQUARED,
            &personal_verification_key_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_DECRYPTION_SHARE_SQUARED,
            &decryption_share_squared.as_natural_number(),
        );
        transcript.append_statement(TRANSCRIPT_G_BASE_RANDOMIZED, &g_base_squared_randomized);
        transcript.append_statement(
            TRANSCRIPT_CIPHERTEXT_BIQUADRATED_RANDOMIZED,
            &ciphertext_biquadrated_randomized,
        );
        let challenge: ComputationalSecuritySizedNumber =
            transcript.challenge(TRANSCRIPT_CHALLENGE);

        // $u*d$ is a 128-bit number $u$, multiplied by a 4096-bit number $d$ => (4096 + 128)-bit
        // number.
        // $r$ is a (256+4096)-bit number, so to get $w = r - u*d$, which will
        // never overflow (r is sampled randomly, the probability for r to be < u*d is < 1/2^128
        // which is the computational security parameter. This results in a (4096 + 256)-bit
        // number $w$).
        let response = randomizer.wrapping_sub(&((challenge * secret_key_share).into()));

        ProofOfEqualityOfDiscreteLogs {
            challenge,
            response,
        }
    }

    /// verify that `self` represents a valid proof of equality of discrete logs of
    /// `personal_verification_key` and `decryption_share` with respect to the bases `g_base` and
    /// `ciphertext` respectively.
    #[allow(dead_code)]
    pub(crate) fn verify(
        &self,
        // Paillier associated bi-prime $N$
        n: &LargeBiPrimeSizedNumber,
        // Global verification key $g$
        g_base: &PaillierModulusSizedNumber,
        // Ciphertext $h$
        ciphertext: &PaillierModulusSizedNumber,
        // Personal verification key $a = g^d$
        personal_verification_key: &PaillierModulusSizedNumber,
        // Decryption share $b = h^d$
        decryption_share: &PaillierModulusSizedNumber,
    ) -> Result<(), ProofError> {
        let n2 = n.square();

        // The paper assumes that $a, b, g, h\in QR_{N}$ after the setup.
        // In order to eliminate problems from the caller's side, we perform the squaring ourselves
        // to assure it is in the quadratic residue group.
        let g_base_squared = g_base
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);
        let ciphertext_biquadrated = ciphertext
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(4u8), 3);
        let personal_verification_key_squared = personal_verification_key
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);
        let decryption_share_squared = decryption_share
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);

        // Every square number except for zero that is not co-primed to $N^2$ yields factorization
        // of $N$, Therefore checking that a square number is not zero sufficiently assures
        // they belong to the quadratic-residue group.
        //
        // Note that if we'd have perform this check prior to squaring, it wouldn't have suffice;
        // take e.g. $g = N \neq 0$ -> $g^2 = N^2 mod N^2 = 0$
        // (accepting this value would have allowed bypassing of the proof).
        if g_base_squared == PaillierModulusSizedNumber::ZERO.as_ring_element(&n2)
            || ciphertext_biquadrated == PaillierModulusSizedNumber::ZERO.as_ring_element(&n2)
            || personal_verification_key_squared
                == PaillierModulusSizedNumber::ZERO.as_ring_element(&n2)
            || decryption_share_squared == PaillierModulusSizedNumber::ZERO.as_ring_element(&n2)
        {
            return Err(ProofError {});
        }

        let g_base_squared_raised_to_the_response = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&g_base_squared, &self.response);

        let ciphertext_biquadrated_raised_to_the_response =
            <PaillierRingElement as Pow<ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber>>::pow(
                &ciphertext_biquadrated,
                &self.response,
            );

        let personal_verification_key_squared_raised_to_the_challenge =
            <PaillierRingElement as Pow<ComputationalSecuritySizedNumber>>::pow(
                &personal_verification_key_squared,
                &self.challenge,
            );

        let decryption_share_squared_raised_to_the_challenge =
            <PaillierRingElement as Pow<ComputationalSecuritySizedNumber>>::pow(
                &decryption_share_squared,
                &self.challenge,
            );

        // The base randomizer $\hat{g} \in \mathbb{Z}_{N^2}^*$.
        let g_base_squared_randomized = (g_base_squared_raised_to_the_response
            * personal_verification_key_squared_raised_to_the_challenge)
            .as_natural_number();

        // The ciphertext randomizer $\hat{h} \in \mathbb{Z}_{N^2}^*$.
        let ciphertext_biquadrated_randomized = (ciphertext_biquadrated_raised_to_the_response
            * decryption_share_squared_raised_to_the_challenge)
            .as_natural_number();

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        transcript.append_statement(TRANSCRIPT_N_SQUARED, &n2);
        transcript.append_statement(
            TRANSCRIPT_G_BASE_SQUARED,
            &g_base_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_CIPHERTEXT_BIQUADRATED,
            &ciphertext_biquadrated.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_PERSONAL_VERIFICATION_KEY_SQUARED,
            &personal_verification_key_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_DECRYPTION_SHARE_SQUARED,
            &decryption_share_squared.as_natural_number(),
        );
        transcript.append_statement(TRANSCRIPT_G_BASE_RANDOMIZED, &g_base_squared_randomized);
        transcript.append_statement(
            TRANSCRIPT_CIPHERTEXT_BIQUADRATED_RANDOMIZED,
            &ciphertext_biquadrated_randomized,
        );

        let challenge: ComputationalSecuritySizedNumber =
            transcript.challenge(TRANSCRIPT_CHALLENGE);
        if challenge == self.challenge {
            return Ok(());
        }
        Err(ProofError {})
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::tests::{CIPHERTEXT, G_BASE, N, SECRET_KEY};

    #[test]
    fn valid_proof_verifies() {
        let n2 = N.square();

        let personal_verification_key = G_BASE
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();
        let decryption_share = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow(&SECRET_KEY)
            .as_natural_number();

        let proof = ProofOfEqualityOfDiscreteLogs::prove(
            &n2,
            &SECRET_KEY,
            &G_BASE,
            &CIPHERTEXT,
            &personal_verification_key,
            &decryption_share,
            &mut OsRng,
        );

        assert!(proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &personal_verification_key,
                &decryption_share,
            )
            .is_ok());
    }

    fn craft_proof(
        n2: &PaillierModulusSizedNumber,
        g_base: &PaillierModulusSizedNumber,
        ciphertext: &PaillierModulusSizedNumber,
        personal_verification_key: &PaillierModulusSizedNumber,
        decryption_share: &PaillierModulusSizedNumber,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let g_base_squared = g_base
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);
        let ciphertext_biquadrated = ciphertext
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(4u8), 3);
        let personal_verification_key_squared = personal_verification_key
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);
        let decryption_share_squared = decryption_share
            .as_ring_element(n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        transcript.append_statement(TRANSCRIPT_N_SQUARED, n2);
        transcript.append_statement(
            TRANSCRIPT_G_BASE_SQUARED,
            &g_base_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_CIPHERTEXT_BIQUADRATED,
            &ciphertext_biquadrated.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_PERSONAL_VERIFICATION_KEY_SQUARED,
            &personal_verification_key_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_DECRYPTION_SHARE_SQUARED,
            &decryption_share_squared.as_natural_number(),
        );
        transcript.append_statement(
            TRANSCRIPT_G_BASE_RANDOMIZED,
            &PaillierModulusSizedNumber::ZERO,
        );
        transcript.append_statement(
            TRANSCRIPT_CIPHERTEXT_BIQUADRATED_RANDOMIZED,
            &PaillierModulusSizedNumber::ZERO,
        );

        let challenge: ComputationalSecuritySizedNumber =
            transcript.challenge(TRANSCRIPT_CHALLENGE);
        let wrong_response = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::from_be_hex("D09B42E9E0E7923F33FB1A81A72545DBF6710C72D43F1CDA195A2461A414BE228F4DA35BF1056AC4E58D04167D66C0E69417ED428CE39CE810BFA0AA589917E22C2D9519EC475BDCBDE46B5898E730F3B15D58E5906848106909B5A423F3DCA73F7C130424442E171CDFD7F58A808D974766A576D90C72119084A91156989E8DBB100329B81F1EC8E592CF84802FACC1049ED522C83D13E52CC45630DD70A2045F657E209496B4218CD6B394BBDC799CABB393BF8A3AEC3379BF40F19FA40C5EC4A375C6946A56778F3CAFA43D319F1116E36D88D447A89EF2D7BD822E15FB09F1C4E3B00FEB167C715DF1318DC0D1C3ACE3B739C0E1C886E43AB49EFFD1E697CE0F8F68BA31468DED59B466F0249A9AE395A1FC4533164AD7F543D1195C11F99B9D18E08464A10CB6CC42FD39E838B0CD5512435F1CC1A29D4B60A013700D5D5E95459C354A140533B7FA938A9E7E6E7ECFB233BC80A40E495577F901DE5229B73823473EACCFC058320F98CA2D124E47E5412BA8C88517077DE964830A487E80C8A4A49343B7000AE2D702998F8CB3A812BB01971BC47BA514A5723382AFD3AF3EC5F9D9C17FC33157C49B8E84453B80F636C92600D31A4EEF6E92694B99C02489443351319CC576B763E4C293A0CDDF620A38DB381D252D8FDD2DF239B67404586DA8C34A4A993351AAC1188DF6D26CDAEF1B3A46599C3A310376C7FFB2CA75AE4A32E539D34615269A9D2BE93C4CF8B557677E04737AA0395E392AE6A804");

        ProofOfEqualityOfDiscreteLogs {
            challenge,
            response: wrong_response,
        }
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let n2 = N.square();

        // generate a random proof and make sure it fails
        let wrong_g_base = PaillierModulusSizedNumber::from_be_hex("391875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_ciphertext = PaillierModulusSizedNumber::from_be_hex("458884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_personal_verification_key = PaillierModulusSizedNumber::from_be_hex("891875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share = PaillierModulusSizedNumber::from_be_hex("058884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_response = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::from_be_hex("D09B42E9E0E7923F33FB1A81A72545DBF6710C72D43F1CDA195A2461A414BE228F4DA35BF1056AC4E58D04167D66C0E69417ED428CE39CE810BFA0AA589917E22C2D9519EC475BDCBDE46B5898E730F3B15D58E5906848106909B5A423F3DCA73F7C130424442E171CDFD7F58A808D974766A576D90C72119084A91156989E8DBB100329B81F1EC8E592CF84802FACC1049ED522C83D13E52CC45630DD70A2045F657E209496B4218CD6B394BBDC799CABB393BF8A3AEC3379BF40F19FA40C5EC4A375C6946A56778F3CAFA43D319F1116E36D88D447A89EF2D7BD822E15FB09F1C4E3B00FEB167C715DF1318DC0D1C3ACE3B739C0E1C886E43AB49EFFD1E697CE0F8F68BA31468DED59B466F0249A9AE395A1FC4533164AD7F543D1195C11F99B9D18E08464A10CB6CC42FD39E838B0CD5512435F1CC1A29D4B60A013700D5D5E95459C354A140533B7FA938A9E7E6E7ECFB233BC80A40E495577F901DE5229B73823473EACCFC058320F98CA2D124E47E5412BA8C88517077DE964830A487E80C8A4A49343B7000AE2D702998F8CB3A812BB01971BC47BA514A5723382AFD3AF3EC5F9D9C17FC33157C49B8E84453B80F636C92600D31A4EEF6E92694B99C02489443351319CC576B763E4C293A0CDDF620A38DB381D252D8FDD2DF239B67404586DA8C34A4A993351AAC1188DF6D26CDAEF1B3A46599C3A310376C7FFB2CA75AE4A32E539D34615269A9D2BE93C4CF8B557677E04737AA0395E392AE6A804");
        let wrong_challenge =
            ComputationalSecuritySizedNumber::from_be_hex("5C39491D60D4D0CC8914C67D6CF41212");

        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            challenge: wrong_challenge,
            response: wrong_response,
        };

        assert!(invalid_proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &wrong_personal_verification_key,
                &wrong_decryption_share,
            )
            .is_err());

        let personal_verification_key = G_BASE
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();
        let decryption_share = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow(&SECRET_KEY)
            .as_natural_number();

        // Try to fool verification with zeroed out fields
        let crafted_proof = craft_proof(
            &n2,
            &G_BASE,
            &CIPHERTEXT,
            &PaillierModulusSizedNumber::ZERO,
            &PaillierModulusSizedNumber::ZERO,
        );

        assert!(crafted_proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &PaillierModulusSizedNumber::ZERO,
                &PaillierModulusSizedNumber::ZERO,
            )
            .is_err());

        // Try to fool verification with fields that their square is zero mod N^2 (e.g. N)
        let crafted_proof = craft_proof(&n2, &G_BASE, &CIPHERTEXT, &N.into(), &N.into());

        assert!(crafted_proof
            .verify(&N, &G_BASE, &CIPHERTEXT, &N.into(), &N.into(),)
            .is_err());

        // Now generate a valid proof, and make sure that if we change any field it fails
        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(
            &n2,
            &SECRET_KEY,
            &G_BASE,
            &CIPHERTEXT,
            &personal_verification_key,
            &decryption_share,
            &mut OsRng,
        );

        // Assure that verification fails for random values
        assert!(valid_proof
            .verify(
                &N,
                &wrong_g_base,
                &CIPHERTEXT,
                &personal_verification_key,
                &decryption_share,
            )
            .is_err());

        assert!(valid_proof
            .verify(
                &N,
                &G_BASE,
                &wrong_ciphertext,
                &personal_verification_key,
                &decryption_share,
            )
            .is_err());

        assert!(valid_proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &wrong_personal_verification_key,
                &decryption_share,
            )
            .is_err());

        assert!(valid_proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &personal_verification_key,
                &wrong_decryption_share,
            )
            .is_err());

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.challenge = wrong_challenge;
        assert!(invalid_proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &personal_verification_key,
                &decryption_share,
            )
            .is_err());

        invalid_proof = valid_proof;
        invalid_proof.response = wrong_response;
        assert!(invalid_proof
            .verify(
                &N,
                &G_BASE,
                &CIPHERTEXT,
                &personal_verification_key,
                &decryption_share,
            )
            .is_err());
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::{BatchSize, Criterion};
    use crypto_bigint::{NonZero, RandomMod};
    use rand_core::OsRng;

    use super::*;

    pub(crate) fn benchmark_proof_of_equality_of_discrete_logs(c: &mut Criterion) {
        let mut g = c.benchmark_group("proof of equality of discrete logs benches");
        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();
        let secret_key_share = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");

        g.bench_function(
            "benchmark proof of equality of discrete logs' prove()",
            |bench| {
                bench.iter_batched(
                    || {
                        let g_base = PaillierModulusSizedNumber::random_mod(
                            &mut OsRng,
                            &NonZero::new(n2).unwrap(),
                        );
                        let ciphertext = PaillierModulusSizedNumber::random_mod(
                            &mut OsRng,
                            &NonZero::new(n2).unwrap(),
                        );

                        let personal_verification_key = g_base
                            .as_ring_element(&n2)
                            .pow(&secret_key_share)
                            .as_natural_number();
                        let decryption_share = ciphertext
                            .as_ring_element(&n2)
                            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                            .pow(&secret_key_share)
                            .as_natural_number();
                        (
                            secret_key_share,
                            g_base,
                            ciphertext,
                            personal_verification_key,
                            decryption_share,
                        )
                    },
                    |(
                        secret_key_share,
                        g_base,
                        ciphertext,
                        personal_verification_key,
                        decryption_share,
                    )| {
                        ProofOfEqualityOfDiscreteLogs::prove(
                            &n2,
                            &secret_key_share,
                            &g_base,
                            &ciphertext,
                            &personal_verification_key,
                            &decryption_share,
                            &mut OsRng,
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        g.bench_function(
            "benchmark proof of equality of discrete logs' verify()",
            |bench| {
                bench.iter_batched(
                    || {
                        let g_base = PaillierModulusSizedNumber::random_mod(
                            &mut OsRng,
                            &NonZero::new(n2).unwrap(),
                        );
                        let ciphertext = PaillierModulusSizedNumber::random_mod(
                            &mut OsRng,
                            &NonZero::new(n2).unwrap(),
                        );

                        let personal_verification_key = g_base
                            .as_ring_element(&n2)
                            .pow(&secret_key_share)
                            .as_natural_number();
                        let decryption_share = ciphertext
                            .as_ring_element(&n2)
                            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                            .pow(&secret_key_share)
                            .as_natural_number();
                        (
                            n,
                            g_base,
                            ciphertext,
                            personal_verification_key,
                            decryption_share,
                            ProofOfEqualityOfDiscreteLogs::prove(
                                &n2,
                                &secret_key_share,
                                &g_base,
                                &ciphertext,
                                &personal_verification_key,
                                &decryption_share,
                                &mut OsRng,
                            ),
                        )
                    },
                    |(
                        n,
                        g_base,
                        ciphertext,
                        personal_verification_key,
                        decryption_share,
                        proof,
                    )| {
                        proof.verify(
                            &n,
                            &g_base,
                            &ciphertext,
                            &personal_verification_key,
                            &decryption_share,
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        g.finish();
    }
}
