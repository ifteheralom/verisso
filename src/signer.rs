// use crate::constant::*;
use crate::constant::*;
use crate::ot::do_pairwise_base_ot;
use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::threshold::multiplication_phase::Phase2;
use bbs_plus::threshold::randomness_generation_phase::Phase1;
use bbs_plus::threshold::threshold_bbs::Phase1Output;
use blake2::Blake2b512;
use oblivious_transfer_protocols::cointoss::Commitments;
use oblivious_transfer_protocols::ot_based_multiplication::batch_mul_multi_party::Message1;
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
};
use oblivious_transfer_protocols::ParticipantId;
use std::collections::{BTreeMap, BTreeSet};

pub struct Signer {
    pub id: u16,
    pub sk_share: Option<Fr>,
    pub rng: StdRng,
    pub all_party_set: BTreeSet<u16>,
    pub threshold_party_set: BTreeSet<u16>,
    pub protocol_id: Vec<u8>,
}

impl Signer {
    pub fn new(id: u16) -> Self {
        Signer {
            rng: StdRng::seed_from_u64(0u64),
            all_party_set: (1..=TOTAL_SIGNERS).into_iter().collect::<BTreeSet<_>>(),
            // THRESHOLD_SIGNERS -> TOTAL_SIGNERS
            threshold_party_set: (1..=THRESHOLD_SIGNERS).into_iter().collect::<BTreeSet<_>>(),
            protocol_id: b"test".to_vec(),
            id: id,
            sk_share: None,
        }
    }

    pub fn set_sk_share(&mut self, sk_share: Fr) {
        self.sk_share = Some(sk_share);
    }

    pub fn do_round1(
        &self,
    ) -> (
        Phase1<Fr, 256>,
        Commitments,
        BTreeMap<ParticipantId, Commitments>,
    ) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut others = self.threshold_party_set.clone();
        others.remove(&self.id);

        Phase1::<Fr, 256>::init_for_bbs(
            &mut rng,
            SIG_BATCH_SIZE,
            self.id,
            others.clone(),
            self.protocol_id.clone(),
        )
        .unwrap()
    }

    pub fn finish_round1(&self, round1: Phase1<Fr, 256>) -> Phase1Output<Fr> {
        let sk_share = &self.sk_share.unwrap();
        println!("Finishing round 1 with sk_share: {:?}", sk_share);
        let result = round1.finish_for_bbs::<Blake2b512>(sk_share).unwrap();

        println!("Finished round 1");

        result
    }

    pub fn do_round2(
        &self,
        masked_signing_key_share: Vec<Fr>,
        masked_r: Vec<Fr>,
    ) -> (Phase2<Fr, 256, 80>, BTreeMap<ParticipantId, Message1<Fr>>) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut others = self.threshold_party_set.clone();
        others.remove(&self.id);

        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test-gadget-vector");

        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            ote_params.num_base_ot(),
            TOTAL_SIGNERS,
            self.all_party_set.clone(),
        );

        Phase2::init(
            &mut rng,
            self.id,
            masked_signing_key_share,
            masked_r,
            base_ot_outputs[self.id as usize - 1].clone(),
            others.clone(),
            ote_params,
            &gadget_vector,
        )
        .unwrap()
    }
}
