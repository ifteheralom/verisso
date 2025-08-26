use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use blake2::Blake2b512;
use bbs_plus::setup::{PublicKeyG2, SignatureParams23G1, SecretKey};
use rand::prelude::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_std::{rand::{rngs::StdRng, SeedableRng}, Zero};
use bbs_plus::signature_23::Signature23G1;
use bbs_plus::threshold::multiplication_phase::Phase2;
use bbs_plus::threshold::randomness_generation_phase::Phase1;
use bbs_plus::threshold::threshold_bbs::{BBSSignatureShare, Phase1Output};
use oblivious_transfer_protocols::cointoss::Commitments;
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
};
use oblivious_transfer_protocols::ot_based_multiplication::base_ot_multi_party_pairwise::BaseOTOutput;
use oblivious_transfer_protocols::ot_based_multiplication::batch_mul_multi_party::Message1;
use oblivious_transfer_protocols::ParticipantId;
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use crate::ot::do_pairwise_base_ot;
use crate::constants::{*};
use crate::tbbs_sign::trusted_party_keygen;

pub struct Signer {
    pub id: u16,
    pub sk_share: Fr,
    pub rng: StdRng,
    pub all_party_set: BTreeSet<u16>,
    pub threshold_party_set: BTreeSet<u16>,
    pub protocol_id: Vec<u8>,
}

impl Signer {
    pub fn new(id: u16, sk_share: Fr) -> Self {
        Signer {
            rng: StdRng::seed_from_u64(0u64),
            all_party_set: (1..=TOTAL_SIGNERS).into_iter().collect::<BTreeSet<_>>(),
            threshold_party_set: (1..=THRESHOLD_SIGNERS).into_iter().collect::<BTreeSet<_>>(),
            protocol_id: b"test".to_vec(),
            id: id,
            sk_share: sk_share
        }
    }

    pub fn do_round1 (
        &self,
        id: u16
    ) -> (Phase1<Fr, 256>, Commitments, BTreeMap<ParticipantId, Commitments>) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut others = self.threshold_party_set.clone();
        others.remove(&id);

        Phase1::<Fr, 256>::init_for_bbs(
            &mut rng, SIG_BATCH_SIZE, id, others.clone(), self.protocol_id.clone()
        ).unwrap()
    }

    pub fn finish_round1 (
        &self,
        round1: Phase1<Fr, 256>
    ) -> (Phase1Output<Fr>) {
        round1.finish_for_bbs::<Blake2b512>(&self.sk_share)
            .unwrap()
    }

    pub fn do_round2 (
        &self,
        id: u16,
        masked_signing_key_share: Vec<Fr>,
        masked_r: Vec<Fr>,
    ) -> (Phase2<Fr, 256, 80>, BTreeMap<ParticipantId, Message1<Fr>>) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut others = self.threshold_party_set.clone();
        others.remove(&id);

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
            &mut rng, id,
            masked_signing_key_share,
            masked_r,
            base_ot_outputs[id as usize - 1].clone(),
            others.clone(),
            ote_params,
            &gadget_vector,
        ).unwrap()
    }
}
