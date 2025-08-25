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

const BASE_OT_KEY_SIZE: u16 = 128;
const KAPPA: u16 = 256;
const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
const SIG_BATCH_SIZE: u32 = 1;

pub struct Signer {
    pub id: u16,
    pub sk_share: Fr,
}

impl Signer {
    pub fn new(id: u16, sk_share: Fr) -> Self {
        Self { id, sk_share }
    }

    pub fn do_round1<R: RngCore>(
        &self,
        rng: &mut R,
        batch_size: u32,
        id: u16,
        others: BTreeSet<u16>,
        protocol_id: Vec<u8>,
    ) -> (Phase1<Fr, 256>, Commitments, BTreeMap<ParticipantId, Commitments>) {
        Phase1::<Fr, 256>::init_for_bbs(
            rng,
            batch_size,
            id,
            others.clone(),
            protocol_id
        ).unwrap()
    }

    pub fn do_round2<R: RngCore>(
        &self,
        rng: &mut R,
        id: u16,
        masked_signing_key_share: Vec<Fr>,
        masked_r: Vec<Fr>,
        base_ot: BaseOTOutput,
        others: BTreeSet<u16>,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> (Phase2<Fr, 256, 80>, BTreeMap<ParticipantId, Message1<Fr>>) {
        Phase2::init(
            rng,
            id,
            masked_signing_key_share.clone(),
            masked_r.clone(),
            base_ot,
            others.clone(),
            ote_params,
            gadget_vector,
        ).unwrap()
    }
}
