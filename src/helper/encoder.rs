use crate::constant::*;
use std::{collections::BTreeMap, io::Cursor};

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{engine::general_purpose, Engine as _};
use bbs_plus::threshold::{
    multiplication_phase::{Phase2, Phase2Output},
    randomness_generation_phase::Phase1,
    threshold_bbs::Phase1Output,
    ParticipantId,
};
use oblivious_transfer_protocols::{
    cointoss::Commitments,
    ot_based_multiplication::{
        batch_mul_multi_party::{Message1, Message2},
        dkls19_batch_mul_2p::GadgetVector,
    },
};

pub struct Encoder;

impl Encoder {
    pub fn encode_sk_share(sk_share: &Fr) -> String {
        let bytes: Vec<u8> = (*sk_share).into_bigint().to_bytes_be();
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn decode_sk_share(sk_share_b64: &str) -> Result<Fr, String> {
        let bytes = general_purpose::STANDARD
            .decode(sk_share_b64)
            .map_err(|e| format!("Invalid base64: {}", e))?;

        // `Fr` is 32 bytes (256 bits). Left-pad if shorter.
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);

        Ok(Fr::from_be_bytes_mod_order(&padded))
    }

    pub fn encode_phase1(phase1: &Phase1<Fr, 256>) -> String {
        let mut bytes = Vec::new();
        phase1.serialize_compressed(&mut bytes).unwrap();
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn decode_phase1(phase1_b64: &str) -> Result<Phase1<Fr, 256>, String> {
        let bytes = general_purpose::STANDARD
            .decode(phase1_b64)
            .expect("Base64 decode error");
        Phase1::<Fr, 256>::deserialize_compressed(&mut Cursor::new(bytes))
            .map_err(|e| format!("Failed to deserialize Phase1: {}", e))
    }

    pub fn encode_phase1_output(phase1_output: &Phase1Output<Fr>) -> String {
        let mut bytes = Vec::new();
        phase1_output.serialize_compressed(&mut bytes).unwrap();
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn decode_phase1_output(phase1_output_b64: &str) -> Result<Phase1Output<Fr>, String> {
        let bytes = general_purpose::STANDARD
            .decode(phase1_output_b64)
            .expect("Base64 decode error");
        Phase1Output::<Fr>::deserialize_compressed(&mut Cursor::new(bytes))
            .map_err(|e| format!("Failed to deserialize Phase1Output: {}", e))
    }

    pub fn encode_vec_fr(vec: &Vec<Fr>) -> String {
        let mut bytes = Vec::new();
        vec.serialize_compressed(&mut bytes).unwrap();
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn decode_vec_fr(vec_b64: &str) -> Result<Vec<Fr>, String> {
        let bytes = general_purpose::STANDARD
            .decode(vec_b64)
            .expect("Base64 decode error");
        Vec::<Fr>::deserialize_compressed(&mut Cursor::new(bytes))
            .map_err(|e| format!("Failed to deserialize Vec<Fr>: {}", e))
    }

    pub fn encode_phase2(phase2: &Phase2<Fr, 256, 80>) -> String {
        let mut bytes = Vec::new();
        phase2.serialize_compressed(&mut bytes).unwrap();
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn decode_phase2(phase2_b64: &str) -> Result<Phase2<Fr, 256, 80>, String> {
        let bytes = general_purpose::STANDARD
            .decode(phase2_b64)
            .expect("Base64 decode error");
        Phase2::<Fr, 256, 80>::deserialize_compressed(&mut Cursor::new(bytes))
            .map_err(|e| format!("Failed to deserialize Phase2: {}", e))
    }

    /// Encode a BTreeMap<ParticipantId, Message1<F>> -> JSON string
    pub fn encode_map(
        map: &BTreeMap<ParticipantId, Message1<Fr>>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>
    where
        Message1<Fr>: CanonicalSerialize,
    {
        // intermediate map: ParticipantId -> base64 string
        let mut tmp: BTreeMap<ParticipantId, String> = BTreeMap::new();

        for (pid, msg) in map {
            let mut bytes = Vec::new();
            // serialize compressed into bytes
            msg.serialize_compressed(&mut bytes)?;
            // base64 encode
            let b64 = general_purpose::STANDARD.encode(&bytes);
            tmp.insert(*pid, b64);
        }

        // encode the intermediate map as JSON for transport
        let json = serde_json::to_string(&tmp)?;
        Ok(json)
    }

    /// Decode JSON string -> BTreeMap<ParticipantId, Message1<F>>
    pub fn decode_map(
        encoded: &str,
    ) -> Result<BTreeMap<ParticipantId, Message1<Fr>>, Box<dyn std::error::Error + Send + Sync>>
    where
        Message1<Fr>: CanonicalDeserialize,
    {
        // parse JSON -> map of base64 strings
        let tmp: BTreeMap<ParticipantId, String> = serde_json::from_str(encoded)?;

        let mut map: BTreeMap<ParticipantId, Message1<Fr>> = BTreeMap::new();

        for (pid, b64) in tmp {
            let bytes = general_purpose::STANDARD.decode(&b64)?;
            let msg = Message1::<Fr>::deserialize_compressed(&mut Cursor::new(bytes))?;
            map.insert(pid, msg);
        }

        Ok(map)
    }

    pub fn encode_map_commitments(
        map: &BTreeMap<ParticipantId, Commitments>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut tmp: BTreeMap<ParticipantId, String> = BTreeMap::new();

        for (pid, comm) in map {
            let mut bytes = Vec::new();
            comm.serialize_compressed(&mut bytes)?;
            let b64 = general_purpose::STANDARD.encode(&bytes);
            tmp.insert(*pid, b64);
        }

        let json = serde_json::to_string(&tmp)?;
        Ok(json)
    }

    pub fn decode_map_commitments(
        encoded: &str,
    ) -> Result<BTreeMap<ParticipantId, Commitments>, Box<dyn std::error::Error + Send + Sync>>
    {
        let tmp: BTreeMap<ParticipantId, String> = serde_json::from_str(encoded)?;

        let mut map: BTreeMap<ParticipantId, Commitments> = BTreeMap::new();

        for (pid, b64) in tmp {
            let bytes = general_purpose::STANDARD.decode(&b64)?;
            let comm = Commitments::deserialize_compressed(&mut Cursor::new(bytes))?;
            map.insert(pid, comm);
        }

        Ok(map)
    }

    pub fn encode_commitments(
        comm: &Commitments,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut bytes = Vec::new();
        comm.serialize_compressed(&mut bytes)?;
        let b64 = general_purpose::STANDARD.encode(&bytes);
        Ok(b64)
    }

    pub fn decode_commitments(
        encoded: &str,
    ) -> Result<Commitments, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = general_purpose::STANDARD.decode(encoded)?;
        let comm = Commitments::deserialize_compressed(&mut Cursor::new(bytes))?;
        Ok(comm)
    }

    pub fn encode_msg2(
        msg: &Message2<Fr>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut bytes = Vec::new();
        msg.serialize_compressed(&mut bytes)?;
        let b64 = general_purpose::STANDARD.encode(&bytes);
        Ok(b64)
    }

    pub fn decode_msg2(
        encoded: &str,
    ) -> Result<Message2<Fr>, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = general_purpose::STANDARD.decode(encoded)?;
        let msg = Message2::<Fr>::deserialize_compressed(&mut Cursor::new(bytes))?;
        Ok(msg)
    }

    pub fn encode_phase2output(
        output: &Phase2Output<Fr>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut bytes = Vec::new();
        output.serialize_compressed(&mut bytes)?;
        let b64 = general_purpose::STANDARD.encode(&bytes);
        Ok(b64)
    }

    pub fn decode_phase2output(
        encoded: &str,
    ) -> Result<Phase2Output<Fr>, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = general_purpose::STANDARD.decode(encoded)?;
        let output = Phase2Output::<Fr>::deserialize_compressed(&mut Cursor::new(bytes))?;
        Ok(output)
    }

    pub fn encode_gadget_vector(
        vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut bytes = Vec::new();
        vector.serialize_compressed(&mut bytes)?;
        let b64 = general_purpose::STANDARD.encode(&bytes);
        Ok(b64)
    }
}
