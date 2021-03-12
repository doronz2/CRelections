use curv::BigInt;
use elgamal::{rfc7919_groups::SupportedGroups,ElGamalPP,
              ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
              ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::arithmetic::traits::{Samplable, Modulo};
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use serde::{Deserialize, Serialize};
use vice_city::utlities::dlog_proof::{ProveDLog, Witness, DLogProof, Statement};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyProof {
    pk: ElGamalPublicKey,
    proof: DLogProof,
    party_index: i32
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenCommitment {
    comm: BigInt,
    party_index: i32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct keyGenPKShare{
    share_pk: BigInt,
    party_index: i32
}
/*
impl KeyPair{
    pub fn generate_key_pair(party_index:i32) -> ElGamalKeyPair{
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        key_pair
    }
}
*/

impl KeyGenCommitment{
    pub fn generate_commitment(pp: ElGamalPP, party_index:i32) -> (Self, ElGamalKeyPair){
        let x = BigInt::sample_below(&pp.q);
        let y = BigInt::mod_pow(&pp.g, &x, &pp.p);
        let comm = hash_sha256::HSha256::create_hash(&[&y]);
        (Self{comm, party_index}, ElGamalKeyPair{sk: ElGamalPrivateKey{pp: pp.clone(),x}, pk:ElGamalPublicKey{pp: pp.clone(), h:y}})
    }
}

impl KeyProof{
    pub fn generate_proof_for_key(sk: ElGamalPrivateKey, pk: ElGamalPublicKey, pp: ElGamalPP, party_index:i32)-> KeyProof{
        let w = Witness{x: sk.x};
        let dLogProof = DLogProof::prove(&w, &pp);
        KeyProof{pk, proof: dLogProof, party_index}
    }

    pub fn verify_and_construct_global_keys(comm_list: Vec<KeyGenCommitment>, proof_list: Vec<KeyProof>) -> bool{

        comm_list.iter().
            zip(proof_list.iter())
            .any( |(e_comm,e_proof)|
                {
                    let y= e_proof.clone().pk;
                    e_comm.party_index == e_proof.party_index //verify the indices are compatible
                        && e_comm.comm == hash_sha256::HSha256::create_hash(&[&y.h]) //verify commitment
                        && e_proof.proof.verify(&Statement{ h: y.h}, &e_proof.pk.pp).is_ok() //verify proofs
                })
    }
}

