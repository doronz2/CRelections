use curv::BigInt;
use elgamal::{rfc7919_groups::SupportedGroups,ElGamalPP,
              ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
              ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::arithmetic::traits::{Samplable, Modulo};
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use serde::{Deserialize, Serialize};
use vice_city::utlities::dlog_proof::{ProveDLog, Witness, DLogProof, Statement};
use crate::citivas::supervisor::SystemParameters;
use vice_city::utlities::ddh_proof::{DDHStatement, DDHProof, DDHWitness, NISigmaProof};


pub struct Party{
    private_share: BigInt,
    public_share: BigInt,
    pp: ElGamalPP,
    party_index: i32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyProof {
    pk: ElGamalPublicKey,
    proof: DLogProof,
    party_index: i32
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareAndCommitment{
    comm: BigInt,
    key_pair: ElGamalKeyPair,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentKeyGen{
    comm: BigInt,
    party_index: i32,
}



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct keyGenPKShare{
    share: BigInt,
    party_index: i32
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistDecryptEGMsg{
    share: BigInt,
    proof: DDHProof,
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

impl Party {

    //------ Distributed El Gamal Key Generation --------

    pub fn generate_share(pp: &ElGamalPP, party_index: i32) -> Party{
        let private_share = BigInt::sample_below(&pp.q);
        let public_share = BigInt::mod_pow(&pp.g, &private_share, &pp.p);
        Self{
            private_share, public_share, pp: pp.clone(), party_index
        }

    }

    pub fn publish_commitment_key_gen(&self) -> CommitmentKeyGen {

        let comm = hash_sha256::HSha256::create_hash(&[&self.public_share]);
        CommitmentKeyGen{comm, party_index: self.party_index}
        }


    pub fn publish_proof_for_key_share(&self) -> KeyProof {
        let w = Witness { x: self.private_share.clone() };
        let dLogProof = DLogProof::prove(&w, &self.pp);
        KeyProof {
            pk: ElGamalPublicKey{ pp: self.pp.clone(), h: self.public_share.clone()},
            proof: dLogProof,
            party_index: self.party_index }
    }


//The following function verifies the DLOG proofs of the public key shares and their commitments
    pub fn create_valid_shares_list(&self, comm_list: Vec<CommitmentKeyGen>, proof_list: Vec<KeyProof>) -> Vec<ElGamalPublicKey>{
        if comm_list.len()!= proof_list.len() {
            panic!("Mismatch size between commitment list and proof list");

        }
        for i in 0..comm_list.len(){
            if comm_list[i].party_index != proof_list[i].party_index {
                panic!("Party {} does not match commitment and proof",i);
            } //verify that both lists have the same order
        }
        let valid_shares = comm_list.iter().
            zip(proof_list.iter())
            .filter( |(share_comm,share_proof)|
                {
                   // assert_eq!(e_comm.party_index, e_proof.party_index); //verify that both lists have the same order

                    let public_key_share= &share_proof.pk;
                        share_comm.comm == hash_sha256::HSha256::create_hash(&[&public_key_share.h]) //verify commitment
                        && share_proof.proof.verify(&Statement{ h: public_key_share.h.clone()}, &self.pp).is_ok() //verify proofs
                })
            .map(|(_,share_proof)| share_proof.pk.clone())
            .collect();
        valid_shares
    }

    pub fn construct_public_key_from_valid_shares(&self, pk_list: Vec<ElGamalPublicKey>)-> ElGamalPublicKey{
        let global_pk =
            pk_list.iter().fold(BigInt::one(), | prod, key_share | prod * &key_share.h)
                .mod_floor(&self.pp.p);
        ElGamalPublicKey { pp: self.pp.clone(), h: global_pk}
    }

    pub fn construct_shared_public_key(&self, comm_list: Vec<CommitmentKeyGen>, proof_list: Vec<KeyProof>)-> ElGamalPublicKey{
        let valid_shares_list = self.create_valid_shares_list(
            comm_list, proof_list);
       self.construct_public_key_from_valid_shares(valid_shares_list)
    }

    //------ Distributed El Gamal Decryption --------
    pub fn publish_shares_and_proofs_for_decryption(&self, cipher: ElGamalCiphertext)-> DistDecryptEGMsg{
        let a_i = BigInt::mod_pow(&cipher.c1, &self.private_share, &self.pp.p);
        let statement = DDHStatement{
            pp: self.pp.clone(),
            g1: self.pp.g.clone(),
            h1: cipher.c1.clone(),
            g2: self.public_share.clone(),
            h2: a_i.clone()
        };
        let witness = DDHWitness{ x: self.private_share.clone() };
        let proof = DDHProof::prove(&witness, &statement);
        DistDecryptEGMsg{
            share: a_i,
            proof,
            party_index: self.party_index
        }
    }

    pub fn dist_EG_decrypt(self, cipher: ElGamalCiphertext, shares_and_proofs: Vec<DistDecryptEGMsg>)-> BigInt{
        for msg in shares_and_proofs.clone(){
            let statement = DDHStatement{
                pp: self.pp.clone(),
                g1: self.pp.g.clone(),
                h1: cipher.c1.clone(),
                g2: self.public_share.clone(),
                h2: msg.share.clone()
            };
            let is_valid = msg.proof.verify(&statement);
            if is_valid.is_err(){
                panic!("share {} or proof of share {} for decryption is invalid", msg.party_index, msg.party_index);
            }
        }
        let a = shares_and_proofs.iter()
            .map(|msg| msg.share.clone())
            .fold( BigInt::one(), |prod, share| prod * share).mod_floor(&self.pp.p);
        let decrypted_text = cipher.c2 * a.invert(&self.pp.p).unwrap();
        decrypted_text
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use crate::ElGamal;

    #[test]
    pub fn test_generate_key_from_shares() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let party_1 = Party::generate_share(&pp, 1);
        let party_2 = Party::generate_share(&pp, 2);
        let party_3 = Party::generate_share(&pp, 3);

        let mut parties = Vec::new();
        parties.push(&party_1);
        parties.push(&party_2);
        parties.push(&party_3);

        let commitments = parties.clone()
            .iter()
            .map(|&party| party.publish_commitment_key_gen())
            .collect();

        let shares_and_proofs = parties.clone()
            .iter()
            .map(|&party| party.clone().publish_proof_for_key_share())
            .collect();
        let shared_public_key =
            party_1.construct_shared_public_key(commitments, shares_and_proofs);
        let shared_private_key = ElGamalPrivateKey {
            x: (party_1.private_share + party_2.private_share + party_3.private_share).mod_floor(&pp.p),
            pp
        };
        let msg = BigInt::from(1234);
        let encrypted_msg = ElGamal::encrypt(&msg, &shared_public_key).unwrap();
        let decrypted_msg = ElGamal::decrypt(&encrypted_msg, &shared_private_key).unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    pub fn test_distributed_EG_decryption() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let party_1 = Party::generate_share(&pp, 1);
        let party_2 = Party::generate_share(&pp, 2);
        let party_3 = Party::generate_share(&pp, 3);

        let mut parties = Vec::new();
        parties.push(&party_1);
        parties.push(&party_2);
        parties.push(&party_3);

        let commitments = parties
            .iter()
            .map(|party| party.publish_commitment_key_gen())
            .collect();

        let shares_and_proofs = parties
            .iter()
            .map(|party| party.publish_proof_for_key_share())
            .collect();
        let shared_public_key =
            party_1.construct_shared_public_key(commitments, shares_and_proofs);



        let msg = BigInt::from(1234);
        let encrypted_msg = ElGamal::encrypt(&msg, &shared_public_key).unwrap();

        let proofs = parties
            .iter()
            .map(|party| party.publish_shares_and_proofs_for_decryption(encrypted_msg.clone()))
            .collect();
        let plain_text_msg = party_1.dist_EG_decrypt(encrypted_msg, proofs);
        assert_eq!(msg, plain_text_msg);
    }
}


