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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DistElGamal{
    share_key_pair: ElGamalKeyPair,// a share of key pair, i.e., a share of private and a share of public key
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
    share_key_pair: ElGamalKeyPair,
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
    pub(crate) share: BigInt,
    proof: DDHProof,
    party_index: i32
}


/*
impl KeyPair{
    pub fn generate_share_key_pair(party_index:i32) -> ElGamalKeyPair{
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let share_key_pair = ElGamalKeyPair::generate(&pp);
        share_key_pair
    }
}
*/

impl DistElGamal {

    //------ Distributed El Gamal Key Generation --------

    pub fn generate_share(pp: &ElGamalPP, party_index: i32) -> DistElGamal{
          Self{
             share_key_pair: ElGamalKeyPair::generate(&pp),
            party_index
        }

    }

    pub fn get_public_share(self) -> BigInt{
        self.share_key_pair.pk.h
    }

    pub  fn get_private_share(self) -> BigInt{
        self.share_key_pair.sk.x
    }

    pub fn publish_commitment_key_gen(&self) -> CommitmentKeyGen {

        let comm = hash_sha256::HSha256::create_hash(&[&self.share_key_pair.pk.h]);
        CommitmentKeyGen{comm, party_index: self.party_index}
        }


    pub fn publish_proof_for_key_share(&self) -> KeyProof {
        let w = Witness { x: self.share_key_pair.sk.x.clone() };
        let dLogProof = DLogProof::prove(&w, &self.share_key_pair.pk.pp);
        KeyProof {
            pk: ElGamalPublicKey{ pp: self.share_key_pair.pk.pp.clone(), h: self.share_key_pair.pk.h.clone()},
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
                panic!("DistElGamal {} does not match commitment and proof",i);
            } //verify that both lists have the same order
        }
        let valid_shares: Vec<ElGamalPublicKey> = comm_list.iter().
            zip(proof_list.iter())
            .filter( |(share_comm,share_proof)|
                {
                   // assert_eq!(e_comm.party_index, e_proof.party_index); //verify that both lists have the same order

                    let public_key_share= &share_proof.pk;
                        share_comm.comm == hash_sha256::HSha256::create_hash(&[&public_key_share.h]) //verify commitment
                        && share_proof.proof.verify(&Statement{ h: public_key_share.h.clone()}, &self.share_key_pair.pk.pp).is_ok() //verify proofs
                })
            .map(|(_,share_proof)| share_proof.pk.clone())
            .collect();
       if valid_shares.len() == 0{
            panic!("All share were invalidated")
        }
        valid_shares
    }

    pub fn construct_public_key_from_valid_shares(&self, pk_list: &Vec<ElGamalPublicKey>)-> ElGamalPublicKey{
        let global_pk =
            pk_list.iter().fold(BigInt::one(), | prod, key_share | prod * &key_share.h)
                .mod_floor(&self.share_key_pair.pk.pp.p);
        ElGamalPublicKey { pp: self.share_key_pair.pk.pp.clone(), h: global_pk}
    }

    pub fn construct_shared_public_key(&self, comm_list: Vec<CommitmentKeyGen>, proof_list: Vec<KeyProof>)-> ElGamalPublicKey{
        let valid_shares_list = &self.create_valid_shares_list(
            comm_list, proof_list);
       self.construct_public_key_from_valid_shares(valid_shares_list)
    }

    //------ Distributed El Gamal Decryption --------
    pub fn publish_shares_and_proofs_for_decryption(&self, cipher: &ElGamalCiphertext)-> DistDecryptEGMsg{
        let a_i = BigInt::mod_pow(&cipher.c1, &self.share_key_pair.sk.x, &self.share_key_pair.pk.pp.p);
        let statement = DDHStatement{
            pp: self.share_key_pair.pk.pp.clone(),
            g1: self.share_key_pair.pk.pp.g.clone(),
            h1: self.share_key_pair.pk.h.clone(),
            g2: cipher.c1.clone(),
            h2: a_i.clone()
        };
        let witness = DDHWitness{ x: self.share_key_pair.sk.x.clone() };
        let proof = DDHProof::prove(&witness, &statement);
        DistDecryptEGMsg{
            share: a_i,
            proof,
            party_index: self.party_index
        }
    }

    pub fn verify_proof_for_decryption(&self, cipher: &ElGamalCiphertext, share_and_proof: &DistDecryptEGMsg, party_index: i32)-> bool{
            let statement = DDHStatement{
                pp: self.share_key_pair.pk.pp.clone(),
                g1: self.share_key_pair.pk.pp.g.clone(),
                h1: self.share_key_pair.pk.h.clone(),
                g2: cipher.c1.clone(),
                h2: share_and_proof.share.clone()
            };
            let is_valid = share_and_proof.proof.verify(&statement);
            if is_valid.is_err(){
                panic!("share/proof of share {} for decryption is invalid", party_index);
            }
            else {true}
    }

    pub fn combine_shares_and_decrypt( cipher: ElGamalCiphertext, shares: Vec<BigInt>, pp: &ElGamalPP)-> BigInt{
        let A = shares.iter()
            .fold( BigInt::one(), |prod, share| prod * share)
            .mod_floor(&pp.p);
        let decrypted_text = (cipher.clone().c2 * A.invert(&pp.p).unwrap()).mod_floor(&pp.p);
        decrypted_text

    }

}


#[cfg(test)]
mod test {
    use super::*;
    use crate::ElGamal;
    use crate::citivas::encryption_schemes::encoding_quadratic_residue;

    #[test]
    pub fn test_generate_key_from_shares() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let party_1 = DistElGamal::generate_share(&pp, 1);
        let party_2 = DistElGamal::generate_share(&pp, 2);
        let party_3 = DistElGamal::generate_share(&pp, 3);

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
            x: (party_1.share_key_pair.sk.x + party_2.share_key_pair.sk.x + party_3.share_key_pair.sk.x).mod_floor(&pp.q),
            pp: pp.clone()
        };
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let r = BigInt::sample_below(&pp.q);
        let encrypted_msg = elgamal::ElGamal::encrypt_from_predefined_randomness(
            &BigInt::from(encoded_msg.clone()),&shared_public_key, &r).unwrap();


        println!("msg1: {:?}", encoded_msg);
        let encrypted_msg = ElGamal::encrypt(&encoded_msg, &shared_public_key).unwrap();
        let decrypted_msg = ElGamal::decrypt(&encrypted_msg, &shared_private_key).unwrap();
        assert_eq!(encoded_msg, decrypted_msg);
    }

    #[test]
    pub fn test_distributed_EG_decryption() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let party_1 = DistElGamal::generate_share(&pp, 1);
        let party_2 = DistElGamal::generate_share(&pp, 2);
        let party_3 = DistElGamal::generate_share(&pp, 3);

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



        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        println!("msg2: {:?}", encoded_msg);
        let r = BigInt::sample_below(&pp.q);

        let encrypted_msg = elgamal::ElGamal::encrypt_from_predefined_randomness(
            &BigInt::from(encoded_msg.clone()),&shared_public_key, &r).unwrap();

        let shares_and_proofs: Vec<DistDecryptEGMsg> = parties
            .iter()
            .map(|party| party.publish_shares_and_proofs_for_decryption(&encrypted_msg))
            .collect();
        let valid_shares_for_decryption: Vec<BigInt> = parties
            .iter()
            .zip(shares_and_proofs)
            .filter(|(party, share_and_proof)| party.verify_proof_for_decryption(&encrypted_msg, share_and_proof, party.party_index) )
            .map(|(_, shares_and_proof)| shares_and_proof.share)
            .collect();
        if valid_shares_for_decryption.len() == 0{
            panic!("no share has been validated");
        }
        println!("number of valid shares = {:?}", valid_shares_for_decryption.len());
        let plain_text_msg = DistElGamal::combine_shares_and_decrypt( encrypted_msg, valid_shares_for_decryption, &pp);
        assert_eq!(encoded_msg, plain_text_msg);
    }
}


