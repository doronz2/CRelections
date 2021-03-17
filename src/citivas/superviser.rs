use elgamal::{ElGamal,rfc7919_groups::SupportedGroups,ElGamalPP,
ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::BigInt;

use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use std::convert::TryInto;
use vice_city::ProofError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::Error;
use crate::citivas::encryption_schemes::{reencrypt, encoding_quadratic_residue, ElGamalCipherTextAndPK};
use crate::citivas::tellers::*;


const O_STRING: &str ="5493847203023738409235948752";
const NUMBER_OF_TALLIES:usize = 3;
pub const NUMBER_OF_VOTERS:usize = 3;
pub const NUMBER_OF_CANDIDATES: usize = 3;
const OUT: bool = true;
const IN: bool = false;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SystemParameters {
    pub pp: ElGamalPP,
    pub num_of_tellers: usize,
    pub num_of_voters: usize,
    pub O: BigInt, //a set (of size O) is specified in Citivas where random parameter are selected from
    pub nonce_for_candidate_encryption: BigInt, //the reason for publishing this is that it is needed for computing the witness in votePf. //The reason not to hide the candidate under the encryption is that the encryption is done (AFAIK) for creating a data format that allows to prove  reenc 1 out of L
    pub encrypted_candidate_list: Vec<ElGamalCiphertext>,
    pub KTT: ElGamalPublicKey //tellers joint public key
  }



impl SystemParameters {
    //implement
    pub fn receive_KTT_from_tallies(pp: ElGamalPP)-> ElGamalPublicKey {
        ElGamalPublicKey {
            pp,
            h: BigInt::one()
        }
    }

    pub fn create_sp(&self) -> Self{
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let O = BigInt::from_str(O_STRING).unwrap();
        let nonce_for_candidate_encryption = BigInt::sample_below(&pp.q);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let KTT = SystemParameters::receive_KTT_from_tallies(pp.clone());
        let encrypted_candidate_list = (0..NUMBER_OF_CANDIDATES).
            map(|candidate| ElGamal::encrypt_from_predefined_randomness(
                &BigInt::from(candidate as i32), &key_pair.pk, &nonce_for_candidate_encryption
            ).unwrap())
            .collect();
        SystemParameters{
            pp,
            num_of_tellers: NUMBER_OF_TALLIES,
            num_of_voters: NUMBER_OF_VOTERS,
            O: BigInt::from_str(O_STRING).unwrap(),
            nonce_for_candidate_encryption,
            encrypted_candidate_list,
            KTT
        }
    }

}


/*
fn create_tellers()-> Vec<Teller>{
    let sp = SystemParameters.create_sp();
    (0..sp.num_of_tellers).map(|i| Teller::createTeller(sp.clone())).collect()
}
*/
