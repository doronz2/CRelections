use elgamal::{ElGamal,ElGamalPP,
ElGamalKeyPair,ElGamalCiphertext,
ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::BigInt;
use serde::{Deserialize, Serialize};
use std::str::FromStr;


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
    pub num_of_candidates: usize,
    pub O: BigInt, //a set (of size O) is specified in Citivas where random parameter are selected from
    pub nonce_for_candidate_encryption: BigInt, //the reason for publishing this is that it is needed for computing the witness in votePf. //The reason not to hide the candidate under the encryption is that the encryption is done (AFAIK) for creating a data format that allows to prove  reenc 1 out of L
    pub encrypted_candidate_list: Vec<ElGamalCiphertext>,
    pub KTT: ElGamalPublicKey, //tellers joint public key
    pub eid: i32 //identifier of election
  }



impl SystemParameters {
    //implement
    pub fn receive_KTT_from_tallies(pp: ElGamalPP)-> ElGamalPublicKey {
        ElGamalPublicKey {
            pp,
            h: BigInt::from(4)
        }
    }

    pub fn create_supervisor(pp: &ElGamalPP) -> Self{
        let _O = BigInt::from_str(O_STRING).unwrap();
     //   let nonce_for_candidate_encryption = BigInt::sample_below(&pp.q);
        let nonce_for_candidate_encryption = BigInt::from(3);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let KTT = SystemParameters::receive_KTT_from_tallies(pp.clone());
        let encrypted_candidate_list = (1..NUMBER_OF_CANDIDATES + 1).
            map(|candidate| ElGamal::encrypt_from_predefined_randomness(
                &BigInt::from(candidate as i32), &key_pair.pk, &nonce_for_candidate_encryption
            ).unwrap())
            .collect();
        SystemParameters{
            pp: pp.clone(),
            num_of_tellers: NUMBER_OF_TALLIES,
            num_of_voters: NUMBER_OF_VOTERS,
            num_of_candidates: NUMBER_OF_CANDIDATES,
            O: BigInt::from_str(O_STRING).unwrap(),
            nonce_for_candidate_encryption,
            encrypted_candidate_list,
            KTT,
            eid: 0
        }
    }

    pub fn create_supervisor_toy(pp: &ElGamalPP) -> Self{
        let _O = BigInt::from_str(O_STRING).unwrap();
        //let nonce_for_candidate_encryption = BigInt::sample_below(&pp.q);
        let nonce_for_candidate_encryption = BigInt::one();
        let KTT = SystemParameters::receive_KTT_from_tallies(pp.clone());
        let encrypted_candidate_list = (1..NUMBER_OF_CANDIDATES + 1).
            map(|candidate| ElGamal::encrypt_from_predefined_randomness(
                &BigInt::from(candidate as i32), &KTT, &BigInt::one()
            ).unwrap())
            .collect();
        SystemParameters{
            pp: pp.clone(),
            num_of_tellers: NUMBER_OF_TALLIES,
            num_of_voters: NUMBER_OF_VOTERS,
            num_of_candidates: NUMBER_OF_CANDIDATES,
            O: BigInt::from_str(O_STRING).unwrap(),
            nonce_for_candidate_encryption,
            encrypted_candidate_list,
            KTT,
            eid: 0
        }
    }

}


/*
fn create_tellers()-> Vec<Teller>{
    let sp = SystemParameters.create_sp();
    (0..sp.num_of_tellers).map(|i| Teller::createTeller(sp.clone())).collect()
}
*/