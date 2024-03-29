use crate::citivas::encryption_schemes::encoding_quadratic_residue;
use curv::BigInt;
use elgamal::{ElGamal, ElGamalCiphertext, ElGamalPP, ElGamalPublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
#[allow(dead_code)]
const O_STRING: &str = "5493847203023738409235948752"; //used for sampling values for mixing
const NUMBER_OF_TALLIES: usize = 3;
pub const NUMBER_OF_VOTERS: usize = 3;
pub const NUMBER_OF_CANDIDATES: usize = 3;
const OUT: bool = true;
const IN: bool = false;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SystemParameters {
    pub pp: ElGamalPP,
    pub num_of_tellers: usize,
    pub num_of_voters: usize,
    pub num_of_candidates: usize,
    pub o: BigInt, //a set (of size O) is specified in Citivas where random parameter are selected from
    pub nonce_for_candidate_encryption: BigInt, //the reason for publishing this is that it is needed for computing the witness in votepf. //The reason not to hide the candidate under the encryption is that the encryption is done (AFAIK) for creating a data format that allows to prove  reenc 1 out of L
    pub encrypted_candidate_list: Option<Vec<ElGamalCiphertext>>,
    pub eid: i32, //identifier of election
}

impl SystemParameters {
    //implement

    pub fn create_supervisor(pp: &ElGamalPP) -> Self {
        let nonce_for_candidate_encryption = BigInt::from(3); // you can replace the "3" with any value
        SystemParameters {
            pp: pp.clone(),
            num_of_tellers: NUMBER_OF_TALLIES,
            num_of_voters: NUMBER_OF_VOTERS,
            num_of_candidates: NUMBER_OF_CANDIDATES,
            o: BigInt::from_str(O_STRING).unwrap(),
            nonce_for_candidate_encryption,
            eid: 0,
            encrypted_candidate_list: None,
        }
    }

    pub fn set_encrypted_list(&mut self, shared_pk: ElGamalPublicKey) {
        //encode the msg before encryption (qr encoding)
        let encoded_candidates: Vec<BigInt> = (0..NUMBER_OF_CANDIDATES)
            .map(|candidate| encoding_quadratic_residue(BigInt::from(candidate as i32), &self.pp))
            .collect();
        let encrypted_candidate_list = (0..NUMBER_OF_CANDIDATES)
            .map(|candidate_index| {
                ElGamal::encrypt_from_predefined_randomness(
                    &encoded_candidates.get(candidate_index).unwrap(),
                    &shared_pk,
                    &self.nonce_for_candidate_encryption,
                )
                .unwrap()
            })
            .collect();
        self.encrypted_candidate_list = Some(encrypted_candidate_list);
    }
}
