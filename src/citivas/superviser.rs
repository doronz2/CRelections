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
use crate::citivas::mix_network::*;
use crate::citivas::encryption_schemes::{ElGamalCipherTextAndPK,reencrypt, encoding_quadratic_residue};
use crate::citivas::tellers::*;


const O_STRING: &str ="5493847203023738409235948752";
const NUMBER_OF_TALLIES:usize = 5;
const NUMBER_OF_VOTERS:usize = 8;
const OUT: bool = true;
const IN: bool = false;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PP{
    pub pp: ElGamalPP,
    pub num_of_tellers: usize,
    pub num_of_voters: usize,
    pub O: BigInt
  }

impl PP{
    pub fn create_pp()-> Self{
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let O = BigInt::from_str(O_STIRNG).unwrap();
        PP{
            pp,
            num_of_tellers: NUMBER_OF_TALLIES,
            num_of_voters: NUMBER_OF_VOTERS,
            O: BigInt::from_str(O_STRING).unwrap()
        }
    }

}

fn create_tellers(num_of_tellers: usize)-> Vec<Teller>{
    let pp = PP::create_pp();
    (0..numb_of_tellers).map(|i| Teller::createTeller(pp)).collect()
}

fn run_mix_network() {
    let group_id = SupportedGroups::FFDHE4096;
    let pp = ElGamalPP::generate_from_rfc7919(group_id);
    let key_pair = ElGamalKeyPair::generate(&pp);
    let pk = &key_pair.pk;
    //creating the first list of massages
    let enc_messages = (1..MUMBER_OF_VOTERS)
        .map(|&i| {
            let msg = encoding_quadratic_residue(BigInt::sample_below(&pp.p),&pp);
            ElGamal::encrypt(&msg, &pk)
        }).collect();
    let tellers = create_tellers(NUMBER_OF_TALLIES);
    for i in 0..NUMBER_OF_TALLIES{
        let teller_pk = tellers.get(&i).unwrap().key_pair.pk;
        let mut l1 = MixInput{
            ctx_list: enc_messages.iter().map(|ctx|{
                ElGamalCipherTextAndPK{ ctx, pk}
            }).collect(),
            pp,
            O: BigInt::from(872368723)
        };
        let mut l2: MixInput;
        let mut anonimized_list: Vec<ElGamalCiphertext>;
        for i in (1..NUMBER_OF_TALLIES){
            let l1_output = l1.mix(IN);

        }

    }
}