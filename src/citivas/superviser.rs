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
const NUMBER_OF_TALLIES:usize = 5;
pub const NUMBER_OF_VOTERS:usize = 8;
const OUT: bool = true;
const IN: bool = false;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SystemParameters {
    pub pp: ElGamalPP,
    pub num_of_tellers: usize,
    pub num_of_voters: usize,
    pub O: BigInt //a set (of size O) is specified in Citivas where random parameter are selected from
  }

impl SystemParameters {
    pub fn create_sp()-> Self{
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let O = BigInt::from_str(O_STRING).unwrap();
        SystemParameters{
            pp,
            num_of_tellers: NUMBER_OF_TALLIES,
            num_of_voters: NUMBER_OF_VOTERS,
            O: BigInt::from_str(O_STRING).unwrap()
        }
    }

}

fn create_tellers()-> Vec<Teller>{
    let sp = SystemParameters::create_sp();
    (0..sp.num_of_tellers).map(|i| Teller::createTeller(sp.clone())).collect()
}

fn run_mix_network() {
    let group_id = SupportedGroups::FFDHE4096;
    let pp = ElGamalPP::generate_from_rfc7919(group_id);
    let key_pair = ElGamalKeyPair::generate(&pp);
    let pk = &key_pair.pk;
    //creating the first list of massages
    let enc_messages: Vec<ElGamalCiphertext> = (1..NUMBER_OF_VOTERS)
        .map(|i| {
            let msg = encoding_quadratic_residue(BigInt::sample_below(&pp.p),&pp);
            ElGamal::encrypt(&msg, &pk).unwrap()
        }).collect();
    let tellers = create_tellers();
    for i in (0..NUMBER_OF_TALLIES).by_ref(){
        let teller_pk = tellers.get(i).unwrap().key_pair.pk.clone();
        let mut l1 = MixInput{
            ctx_list: enc_messages.iter().map(|ctx|{
                ElGamalCipherTextAndPK{ ctx: ctx.clone(), pk}
            }).collect()
        };
        let mut l2: MixInput;
        let mut anonimized_list: Vec<ElGamalCiphertext>;
        //let l1_output = tellers.get(i).unwrap().mix(l1, IN);

        }

    }
