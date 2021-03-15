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
use crate::citivas::encryption_schemes::{reencrypt, ElGamalCipherTextAndPK};
use rand::seq::SliceRandom;
use rand::thread_rng;
use crate::citivas::superviser::SystemParameters;
use crate::citivas::superviser;
use crate::citivas::Entity::Entity;
use crate::citivas::zkproofs::DVRP_Proof;
use crate::citivas::registrar;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Voter{
    designation_key_pair: ElGamalKeyPair,
    voter_number: usize,
    pub(crate) pp:ElGamalPP
}

//a technical function that computes (x/x')^c mod p
pub fn div_and_pow(x: &BigInt, x_tag: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(x_tag * BigInt::mod_inv(&x, &p)).mod_floor(&p), &c, &p)
}

impl Voter {
    pub fn create(voter_number: usize, pp: ElGamalPP) -> Self {
        let key_pair = ElGamalKeyPair::generate(&pp);
        //  let key_pair= ElGamalKeyPair{ pk: ElGamalPublicKey { pp:pp.clone(), h: BigInt::from(13) }, sk: ElGamalPrivateKey{ pp:pp.clone(), x: BigInt::from(29) } };
        let h_v = BigInt::sample_below(&pp.p);
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp
        }
    }

    pub fn create_voter_from_given_sk(voter_number: usize, pp: ElGamalPP, x: BigInt) -> Self {
        let h = BigInt::mod_pow(&pp.g, &x, &pp.p);
        let pk = ElGamalPublicKey { pp: pp.clone(), h };
        let sk = ElGamalPrivateKey { pp: pp.clone(), x };
        let key_pair = ElGamalKeyPair { pk, sk };
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp
        }
    }
}

impl Entity for Voter {
    fn get_pp(&self) -> &ElGamalPP {
        &self.pp
    }


    fn get_pk(&self) -> &BigInt {
        &self.designation_key_pair.pk.h
    }

    fn get_sk(&self) -> &BigInt {
        &self.designation_key_pair.sk.x
    }

    fn get_p(&self) -> &BigInt {
        &self.pp.p
    }

    fn get_q(&self) -> &BigInt {
        &self.pp.q
    }

    fn get_generator(&self) -> &BigInt {
        &self.pp.g
    }

    fn get_key_pair(&self) -> &ElGamalKeyPair{
        &self.designation_key_pair
    }
}



fn verify_cred(dvrp_proof: DVRP_Proof)->bool{

}