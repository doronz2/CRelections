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
use crate::citivas::Entity::Entity;
use crate::citivas::zkproofs::{DVRP_prover, DVRP_Public_Input, DVRP_Proof};

pub struct RegistrationTeller{
    KTT: BigInt, // Tabulate tellers public keys (yes not registration tellers!)
    CredentialShare: Vec<CredentialShare>
}

pub struct Registrar{
    registrar_index: usize,
    pp:ElGamalPP,
    key_pair: ElGamalKeyPair,
    num_of_voters: usize,
    KTT: ElGamalPublicKey,//PK of the tellers (tally tellers)
    cred_vec: Vec<CredentialShare>
}

impl Entity for Registrar{
    fn get_pp(&self) -> &ElGamalPP {
        &self.pp
    }

    fn get_pk(&self) -> &BigInt {
        &self.key_pair.pk.h
    }

    fn get_sk(&self) -> &BigInt {
        &self.key_pair.sk.x
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

    fn get_key_pair(&self) -> &ElGamalKeyPair {
        &self.key_pair
    }
}





pub struct CredentialShare{
    s_i: BigInt, //private credential share
    S_i: ElGamalCiphertext,// Public credential share
    S_i_tag: ElGamalCiphertext,// Public credential share
    r_i: BigInt,// randomness for encrypting S_i_tag
    eta: BigInt// randomness for reencryption to obtain S_i
}

pub struct CredetialShareOutput{
    pub s_i: BigInt, //private credential share
    pub S_i_tag: ElGamalCiphertext,// Public credential share
    pub r_i: BigInt,// randomness for encrypting S_i_tag
    pub dvrp_proof: DVRP_Proof
}

impl CredetialShareOutput{
    pub fn get_dvrp_input(&self, S_i: &ElGamalCiphertext)-> DVRP_Public_Input{
        DVRP_Public_Input{ e: &S_i, e_tag:  &self.S_i_tag}
    }
}

impl  Registrar{
    pub fn create_credential_share(&mut self) -> (){
        let pp = &self.pp.clone();
        let s_i = BigInt::sample_below(&pp.q);
        let r_i = BigInt::sample_below(&pp.q);
        let S_i_tag = ElGamal::encrypt_from_predefined_randomness(&s_i, &self.KTT, &r_i).unwrap();
        let eta = BigInt::sample_below(&pp.q);
        let S_i = reencrypt(&ElGamalCipherTextAndPK { ctx: S_i_tag.clone(), pk: &self.KTT }
                            , &temp_rand_for_reencryption);
        &self.cred_vec.push(CredentialShare {  s_i, S_i, S_i_tag, r_i, eta });
    }


    pub fn publish_credential_with_proof(&self, voter_index: usize)-> CredetialShareOutput{
        let cred_share = &self.cred_vec.get(voter_index).unwrap();
        let dvrp_input = &DVRP_Public_Input{ e: &cred_share.S_i_tag, e_tag: &cred_share.S_i };
        let proof = DVRP_prover(&self, dvrp_input, cred_share.eta.clone());
        CredetialShareOutput{
            s_i: cred_share.s_i.clone(),
            S_i_tag: cred_share.S_i_tag.clone(),
            r_i: cred_share.r_i.clone(),
            dvrp_proof: proof
        }
    }

}
