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

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Voter{
    designation_key_pair: ElGamalKeyPair,
    h_v: BigInt, //registration key
    voter_number: usize,
    pp:ElGamalPP
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DVRP_Public_Input{ //stands for designated-verifier reencryption proof
e: ElGamalCiphertext,
    e_tag: ElGamalCiphertext, //El-Gamal reencyption of e
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DVRP_Proof{ //stands for designated-verifier reencryption proof
c: BigInt,
    w: BigInt,
    r: BigInt,
    u: BigInt,
}

//a technical function that computes (x/x')^c mod p
pub fn div_and_pow(x: &BigInt, x_tag: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(x_tag * BigInt::mod_inv(&x, &p)).mod_floor(&p), &c, &p)
}


impl DVRP_Public_Input{
    pub fn create_input(e: ElGamalCiphertext, e_tag: ElGamalCiphertext)-> Self{
        Self{e,e_tag}
    }
}

impl Voter {
    pub fn create_voter(voter_number: usize, pp: ElGamalPP)-> Self{
        let key_pair = ElGamalKeyPair::generate(&pp);
        //  let key_pair= ElGamalKeyPair{ pk: ElGamalPublicKey { pp:pp.clone(), h: BigInt::from(13) }, sk: ElGamalPrivateKey{ pp:pp.clone(), x: BigInt::from(29) } };
        let h_v = BigInt::sample_below(&pp.p);
        Self{
            designation_key_pair: key_pair,
            h_v,
            voter_number,
            pp
        }
    }

    pub fn get_pk(&self)-> BigInt{
        *self.designation_key_pair.pk.h
    }

    pub fn DVRP_prover(&self, dvrp_input: &DVRP_Public_Input, eta: BigInt) -> DVRP_Proof {
        //let d = BigInt::from(3);
        let w = BigInt::from(2);
        //let r = BigInt::from(5);
        let d = BigInt::sample_below(&self.pp.q);
        //let w = BigInt::sample_below(&self.pp.q);
        let r = BigInt::sample_below(&self.pp.q);
        let a = BigInt::mod_pow(&self.pp.g, &d, &self.pp.p);
        let b = BigInt::mod_pow(&self.designation_key_pair.pk.h, &d, &self.pp.p);
        println!("a = {:?}",a);
        let s = BigInt::mod_mul(&BigInt::mod_pow(&self.pp.g, &w, &self.pp.p),
                                &BigInt::mod_pow(&self.h_v, &r, &self.pp.p),
                                &self.pp.p);
        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &[&dvrp_input.e.c1, &dvrp_input.e.c2,&dvrp_input.e_tag.c1, &dvrp_input.e_tag.c2, &a, &b, &s]
        ), &self.pp.q);
        println!("dvrp prover {:#?}", [&dvrp_input.e.c1, &dvrp_input.e.c2,&dvrp_input.e_tag.c1, &dvrp_input.e_tag.c2, &a, &b, &s]);

        let u = (&d + &eta * (&c + &w)).mod_floor(&self.pp.q);
        println!("u = {:?}",u);
        DVRP_Proof { c, w, r, u }
    }


    pub fn DVRP_verifier(&self, dvrp_input: &DVRP_Public_Input, dvrp_proof: &DVRP_Proof) -> bool {
        //a′ = g^u/(x′/x)^(c+w) mod p
        let x = dvrp_input.e.c1.clone();
        let y = dvrp_input.e.c2.clone();
        let x_tag = dvrp_input.e_tag.c1.clone();
        let y_tag = dvrp_input.e_tag.c2.clone();
        let h = &self.designation_key_pair.pk.h;
        let a_tag: BigInt = (BigInt::mod_pow(&self.pp.g, &dvrp_proof.u, &self.pp.p) *
            BigInt::mod_inv(&div_and_pow(&x, &x_tag, &(&dvrp_proof.c + &dvrp_proof.w), &self.pp.p)
                            , &self.pp.p)).mod_floor(&self.pp.p);
        println!("mod inv {:?}", BigInt::mod_inv(&BigInt::from(7),&BigInt::from(163)));
        let b_tag: BigInt = (BigInt::mod_pow(&h, &dvrp_proof.u, &self.pp.p) *
            BigInt::mod_inv(&div_and_pow(&y, &y_tag, &(&dvrp_proof.c + &dvrp_proof.w), &self.pp.p)
                            , &self.pp.p)).mod_floor(&self.pp.p);
        println!("div and pow {:?}", &b_tag);
        println!("div and pow {:?}", div_and_pow(&y, &y_tag, &BigInt::from(1), &self.pp.p));
        let s_tag = BigInt::mod_mul(&BigInt::mod_pow(&self.pp.g, &dvrp_proof.w, &self.pp.p),
                                    &BigInt::mod_pow(&self.h_v, &dvrp_proof.r, &self.pp.p),
                                    &self.pp.p);

        let c_tag = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &[&x, &y, &x_tag, &y_tag, &a_tag, &b_tag, &s_tag]
        ), &self.pp.q);
        println!("dvrp verifier {:#?}", [&x, &y,&x_tag, &y_tag, &a_tag, &b_tag, &s_tag]);

        c_tag == dvrp_proof.c
    }

    pub fn fakeDVRP_prover(self, dvrp_input: DVRP_Public_Input) -> DVRP_Proof {
        let x = dvrp_input.e.c1;
        let y = dvrp_input.e.c2;
        let x_tag = dvrp_input.e_tag.c1;
        let y_tag = dvrp_input.e_tag.c2;
        let key_pair = self.designation_key_pair;
        let alpha = BigInt::sample_below(&self.pp.q);
        let beta = BigInt::sample_below(&self.pp.q);
        let u_tilde = BigInt::sample_below(&self.pp.q);
        let a_tilde: BigInt = BigInt::mod_pow(&self.pp.g, &u_tilde, &self.pp.p) *
            BigInt::mod_inv(&div_and_pow(&x, &x_tag, &alpha, &self.pp.p)
                            , &self.pp.p);
        let b_tilde: BigInt = BigInt::mod_pow(&key_pair.pk.h, &u_tilde, &self.pp.p) *
            BigInt::mod_inv(&div_and_pow(&y, &y_tag, &alpha, &self.pp.p)
                            , &self.pp.p);
        let s_tilde = BigInt::mod_pow(&self.pp.g, &beta, &self.pp.p);
        let c_tilde = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &[&x, &y, &x_tag, &y_tag, &a_tilde, &b_tilde, &s_tilde]
        ), &self.pp.q);
        let w_tilde = BigInt::mod_floor(&(&alpha - &c_tilde), &self.pp.q);
        let r_tilde = BigInt::mod_floor(&(&(&beta - &w_tilde) * BigInt::mod_inv(&key_pair.sk.x, &self.pp.q))
                                        , &self.pp.q);
        DVRP_Proof{
            c: c_tilde,
            w: w_tilde,
            r: r_tilde,
            u: u_tilde
        }
    }
}

