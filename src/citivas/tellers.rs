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
use crate::citivas::superviser::PP;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Teller{
    pub key_pair: ElGamalKeyPair,
    num_of_tellers: usize,
    num_of_voters: usize,
    O: BigInt
}


impl Teller{
    pub fn createTeller(pp:PP)-> Self{
        let key_pair = ElGamalKeyPair::generate(&pp.pp);
        Teller{
            key_pair,
            num_of_tellers: pp.num_of_tallies,
            num_of_voters: pp.num_of_voters,
            O: pp.O }
    }

    pub fn commit(self)-> BigInt{
        let q = BigInt::sample_below( &self.O);
        hash_sha256::HSha256::create_hash(&[&q]);//commitment to q
    }


}


pub struct TellerMixParameters{
    r_list: Vec<BigInt>,// the r parameter for reencryption of the ctx
    w_list: Vec<BigInt>,// the w parameter for committing the ctx
    perm: Vec<usize>, //representation of the random permutation of the ciphertexts (mixing)
    inv_perm: Vec<usize>,//representation of the inverse random permutation of the ciphertexts (mixing)
}

#[derive(Clone, PartialEq, Debug)]
pub struct MixInput<'a>{
    pub(crate) ctx_list : Vec<ElGamalCipherTextAndPK<'a>>,
    pub(crate) O: BigInt //a set (of size O) is specified in Citivas where random parameter are selected from
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MixOutput{
    pub ctx_mix_list : Vec<ElGamalCiphertext>,
    pub comm_to_shuffle_list: Vec<BigInt>,

}



impl <'a>MixInput<'a>{
    //not that some code is redundent as the lists (permuted and its inverse are computed twice for both directions
    pub fn mix(mut self, dir:bool ) -> (MixOutput, TellerMixParameters) {
        let mut rng = thread_rng();

        let mut permuted_indices: [usize;M] = [0;M];
        for i in 0..M{
            permuted_indices[i] = i;
        }
        permuted_indices.shuffle(&mut rng);
        println!("permuted: {:?}", permuted_indices);
        // let inverse_permuted_indices: [usize;M] = [0;M];
        let inverse_permuted_indices: Vec<usize> = (0..M)
            .map(|i| {
                permuted_indices.iter().position(|&e| e == i).unwrap()
            })
            .collect();
        println!("permuted inverse: {:?}", inverse_permuted_indices);

        let mut permuted_ctx: Vec<&ElGamalCipherTextAndPK>  = permuted_indices
            .iter()
            .map(|&i| self.ctx_list.get(i).unwrap())
            .collect();

        let mut L_R = Vec::with_capacity(M);
        let mut L_C = Vec::with_capacity(M);
        let mut r_list: Vec<BigInt> = Vec::with_capacity(M);
        let mut w_list: Vec<BigInt> = Vec::with_capacity(M);

        for i in 0..M {
            let r_i = BigInt::sample_below(&self.pp.q);
            r_list.push(r_i);
            L_R.push(reencrypt(&permuted_ctx[i], &r_i));

            let w_i = BigInt::sample_below( &self.O);
            w_list.push(w_i);

            if dir == IN {
                L_C.push(hash_sha256::HSha256::create_hash(
                    &[&BigInt::from(permuted_indices[i] as i32), &w_i]
                ));
            } else {
                L_C.push(hash_sha256::HSha256::create_hash(
                    &[&BigInt::from(inverse_permuteddices[i] as i32), &w_i]
                ));
            }
        }
        (
            MixOutput{ ctx_mix_list: L_R, comm_to_shuffle_list: L_C},
            TellerMixParameters{
                r_list,
                w_list,
                perm: Vec::from(permuted_indices),
                inv_perm: inverse_permuted_indices
            }
        )
    }

}

