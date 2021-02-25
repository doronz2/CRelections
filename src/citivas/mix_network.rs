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


const M:usize = 8;
const OUT: bool = true;
const IN: bool = false;



#[derive(Clone, PartialEq, Debug)]
pub struct MixInput<'a>{
    pub(crate) ctx_list : Vec<ElGamalCipherTextAndPK<'a>>,
    pp: ElGamalPP,
    pub(crate) O: BigInt //a set (of size O) is specified in Citivas where random parameter are selected from
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MixOutput{
    pub ctx_mix_list : Vec<ElGamalCiphertext>,
    pub comm_to_shuffle_list: Vec<BigInt>,

}



impl <'a>MixInput<'a>{
    //not that some code is redundent as the lists (permuted and its inverse are computed twice for both directions
    pub fn mix(mut self, dir:bool ) -> MixOutput {
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
        for i in 0..M {
            let r_i = BigInt::sample_below(&self.pp.q);
            L_R.push(reencrypt(&permuted_ctx[i], &r_i));

            let w_i = BigInt::sample_below( &self.O);
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
        MixOutput{ ctx_mix_list: L_R, comm_to_shuffle_list: L_C}
    }

}



pub fn run_mix(){
    let group_id = SupportedGroups::FFDHE4096;
    let pp = ElGamalPP::generate_from_rfc7919(group_id);
    let key_pair = ElGamalKeyPair::generate(&pp);
    let pk = &key_pair.pk;
    let messages = [BigInt::from(12),BigInt::from(13),BigInt::from(14)];
    let mix_input = MixInput{
        ctx_list: messages.iter().map(|msg|{
            let ctx = ElGamal::encrypt(msg, pk).unwrap();
            ElGamalCipherTextAndPK{ ctx, pk}
        }).collect(),
        pp,
        O: BigInt::from(872368723)
    };
    let mix_output = mix_input.mix();
}