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

const M:usize = 8;
const O:BigInt = BigInt::from_str("9872349823749283749284722945184515450128750182512032").unwrap();


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MixInput{
    ctx_list : [ElGamalCipherTextAndPK; M],
    dir_in: bool //dir ={in,out}
}

impl MixInput{
    //I didn't see (yet) the reason to implement direction
    pub fn MixInput(mut self){
        let permuted_indices = [0..M].shuffle();

        let mut permuted_ctx  = permuted_indices.iter().map(
            |i| self.ctx_list[i]
        );
        let mut L_R = Vec::with_capacity(M);
        let mut L_C = Vec::with_capacity(M);
        let r_i: BigInt;
        let w_i: BigInt;
        for i in 0..M {
            let r_i = BigInt::sample_below(&self.q);
            L_R.push(reencrypt(permuted_ctx[i], r_i));
            w_i = BigInt::sample_below( &O);
            L_C.push(Hash::create_hash(&[&permuted_ctx[i],&w_i]));
        }
    }


    }
}