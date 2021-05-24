use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalPublicKey};
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;

use serde::{Deserialize, Serialize};

use crate::citivas::dist_el_gamal::DistElGamal;
use crate::citivas::encryption_schemes::{reencrypt, ElGamalCipherTextAndPK};
use crate::citivas::supervisor::SystemParameters;
use crate::citivas::voter::Vote;
use crate::citivas::zkproofs::{ReencProofInput, VotepfPublicInput};
use rand::seq::SliceRandom;
use rand::thread_rng;
const OUT: bool = true;
const IN: bool = false;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Teller {
    share: DistElGamal,
    sp: SystemParameters,
    pub teller_index: i32,
}

#[derive(Clone, PartialEq, Debug)]
pub struct MixInput<'a> {
    pub(crate) ctx_list: Vec<ElGamalCipherTextAndPK<'a>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MixOutput {
    pub ctx_mix_list: Vec<ElGamalCiphertext>,
    pub comm_to_shuffle_list: Vec<BigInt>,
}

impl Teller {
    pub fn create_teller(sp: SystemParameters, teller_index: i32) -> Self {
        let share = DistElGamal::generate_share(&sp.pp, teller_index);
        Teller {
            share,
            sp,
            teller_index,
        }
    }

}

pub struct TellerMixingParams {
    r_list: Vec<BigInt>,  // the r parameter for reencryption of the ctx
    w_list: Vec<BigInt>,  // the w parameter for committing the ctx
    perm: Vec<usize>,     //representation of the random permutation of the ciphertexts (mixing)
    inv_perm: Vec<usize>, //representation of the inverse random permutation of the ciphertexts (mixing)
}

impl Teller {
    pub fn get_share(&self) -> &DistElGamal {
        &self.share
    }

    pub fn get_public_share(self) -> BigInt {
        self.share.get_public_share()
    }

    pub fn get_private_share(self) -> BigInt {
        self.share.get_private_share()
    }

    //not that some code is redundent as the lists (permuted and its inverse are computed twice for both directions
    pub fn mix(self, mix_input: MixInput, dir: bool) -> (MixOutput, TellerMixingParams) {
        let mut rng = thread_rng();
        let m = self.sp.num_of_voters;
        let mut permuted_indices = Vec::with_capacity(m);

        //for i in 0..m{
        //     permuted_indices[i] = i;
        // }

        permuted_indices.shuffle(&mut rng);
        println!("permuted: {:?}", permuted_indices);
        // let inverse_permuted_indices: [usize;m] = [0;m];
        let inverse_permuted_indices: Vec<usize> = (0..m)
            .map(|i| permuted_indices.iter().position(|&e| e == i).unwrap())
            .collect();
        println!("permuted inverse: {:?}", inverse_permuted_indices);

        let permuted_ctx: Vec<&ElGamalCipherTextAndPK> = permuted_indices
            .iter()
            .map(|&i| mix_input.ctx_list.get(i).unwrap())
            .collect();

        let mut l_r = Vec::with_capacity(m);
        let mut l_c = Vec::with_capacity(m);
        let mut r_list: Vec<BigInt> = Vec::with_capacity(m);
        let mut w_list: Vec<BigInt> = Vec::with_capacity(m);

        for i in 0..m {
            let r_i = BigInt::sample_below(&self.sp.pp.q);
            r_list.push(r_i.clone());
            l_r.push(reencrypt(&permuted_ctx[i], &r_i));

            let w_i = BigInt::sample_below(&self.sp.O);
            w_list.push(w_i.clone());

            if dir == IN {
                l_c.push(hash_sha256::HSha256::create_hash(&[
                    &BigInt::from(permuted_indices[i] as i32),
                    &w_i,
                ]));
            } else {
                l_c.push(hash_sha256::HSha256::create_hash(&[
                    &BigInt::from(inverse_permuted_indices[i] as i32),
                    &w_i,
                ]));
            }
        }
        (
            MixOutput {
                ctx_mix_list: l_r,
                comm_to_shuffle_list: l_c,
            },
            TellerMixingParams {
                r_list,
                w_list,
                perm: Vec::from(permuted_indices),
                inv_perm: inverse_permuted_indices,
            },
        )
    }

    // Verify the proofs of votepf and reencryption
    // move function to tallies
    pub fn check_votes(vote: Vote, params: &SystemParameters, pk: &ElGamalPublicKey) -> bool {
        let vote_pf_input = VotepfPublicInput {
            encrypted_credential: vote.ev.clone(),
            encrypted_choice: vote.es.clone(),
            eid: BigInt::from(params.eid),
        };
        let check_1 = vote.pf.votepf_verifier(&vote_pf_input, &params);

        let reenc_proof_input = ReencProofInput {
            c_list: params.encrypted_candidate_list.clone().unwrap(),
            c: vote.es.clone(),
        };

        let check_2 = reenc_proof_input.reenc_1_out_of_l_verifier(
            &params.pp,
            &pk,
            &vote.pw,
            params.num_of_candidates,
        );

        check_1 && check_2
    }

}
