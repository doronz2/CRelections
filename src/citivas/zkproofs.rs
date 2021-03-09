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
use crate::citivas::voter::Voter;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProofInput{
    pub(crate) C_list : Vec<ElGamalCiphertext>,//list of candidate for encryption
    pub(crate) c : ElGamalCiphertext,
 }

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProofOutput{
    D: Vec<BigInt>,
    R: Vec<BigInt>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DLogProof {
    pub random_point_1: BigInt,
    pub response: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub alpha_1: BigInt,
    pub alpha_2: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Statement {
    pub h: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VotePfPublicInput{
    pub(crate) a1: BigInt,
    pub(crate) a2: BigInt,
    pub(crate) b1: BigInt,
    pub(crate) b2: BigInt,
    pub(crate) ctx: BigInt
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VotePfProof{
    c:BigInt,
    s1:BigInt,
    s2:BigInt
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VoteWitness{
    alpha_1: BigInt,
    alpha_2: BigInt
}


pub trait ProveDLog {
    fn prove(witness: &Witness, pp: &ElGamalPP) -> DLogProof;
    fn verify(&self, statement: &Statement, pp: &ElGamalPP) -> Result<(), ProofError>;
}

impl VoteWitness{
    pub fn generate_example_witness()-> Self{
        Self{
            alpha_1: BigInt::from(6),
            alpha_2: BigInt::from(7)
        }
    }

    pub fn generate_random_witness(pp: &ElGamalPP)-> Self{
        Self{
            alpha_1: BigInt::sample_below(&pp.q),
            alpha_2: BigInt::sample_below(&pp.q)
        }
    }
}
//a technical function that computes (x/x')^c mod p
fn div_and_pow(x: &BigInt, x_tag: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(x_tag * BigInt::mod_inv(&x, &p)), &c, &p)
}

impl VotePfPublicInput{
    pub fn generateRandomInput(pp: &ElGamalPP, witness: &VoteWitness)-> Self{
        let  a1: BigInt = BigInt::mod_pow(&pp.g, &witness.alpha_1, &pp.p);
        let  a2: BigInt = BigInt::mod_pow(&pp.g, &witness.alpha_2, &pp.p);
        let  b1: BigInt = BigInt::sample_below(&pp.p);
        let  b2: BigInt = BigInt::sample_below(&pp.p);
        let  ctx: BigInt = BigInt::sample_below(&pp.p);
        Self{a1,a2,b1,b2, ctx}
    }
}


// This function proves the there is some c_t (for a private t) in c_1,...,c_l that is
// an encryption of some cipher text c=(u,v)
// The following function is an attempt to implement [1] with Fiat-Shamir heuristic
// L is the number of candidate of encryption and t stands for index of the real encrypted message.
// Eta is the value that encrypts the message (represented by r in Civitas)
// [1]: Hirt, Sako: Efficient receipt-free voting based on homomorphic encryption.

impl ReencProofInput {
    pub fn reenc_1_out_of_L_prover(&self, pp: &ElGamalPP, pk: &ElGamalPublicKey, t: usize, eta: BigInt, L:usize) -> ReencProofOutput {
        if self.C_list.len() != L{
            panic!("Size of the list doesn't match the specified list length L")
        }
        if *pp != pk.pp{
            panic!("mismatch pp");
        }
        let mut list_d_i = Vec::with_capacity(L);
        let mut list_r_i = Vec::with_capacity(L);
        let mut list_a_i = Vec::with_capacity(L);
        let mut list_b_i = Vec::with_capacity(L);

        for _ in 0..L {
            list_d_i.push(BigInt::sample_below(&pp.q));
            list_r_i.push(BigInt::sample_below(&pp.q));
        }
        let mut u_i: &BigInt;
        let mut v_i: &BigInt;
        for i in 0..L {
            u_i = &self.C_list[i].c1;
            v_i = &self.C_list[i].c2;
            list_a_i.push(BigInt::mod_floor(&(div_and_pow(u_i, &self.c.c1, &list_d_i[i], &pp.p) *
                BigInt::mod_pow(&pp.g, &list_r_i[i], &pp.p)), &pp.p));
            list_b_i.push(BigInt::mod_floor(&(div_and_pow(v_i, &self.c.c2, &list_d_i[i], &pp.p) *
                BigInt::mod_pow(&pk.h, &list_r_i[i], &pp.p)), &pp.p));
        }

        let mut E = {
            let mut e_vec = Vec::new();
            e_vec.push(&self.c.c1);
            e_vec.push(&self.c.c2);
            for e in self.C_list.iter() {
                e_vec.push(&e.c1);
            }
            for e in self.C_list.iter() {
                e_vec.push(&e.c2);
            }
            e_vec
        };
        E.extend(list_a_i.iter());
        E.extend(list_b_i.iter());

        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &E)
                                  , &pp.q);
        let w = BigInt::mod_floor(&(&eta * &list_d_i[t] + &list_r_i[t]), &pp.q);
        let sum: BigInt = list_d_i.iter().fold(BigInt::zero(), |a, b| a + b);
        let tmp = sum - &list_d_i[t];
        list_d_i[t] = BigInt::mod_floor(&(c - tmp)
                                        , &pp.q);
        list_r_i[t] = BigInt::mod_floor(&(&w - &eta * &list_d_i[t]), &pp.q);
        ReencProofOutput { D: list_d_i.try_into().unwrap(), R: list_r_i.try_into().unwrap() }
    }

    pub fn reenc_1_out_of_L_verifier(&self,  pp: &ElGamalPP, pk: &ElGamalPublicKey, proof: ReencProofOutput, L:usize) -> bool {

        let mut list_a_i = Vec::with_capacity(L);
        let mut list_b_i = Vec::with_capacity(L);

        let mut u_i: &BigInt;
        let mut v_i: &BigInt;
        for i in 0..L {
            u_i = &self.C_list[i].c1;
            v_i = &self.C_list[i].c2;
            list_a_i.push(BigInt::mod_floor(&(div_and_pow(&u_i, &self.c.c1, &proof.D[i], &pp.p) *
                BigInt::mod_pow(&pp.g, &proof.R[i], &pp.p)), &pp.p));
            list_b_i.push(BigInt::mod_floor(&(div_and_pow(&v_i, &self.c.c2, &proof.D[i], &pp.p) *
                BigInt::mod_pow(&pk.h, &proof.R[i], &pp.p)), &pp.p));
        }

        let mut E = {
            let mut e_vec = Vec::new();
            e_vec.push(&self.c.c1);
            e_vec.push(&self.c.c2);
            for e in self.C_list.iter() {
                e_vec.push(&e.c1);
            }
            for e in self.C_list.iter() {
                e_vec.push(&e.c2);
            }
            e_vec
        };
        E.extend(list_a_i.iter());
        E.extend(list_b_i.iter());

        let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&pp.q);
        let sum: BigInt = proof.D.iter().fold(BigInt::zero(), |a, b| a + b);
        let D = sum.mod_floor(&pp.q);
        return c == D
    }
}


impl VotePfPublicInput {
    pub fn votepf_prover(&self, voter: &Voter, witness: VoteWitness) -> VotePfProof {
        let r1 = BigInt::sample_below(&voter.pp.q);
        let r2 = BigInt::sample_below(&voter.pp.q);
        let mut E = vec![&voter.pp.g, &self.a1, &self.b1, &self.a2, &self.b2, &self.ctx];
        let pre_hash_1 = BigInt::mod_pow(&voter.pp.g, &r1, &voter.pp.p);
        let pre_hash_2 = BigInt::mod_pow(&voter.pp.g, &r2, &voter.pp.p);
        E.push(&pre_hash_1);
        E.push(&pre_hash_2);
//        println!("E = {:#?}", E);
        let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&voter.pp.q);
        let s1 = (r1 - &c * witness.alpha_1).mod_floor(&voter.pp.q);
        let s2 = (r2 - &c * witness.alpha_2).mod_floor(&voter.pp.q);
        VotePfProof { c, s1, s2 }
    }
}
impl VotePfProof{
        pub fn votepf_verifier(&self, input: &VotePfPublicInput, voter: &Voter) -> bool {
            let mut E = vec![&voter.pp.g, &input.a1, &input.b1, &input.a2, &input.b2, &input.ctx];
            let pre_hash_1 = (BigInt::mod_pow(&voter.pp.g, &self.s1, &voter.pp.p) *
                BigInt::mod_pow(&input.a1, &self.c, &voter.pp.p)).mod_floor(&voter.pp.p);
            let pre_hash_2 = (BigInt::mod_pow(&voter.pp.g, &self.s2, &voter.pp.p) *
                BigInt::mod_pow(&input.a2, &self.c, &voter.pp.p)).mod_floor(&voter.pp.p);
            E.push(&pre_hash_1);
            E.push(&pre_hash_2);
         //   println!("E = {:#?}", E);
            let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&voter.pp.q);
            self.c == c
        }
}
