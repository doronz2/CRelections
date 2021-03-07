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



const L:usize = 8; //number of alternatives to the encryption

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProofInput{
    X : [BigInt;L],//list of candidate for encryption
    Y : [BigInt;L],//list of candidate for encryption
    c : (BigInt, BigInt),
    g: BigInt, //u's generator
    h: BigInt, //v's generator
    p: BigInt,
    q: BigInt
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProofOutput{
    D: [ BigInt;L],
    R: [ BigInt;L]
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
    pp: ElGamalPP,
    ctx: BigInt,
    a1: BigInt,
    a2: BigInt,
    b1: BigInt,
    b2: BigInt,
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


//a technical function that computes (x/x')^c mod p
fn div_and_pow(x: &BigInt, x_tag: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(x_tag * BigInt::mod_inv(&x, &p)), &c, &p)
}


// This function proves the there is some c_i in c_1,...,c_l that is an encryption of C
// Hirt, Sako: Efficient receipt-free voting based on homomorphic encryption.
// The following function is an attempt to copy from there with Fiat-Shamir heuristic
impl ReencProofInput {
    pub fn reenc_1_out_of_L_prover(self, t: usize, eta: BigInt) -> ReencProofOutput {
        let (x, y) = self.c;
        let mut list_d_i = Vec::with_capacity(L);
        let mut list_r_i = Vec::with_capacity(L);
        let mut list_a_i = Vec::with_capacity(L);
        let mut list_b_i = Vec::with_capacity(L);

        for _ in 0..L {
            list_d_i.push(BigInt::sample_below(&self.q));
            list_r_i.push(BigInt::sample_below(&self.q));
        }
        for i in 0..L {
            list_a_i.push(BigInt::mod_floor(&(div_and_pow(&self.X[i], &x, &list_d_i[i], &self.p) *
                BigInt::mod_pow(&self.g, &list_r_i[i], &self.p)), &self.p));
            list_b_i.push(BigInt::mod_floor(&(div_and_pow(&self.Y[i], &y, &list_d_i[i], &self.p) *
                BigInt::mod_pow(&self.h, &list_r_i[i], &self.p)), &self.p));
        }

        let mut E = {
            let mut e_vec = Vec::new();
            e_vec.push(&x);
            e_vec.push(&y);
            for e_x in self.X.iter() {
                e_vec.push(&e_x);
            }
            for e_y in self.Y.iter() {
                e_vec.push(&e_y);
            }
            e_vec
        };
        E.extend(list_a_i.iter());
        E.extend(list_b_i.iter());

        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &E)
                                  , &self.q);
        let w = BigInt::mod_floor(&(&eta * &list_d_i[t] + &list_r_i[t]), &self.q);
        let sum: BigInt = list_d_i.iter().fold(BigInt::zero(), |a, b| a + b);
        let tmp = sum - &list_d_i[t];
        list_d_i[t] = BigInt::mod_floor(&(c - tmp)
                                        , &self.q);
        list_r_i[t] = BigInt::mod_floor(&(&w - &eta * &list_d_i[t]), &self.q);
        ReencProofOutput { D: list_d_i.try_into().unwrap(), R: list_r_i.try_into().unwrap() }
    }

    pub fn reenc_1_out_of_L_verifier(self, proof: ReencProofOutput) -> bool {
        let (x, y) = self.c;

        let mut list_a_i = Vec::with_capacity(L);
        let mut list_b_i = Vec::with_capacity(L);

        for i in 0..L {
            list_a_i.push(BigInt::mod_floor(&(div_and_pow(&self.X[i], &x, &proof.D[i], &self.p) *
                BigInt::mod_pow(&self.g, &proof.R[i], &self.p)), &self.p));
            list_b_i.push(BigInt::mod_floor(&(div_and_pow(&self.Y[i], &y, &proof.D[i], &self.p) *
                BigInt::mod_pow(&self.h, &proof.R[i], &self.p)), &self.p));
        }

        let mut E = {
            let mut e_vec = Vec::new();
            e_vec.push(&x);
            e_vec.push(&y);
            for e_x in self.X.iter() {
                e_vec.push(&e_x);
            }
            for e_y in self.Y.iter() {
                e_vec.push(&e_y);
            }
            e_vec
        };
        E.extend(list_a_i.iter());
        E.extend(list_b_i.iter());

        let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&self.q);
        let sum: BigInt = proof.D.iter().fold(BigInt::zero(), |a, b| a + b);
        let D = sum.mod_floor(&self.q);
        return c == D
    }
}


impl VotePfPublicInput {
    pub fn votepf_prover(self, witness: VoteWitness) -> VotePfProof {
        let r1 = BigInt::sample_below(&self.pp.q);
        let r2 = BigInt::sample_below(&self.pp.q);
        let mut E = vec![&self.pp.g, &self.a1, &self.b1, &self.a2, &self.b2, &self.ctx];
        let pre_hash_1 = BigInt::mod_pow(&self.pp.g, &r1, &self.pp.p);
        let pre_hash_2 = BigInt::mod_pow(&self.pp.g, &r2, &self.pp.p);
        E.push(&pre_hash_1);
        E.push(&pre_hash_2);
        let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&self.pp.q);
        let s1 = r1 - &c * witness.alpha_1;
        let s2 = r2 - &c * witness.alpha_2;
        VotePfProof { c, s1, s2 }
    }

        pub fn votepf_verifier(self, proof: VotePfProof) -> bool {
            let mut E = vec![&self.pp.g, &self.a1, &self.b1, &self.a2, &self.b2, &self.ctx];
            let pre_hash_1 = (BigInt::mod_pow(&self.pp.g, &proof.s1, &self.pp.p) *
                BigInt::mod_pow(&self.a1, &proof.c, &self.pp.p)).mod_floor(&self.pp.p);
            let pre_hash_2 = (BigInt::mod_pow(&self.pp.g, &proof.s2, &self.pp.p) *
                BigInt::mod_pow(&self.a2, &proof.c, &self.pp.p)).mod_floor(&self.pp.p);
            E.push(&pre_hash_1);
            E.push(&pre_hash_2);
            let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&self.pp.q);
            proof.c == c
        }
    }
