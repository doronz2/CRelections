use crate::citivas::entity::Entity;
use crate::citivas::supervisor::SystemParameters;
use crate::citivas::voter::Voter;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalPP, ElGamalPublicKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use vice_city::ProofError;

use std::ops::Neg;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProofInput {
    pub(crate) c_list: Vec<ElGamalCiphertext>, //list of candidate for encryption
    pub(crate) c: ElGamalCiphertext,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProof {
    d: Vec<BigInt>,
    r: Vec<BigInt>,
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
pub struct VotepfPublicInput {
    pub(crate) encrypted_credential: ElGamalCiphertext,
    pub(crate) encrypted_choice: ElGamalCiphertext,
    pub eid: BigInt, //election identifier,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VotepfProof {
    c: BigInt,
    s1: BigInt,
    s2: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VoteWitness {
    pub(crate) alpha_1: BigInt,
    pub(crate) alpha_2: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct DvrpPublicInput<'a> {
    //stands for designated-verifier reencryption proof
    pub voter_public_key: &'a BigInt,  // denoted hv in Civitas
    pub prover_public_key: &'a BigInt, //for which e' is encrypted from e
    pub e: &'a ElGamalCiphertext,
    pub e_tag: &'a ElGamalCiphertext, //El-Gamal reencyption of e
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DvrpProof {
    //stands for designated-verifier reencryption proof
    c: BigInt,
    w: BigInt,
    r: BigInt,
    u: BigInt,
}

pub trait ProveDLog {
    fn prove(witness: &Witness, pp: &ElGamalPP) -> DLogProof;
    fn verify(&self, statement: &Statement, pp: &ElGamalPP) -> Result<(), ProofError>;
}

impl VoteWitness {
    pub fn generate_random_witness(pp: &ElGamalPP) -> Self {
        Self {
            alpha_1: BigInt::sample_below(&pp.q),
            alpha_2: BigInt::sample_below(&pp.q),
        }
    }
}
//a technical function that computes (x/x')^c mod p
fn div_and_pow(denom: &BigInt, nom: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(nom * BigInt::mod_inv(&denom, &p)), &c, &p)
}

impl VotepfPublicInput {
    pub fn generate_random_input(pp: &ElGamalPP, witness: &VoteWitness) -> Self {
        let a1: BigInt = BigInt::mod_pow(&pp.g, &witness.alpha_1, &pp.p);
        let a2: BigInt = BigInt::mod_pow(&pp.g, &witness.alpha_2, &pp.p);
        let b1: BigInt = BigInt::sample_below(&pp.p);
        let b2: BigInt = BigInt::sample_below(&pp.p);
        let e1 = ElGamalCiphertext {
            c1: a1,
            c2: b1,
            pp: pp.clone(),
        };
        let e2 = ElGamalCiphertext {
            c1: a2,
            c2: b2,
            pp: pp.clone(),
        };
        let ctx: BigInt = BigInt::sample_below(&pp.p);
        Self {
            encrypted_credential: e1,
            encrypted_choice: e2,
            eid: ctx,
        }
    }
}

// The following function proves the there is some c_t (for a private t) in a list of ciphers c_1,...,c_l that is
// an encryption of some cipher text c=(u,v)
// The following function is an attempt to implement [1] with Fiat-Shamir heuristic
// L is the number of candidate of encryption and t stands for index of the real encrypted message.
// Eta is the value that encrypts the message (represented by r in Civitas)
// [1]: Hirt, Sako: Efficient receipt-free voting based on homomorphic encryption.

impl ReencProofInput {
    pub fn reenc_in_list_1_out_of_l_prove(
        &self,
        pp: &ElGamalPP,
        pk: &ElGamalPublicKey,
        chosen_ciphertext_index: usize,
        eta: BigInt,
        l: usize,
    ) -> ReencProof {
        if self.c_list.len() != l {
            panic!("Size of the list doesn't match the specified list length l")
        }
        if *pp != pk.pp {
            panic!("mismatch pp");
        }
        if chosen_ciphertext_index >= l {
            panic! {"t must be smaller than the size of the list"}
        }
        let mut list_d_i = Vec::with_capacity(l);
        let mut list_r_i = Vec::with_capacity(l);
        let mut list_a_i = Vec::with_capacity(l);
        let mut list_b_i = Vec::with_capacity(l);

        for _ in 0..l {
            list_d_i.push(BigInt::sample_below(&pp.q));
            list_r_i.push(BigInt::sample_below(&pp.q));
        }
        let mut u_i: &BigInt;
        let mut v_i: &BigInt;
        for i in 0..l {
            u_i = &self.c_list[i].c1;
            v_i = &self.c_list[i].c2;
            list_a_i.push(BigInt::mod_floor(
                &(div_and_pow(&self.c.c1, u_i, &list_d_i[i], &pp.p)
                    * BigInt::mod_pow(&pp.g, &list_r_i[i], &pp.p)),
                &pp.p,
            ));
            list_b_i.push(BigInt::mod_floor(
                &(div_and_pow(&self.c.c2, v_i, &list_d_i[i], &pp.p)
                    * BigInt::mod_pow(&pk.h, &list_r_i[i], &pp.p)),
                &pp.p,
            ));
        }

        let mut e = {
            let mut e_vec = Vec::new();
            e_vec.push(&self.c.c1);
            e_vec.push(&self.c.c2);
            for e in self.c_list.iter() {
                e_vec.push(&e.c1);
            }
            for e in self.c_list.iter() {
                e_vec.push(&e.c2);
            }
            e_vec
        };

        e.extend(list_a_i.iter());
        e.extend(list_b_i.iter());
        // println!("e:{:#?}", e);

        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(&e), &pp.q);
        let w = BigInt::mod_floor(
            &(&eta * &list_d_i[chosen_ciphertext_index] + &list_r_i[chosen_ciphertext_index]),
            &pp.q,
        );
        let sum: BigInt = list_d_i
            .iter()
            .fold(BigInt::zero(), |a, b| a + b)
            .mod_floor(&pp.q);
        let tmp = (sum - &list_d_i[chosen_ciphertext_index]).mod_floor(&pp.q);
        list_d_i[chosen_ciphertext_index] = BigInt::mod_floor(&(c - tmp), &pp.q);
        list_r_i[chosen_ciphertext_index] =
            BigInt::mod_floor(&(&w - &eta * &list_d_i[chosen_ciphertext_index]), &pp.q);
        ReencProof {
            d: list_d_i.try_into().unwrap(),
            r: list_r_i.try_into().unwrap(),
        }
    }

    pub fn reenc_1_out_of_l_verifier(
        &self,
        pp: &ElGamalPP,
        pk: &ElGamalPublicKey,
        proof: &ReencProof,
        l: usize,
    ) -> bool {
        let mut list_a_i = Vec::with_capacity(l);
        let mut list_b_i = Vec::with_capacity(l);

        let mut u_i: &BigInt;
        let mut v_i: &BigInt;
        for i in 0..l {
            u_i = &self.c_list[i].c1;
            v_i = &self.c_list[i].c2;
            list_a_i.push(BigInt::mod_floor(
                &(div_and_pow(&self.c.c1, &u_i, &proof.d[i], &pp.p)
                    * BigInt::mod_pow(&pp.g, &proof.r[i], &pp.p)),
                &pp.p,
            ));
            list_b_i.push(BigInt::mod_floor(
                &(div_and_pow(&self.c.c2, &v_i, &proof.d[i], &pp.p)
                    * BigInt::mod_pow(&pk.h, &proof.r[i], &pp.p)),
                &pp.p,
            ));
        }

        let mut e = {
            let mut e_vec = Vec::new();
            e_vec.push(&self.c.c1);
            e_vec.push(&self.c.c2);
            for e in self.c_list.iter() {
                e_vec.push(&e.c1);
            }
            for e in self.c_list.iter() {
                e_vec.push(&e.c2);
            }
            e_vec
        };

        e.extend(list_a_i.iter());
        e.extend(list_b_i.iter());
        //    println!("e:{:#?}", e);

        let c = hash_sha256::HSha256::create_hash(&e).mod_floor(&pp.q);
        let sum: BigInt = proof.d.iter().fold(BigInt::zero(), |a, b| a + b);
        let d = sum.mod_floor(&pp.q);
        return c == d;
    }

    // The following function proves that c=(u,v) is an encryption of some c_t (for a private t) in a list of ciphers c_1,...,c_l (See PROTOCOL: Reencpf in Civitas)
    pub fn reenc_out_of_list_1_out_of_l_prove(
        &self,
        pp: &ElGamalPP,
        pk: &ElGamalPublicKey,
        chosen_ciphertext_index: usize,
        r: BigInt,
        l: usize,
    ) -> ReencProof {
        if self.c_list.len() != l {
            panic!("Size of the list doesn't match the specified list length l")
        }
        if *pp != pk.pp {
            panic!("mismatch pp");
        }
        if chosen_ciphertext_index >= l {
            panic! {"t must be smaller than the size of the list"}
        }
        let mut list_d_i = Vec::with_capacity(l);
        let mut list_r_i = Vec::with_capacity(l);
        let mut list_a_i = Vec::with_capacity(l);
        let mut list_b_i = Vec::with_capacity(l);

        for _ in 0..l {
            list_d_i.push(BigInt::sample_below(&pp.q));
            list_r_i.push(BigInt::sample_below(&pp.q));
        }
        let mut u_i: &BigInt;
        let mut v_i: &BigInt;
        for i in 0..l {
            u_i = &self.c_list[i].c1;
            v_i = &self.c_list[i].c2;
            list_a_i.push(BigInt::mod_floor(
                &(div_and_pow(&self.c.c1, u_i, &list_d_i[i], &pp.p)
                    * BigInt::mod_pow(&pp.g, &list_r_i[i], &pp.p)),
                &pp.p,
            ));
            list_b_i.push(BigInt::mod_floor(
                &(div_and_pow(&self.c.c2, v_i, &list_d_i[i], &pp.p)
                    * BigInt::mod_pow(&pk.h, &list_r_i[i], &pp.p)),
                &pp.p,
            ));
        }

        let mut e = {
            let mut e_vec = Vec::new();
            e_vec.push(&self.c.c1);
            e_vec.push(&self.c.c2);
            for e in self.c_list.iter() {
                e_vec.push(&e.c1);
            }
            for e in self.c_list.iter() {
                e_vec.push(&e.c2);
            }
            e_vec
        };

        e.extend(list_a_i.iter());
        e.extend(list_b_i.iter());
        // println!("e:{:#?}", e);

        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(&e), &pp.q);
        //a^t = g^(-r*d_t +r_t)
        //w = -r * d_t + r_t ==> a^t = g^w
        // d_t_new =c - (sum(d_i) - d_t)
        // r_t_new = w + r * d_t_new
        let w = BigInt::mod_floor(
            &(&r.clone().neg() * &list_d_i[chosen_ciphertext_index]
                + &list_r_i[chosen_ciphertext_index]),
            &pp.q,
        );
        let sum: BigInt = list_d_i
            .iter()
            .fold(BigInt::zero(), |a, b| a + b)
            .mod_floor(&pp.q);
        let tmp = (sum - &list_d_i[chosen_ciphertext_index]).mod_floor(&pp.q);
        let d_t_new = BigInt::mod_floor(&(c - tmp), &pp.q);
        let r_t_new = (w + &r * &d_t_new).mod_floor(&pp.q);
        list_d_i[chosen_ciphertext_index] = d_t_new;
        list_r_i[chosen_ciphertext_index] = r_t_new;
        ReencProof {
            d: list_d_i.try_into().unwrap(),
            r: list_r_i.try_into().unwrap(),
        }
    }
}

impl<'a> DvrpPublicInput<'a> {
    pub fn create_input(
        voter_public_key: &'a BigInt,
        prover_public_key: &'a BigInt,
        e: &'a ElGamalCiphertext,
        e_tag: &'a ElGamalCiphertext,
    ) -> Self {
        Self {
            voter_public_key,
            prover_public_key,
            e,
            e_tag,
        }
    }
}

impl VotepfPublicInput {
    pub fn votepf_prover(&self, witness: VoteWitness, params: &SystemParameters) -> VotepfProof {
        let r1 = BigInt::sample_below(&params.pp.q);
        let r2 = BigInt::sample_below(&params.pp.q);
        let mut e = vec![
            &params.pp.g,
            &self.encrypted_credential.c1,
            &self.encrypted_credential.c2,
            &self.encrypted_choice.c1,
            &self.encrypted_choice.c2,
            &self.eid,
        ];
        let pre_hash_1 = BigInt::mod_pow(&params.pp.g, &r1, &params.pp.p);
        let pre_hash_2 = BigInt::mod_pow(&params.pp.g, &r2, &params.pp.p);
        e.push(&pre_hash_1);
        e.push(&pre_hash_2);
        //        println!("e = {:#?}", e);
        let c = hash_sha256::HSha256::create_hash(&e).mod_floor(&params.pp.q);
        let s1 = (r1 - &c * witness.alpha_1).mod_floor(&params.pp.q);
        let s2 = (r2 - &c * witness.alpha_2).mod_floor(&params.pp.q);
        VotepfProof { c, s1, s2 }
    }
}
impl VotepfProof {
    pub fn votepf_verifier(&self, input: &VotepfPublicInput, params: &SystemParameters) -> bool {
        let mut e = vec![
            &params.pp.g,
            &input.encrypted_credential.c1,
            &input.encrypted_credential.c2,
            &input.encrypted_choice.c1,
            &input.encrypted_choice.c2,
            &input.eid,
        ];
        let pre_hash_1 = (BigInt::mod_pow(&params.pp.g, &self.s1, &params.pp.p)
            * BigInt::mod_pow(&input.encrypted_credential.c1, &self.c, &params.pp.p))
        .mod_floor(&params.pp.p);
        let pre_hash_2 = (BigInt::mod_pow(&params.pp.g, &self.s2, &params.pp.p)
            * BigInt::mod_pow(&input.encrypted_choice.c1, &self.c, &params.pp.p))
        .mod_floor(&params.pp.p);
        e.push(&pre_hash_1);
        e.push(&pre_hash_2);
        //   println!("e = {:#?}", e);
        let c = hash_sha256::HSha256::create_hash(&e).mod_floor(&params.pp.q);
        self.c == c
    }
}
#[allow(dead_code)]
pub fn dvrp_prover<E: Entity>(entity: &E, dvrp_input: &DvrpPublicInput, eta: BigInt) -> DvrpProof {
    //let d = BigInt::from(3);
    let w = BigInt::from(2);
    //let r = BigInt::from(5);
    let d = BigInt::sample_below(&entity.get_q());
    //let w = BigInt::sample_below(&entity.get_q());
    let r = BigInt::sample_below(&entity.get_q());
    let a = BigInt::mod_pow(&entity.get_generator(), &d, &entity.get_p());
    let b = BigInt::mod_pow(&dvrp_input.prover_public_key, &d, &entity.get_p());
    let s = BigInt::mod_mul(
        &BigInt::mod_pow(&entity.get_generator(), &w, &entity.get_p()),
        &BigInt::mod_pow(&dvrp_input.voter_public_key, &r, &entity.get_p()),
        &entity.get_p(),
    );
    let c = BigInt::mod_floor(
        &hash_sha256::HSha256::create_hash(&[
            &dvrp_input.e.c1,
            &dvrp_input.e.c2,
            &dvrp_input.e_tag.c1,
            &dvrp_input.e_tag.c2,
            &a,
            &b,
            &s,
        ]),
        &entity.get_q(),
    );

    let u = (&d + &eta * (&c + &w)).mod_floor(&entity.get_q());
    DvrpProof { c, w, r, u }
}

pub fn dvrp_verifier<E: Entity>(
    entity: &E,
    dvrp_input: &DvrpPublicInput,
    dvrp_proof: &DvrpProof,
) -> bool {
    //a′ = g^u/(x′/x)^(c+w) mod p
    let x = dvrp_input.e.c1.clone();
    let y = dvrp_input.e.c2.clone();
    let x_tag = dvrp_input.e_tag.c1.clone();
    let y_tag = dvrp_input.e_tag.c2.clone();
    let h = dvrp_input.prover_public_key;
    let a_tag: BigInt = (BigInt::mod_pow(&entity.get_generator(), &dvrp_proof.u, &entity.get_p())
        * BigInt::mod_inv(
            &div_and_pow(
                &x,
                &x_tag,
                &(&dvrp_proof.c + &dvrp_proof.w),
                &entity.get_p(),
            ),
            &entity.get_p(),
        ))
    .mod_floor(&entity.get_p());
    let _nom = BigInt::mod_pow(&entity.get_generator(), &dvrp_proof.u, &entity.get_p());
    let _denom = div_and_pow(
        &x,
        &x_tag,
        &(&dvrp_proof.c + &dvrp_proof.w),
        &entity.get_p(),
    );
    let b_tag: BigInt = (BigInt::mod_pow(&h, &dvrp_proof.u, &entity.get_p())
        * BigInt::mod_inv(
            &div_and_pow(
                &y,
                &y_tag,
                &(&dvrp_proof.c + &dvrp_proof.w),
                &entity.get_p(),
            ),
            &entity.get_p(),
        ))
    .mod_floor(&entity.get_p());
    let s_tag = BigInt::mod_mul(
        &BigInt::mod_pow(&entity.get_generator(), &dvrp_proof.w, &entity.get_p()),
        &BigInt::mod_pow(&dvrp_input.voter_public_key, &dvrp_proof.r, &entity.get_p()),
        &entity.get_p(),
    );

    let c_tag = BigInt::mod_floor(
        &hash_sha256::HSha256::create_hash(&[&x, &y, &x_tag, &y_tag, &a_tag, &b_tag, &s_tag]),
        &entity.get_q(),
    );
    // println!("dvrp verifier {:#?}", [&x, &y,&x_tag, &y_tag, &a_tag, &b_tag, &s_tag]);

    c_tag == dvrp_proof.c
}

pub fn fakedvrp_prover(voter: &Voter, dvrp_input: &DvrpPublicInput) -> DvrpProof {
    let x = &dvrp_input.e.c1;
    let y = &dvrp_input.e.c2;
    let x_tag = &dvrp_input.e_tag.c1;
    let y_tag = &dvrp_input.e_tag.c2;
    let alpha = BigInt::sample_below(&voter.get_q());
    let beta = BigInt::sample_below(&voter.get_q());
    let u_tilde = BigInt::sample_below(&voter.get_q());
    let a_tilde: BigInt = (BigInt::mod_pow(&voter.get_generator(), &u_tilde, &voter.get_p())
        * BigInt::mod_inv(
            &div_and_pow(&x, &x_tag, &alpha, &voter.get_p()),
            &voter.get_p(),
        ))
    .mod_floor(&voter.get_p());
    let b_tilde: BigInt =
        (BigInt::mod_pow(&dvrp_input.prover_public_key, &u_tilde, &voter.get_p())
            * BigInt::mod_inv(
                &div_and_pow(&y, &y_tag, &alpha, &voter.get_p()),
                &voter.get_p(),
            ))
        .mod_floor(&voter.get_p());
    let s_tilde = BigInt::mod_pow(&voter.get_generator(), &beta, &voter.get_p());
    let c_tilde = BigInt::mod_floor(
        &hash_sha256::HSha256::create_hash(&[&x, &y, &x_tag, &y_tag, &a_tilde, &b_tilde, &s_tilde]),
        &voter.get_q(),
    );
    // println!("dvrp fake prover {:#?}", [&x, &y,&x_tag, &y_tag,  &a_tilde, &b_tilde, &s_tilde]);
    let w_tilde = (&alpha - &c_tilde).mod_floor(&voter.get_q());
    let r_tilde = (&(&(&beta - &w_tilde)
        * BigInt::mod_inv(&voter.designation_key_pair.sk.x, &voter.get_q())))
        .mod_floor(&voter.get_q());
    DvrpProof {
        c: c_tilde,
        w: w_tilde,
        r: r_tilde,
        u: u_tilde,
    }
}
