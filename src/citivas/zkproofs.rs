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
use crate::citivas::Entity::Entity;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProofInput{
    pub(crate) C_list : Vec<ElGamalCiphertext>,//list of candidate for encryption
    pub(crate) c : ElGamalCiphertext,
 }

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencProof{
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
    pub(crate) encrypted_credential: ElGamalCiphertext,
    pub(crate) encrypted_choice: ElGamalCiphertext,
    pub eid: BigInt //election identifier,
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VotePfProof{
    c:BigInt,
    s1:BigInt,
    s2:BigInt
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VoteWitness{
    pub(crate) alpha_1: BigInt,
    pub(crate) alpha_2: BigInt
}




#[derive(Clone, PartialEq, Debug)]
pub struct DVRP_Public_Input<'a> { //stands for designated-verifier reencryption proof
    pub e: &'a ElGamalCiphertext,
    pub e_tag: &'a ElGamalCiphertext, //El-Gamal reencyption of e
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DVRP_Proof{ //stands for designated-verifier reencryption proof
c: BigInt,
    w: BigInt,
    r: BigInt,
    u: BigInt,
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
fn div_and_pow(denom: &BigInt, nom: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(nom * BigInt::mod_inv(&denom, &p)), &c, &p)
}

impl VotePfPublicInput{
    pub fn generateRandomInput(pp: &ElGamalPP, witness: &VoteWitness)-> Self{
        let  a1: BigInt = BigInt::mod_pow(&pp.g, &witness.alpha_1, &pp.p);
        let  a2: BigInt = BigInt::mod_pow(&pp.g, &witness.alpha_2, &pp.p);
        let  b1: BigInt = BigInt::sample_below(&pp.p);
        let  b2: BigInt = BigInt::sample_below(&pp.p);
        let e1 = ElGamalCiphertext{
            c1: a1,
            c2: b1,
            pp: pp.clone()
        };
        let e2 = ElGamalCiphertext{
            c1: a2,
            c2: b2,
            pp: pp.clone()
        };
        let  ctx: BigInt = BigInt::sample_below(&pp.p);
        Self{
            encrypted_credential: e1,
            encrypted_choice: e2,
            eid: ctx}
    }
}


// The following function proves the there is some c_t (for a private t) in c_1,...,c_l that is
// an encryption of some cipher text c=(u,v)
// The following function is an attempt to implement [1] with Fiat-Shamir heuristic
// L is the number of candidate of encryption and t stands for index of the real encrypted message.
// Eta is the value that encrypts the message (represented by r in Civitas)
// [1]: Hirt, Sako: Efficient receipt-free voting based on homomorphic encryption.

impl ReencProofInput {
    pub fn reenc_1_out_of_L_prove(&self, pp: &ElGamalPP, pk: &ElGamalPublicKey, chosen_ciphertext_index: usize, eta: BigInt, L: usize) -> ReencProof {
        if self.C_list.len() != L {
            panic!("Size of the list doesn't match the specified list length L")
        }
        if *pp != pk.pp {
            panic!("mismatch pp");
        }
        if chosen_ciphertext_index >= L {
            panic! {"t must be smaller than the size of the list"}
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
            list_a_i.push(BigInt::mod_floor(&(div_and_pow( &self.c.c1, u_i,&list_d_i[i], &pp.p) *
                BigInt::mod_pow(&pp.g, &list_r_i[i], &pp.p)), &pp.p));
            list_b_i.push(BigInt::mod_floor(&(div_and_pow( &self.c.c2, v_i,&list_d_i[i], &pp.p) *
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
       // println!("E:{:#?}", E);

        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &E)
                                  , &pp.q);
        let w = BigInt::mod_floor(&(&eta * &list_d_i[chosen_ciphertext_index]
            + &list_r_i[chosen_ciphertext_index]), &pp.q);
        let sum: BigInt = list_d_i.iter().fold(BigInt::zero(), |a, b| a + b).mod_floor(&pp.q);
        let tmp = (sum - &list_d_i[chosen_ciphertext_index]).mod_floor(&pp.q);
        list_d_i[chosen_ciphertext_index] = BigInt::mod_floor(&(c - tmp)
                                        , &pp.q);
        list_r_i[chosen_ciphertext_index] =
            BigInt::mod_floor(&(&w - &eta * &list_d_i[chosen_ciphertext_index]), &pp.q);
        ReencProof { D: list_d_i.try_into().unwrap(), R: list_r_i.try_into().unwrap() }
    }

    pub fn reenc_1_out_of_L_verifier(&self, pp: &ElGamalPP, pk: &ElGamalPublicKey, proof: ReencProof, L: usize) -> bool {
        let mut list_a_i = Vec::with_capacity(L);
        let mut list_b_i = Vec::with_capacity(L);

        let mut u_i: &BigInt;
        let mut v_i: &BigInt;
        for i in 0..L {
            u_i = &self.C_list[i].c1;
            v_i = &self.C_list[i].c2;
            list_a_i.push(BigInt::mod_floor(&(div_and_pow( &self.c.c1, &u_i,&proof.D[i], &pp.p) *
                BigInt::mod_pow(&pp.g, &proof.R[i], &pp.p)), &pp.p));
            list_b_i.push(BigInt::mod_floor(&(div_and_pow(&self.c.c2, &v_i, &proof.D[i], &pp.p) *
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
    //    println!("E:{:#?}", E);

        let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&pp.q);
        let sum: BigInt = proof.D.iter().fold(BigInt::zero(), |a, b| a + b);
        let D = sum.mod_floor(&pp.q);
        return c == D
    }
}

impl <'a> DVRP_Public_Input<'a>{
    pub fn create_input(e: &'a ElGamalCiphertext, e_tag: &'a ElGamalCiphertext)-> Self{
        Self{e,e_tag}
    }
}


impl VotePfPublicInput {
    pub fn votepf_prover(&self, voter: &Voter, witness: VoteWitness) -> VotePfProof {
        let r1 = BigInt::sample_below(&voter.pp.q);
        let r2 = BigInt::sample_below(&voter.pp.q);
        let mut E = vec![&voter.pp.g, &self.encrypted_credential.c1, &self.encrypted_credential.c2, &self.encrypted_choice.c1, &self.encrypted_choice.c2, &self.eid];
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
            let mut E = vec![&voter.pp.g, &input.encrypted_credential.c1, &input.encrypted_credential.c2, &input.encrypted_choice.c1, &input.encrypted_choice.c2, &input.eid];
            let pre_hash_1 = (BigInt::mod_pow(&voter.pp.g, &self.s1, &voter.pp.p) *
                BigInt::mod_pow(&input.encrypted_credential.c1, &self.c, &voter.pp.p)).mod_floor(&voter.pp.p);
            let pre_hash_2 = (BigInt::mod_pow(&voter.pp.g, &self.s2, &voter.pp.p) *
                BigInt::mod_pow(&input.encrypted_choice.c1, &self.c, &voter.pp.p)).mod_floor(&voter.pp.p);
            E.push(&pre_hash_1);
            E.push(&pre_hash_2);
         //   println!("E = {:#?}", E);
            let c = hash_sha256::HSha256::create_hash(&E).mod_floor(&voter.pp.q);
            self.c == c
        }
}





pub fn DVRP_prover<E: Entity>(entity: &E, dvrp_input: &DVRP_Public_Input, eta: BigInt) -> DVRP_Proof {
    //let d = BigInt::from(3);
    let w = BigInt::from(2);
    //let r = BigInt::from(5);
    let d = BigInt::sample_below(&entity.get_q());
    //let w = BigInt::sample_below(&entity.get_q());
    let r = BigInt::sample_below(&entity.get_q());
    let a = BigInt::mod_pow(&entity.get_generator(), &d, &entity.get_p());
    let b = BigInt::mod_pow(&entity.get_pk(), &d, &entity.get_p());
    let s = BigInt::mod_mul(&BigInt::mod_pow(&entity.get_generator(), &w, &entity.get_p()),
                            &BigInt::mod_pow(&entity.get_pk(), &r, &entity.get_p()),
                            &entity.get_p());
    let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
        &[&dvrp_input.e.c1, &dvrp_input.e.c2,&dvrp_input.e_tag.c1, &dvrp_input.e_tag.c2, &a, &b, &s]
    ), &entity.get_q());

    let u = (&d + &eta * (&c + &w)).mod_floor(&entity.get_q());
    DVRP_Proof { c, w, r, u }
}


pub fn DVRP_verifier<E: Entity>(entity: &E, dvrp_input: &DVRP_Public_Input, dvrp_proof: &DVRP_Proof) -> bool {
    //a′ = g^u/(x′/x)^(c+w) mod p
    let x = dvrp_input.e.c1.clone();
    let y = dvrp_input.e.c2.clone();
    let x_tag = dvrp_input.e_tag.c1.clone();
    let y_tag = dvrp_input.e_tag.c2.clone();
    let h = entity.get_pk();
    let a_tag: BigInt = (BigInt::mod_pow(&entity.get_generator(), &dvrp_proof.u, &entity.get_p()) *
        BigInt::mod_inv(&div_and_pow(&x, &x_tag, &(&dvrp_proof.c + &dvrp_proof.w), &entity.get_p())
                        , &entity.get_p())).mod_floor(&entity.get_p());
    let nom = BigInt::mod_pow(&entity.get_generator(), &dvrp_proof.u, &entity.get_p());
    let denom = div_and_pow(&x, &x_tag, &(&dvrp_proof.c + &dvrp_proof.w), &entity.get_p());
    let b_tag: BigInt = (BigInt::mod_pow(&h, &dvrp_proof.u, &entity.get_p()) *
        BigInt::mod_inv(&div_and_pow(&y, &y_tag, &(&dvrp_proof.c + &dvrp_proof.w), &entity.get_p())
                        , &entity.get_p())).mod_floor(&entity.get_p());
    let s_tag = BigInt::mod_mul(&BigInt::mod_pow(&entity.get_generator(), &dvrp_proof.w, &entity.get_p()),
                                &BigInt::mod_pow(&entity.get_pk(), &dvrp_proof.r, &entity.get_p()),
                                &entity.get_p());

    let c_tag = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
        &[&x, &y, &x_tag, &y_tag, &a_tag, &b_tag, &s_tag]
    ), &entity.get_q());
    println!("dvrp verifier {:#?}", [&x, &y,&x_tag, &y_tag, &a_tag, &b_tag, &s_tag]);

    c_tag == dvrp_proof.c
}

pub fn fakeDVRP_prover(voter: &Voter, dvrp_input: &DVRP_Public_Input) -> DVRP_Proof {
    let x = &dvrp_input.e.c1;
    let y = &dvrp_input.e.c2;
    let x_tag = &dvrp_input.e_tag.c1;
    let y_tag = &dvrp_input.e_tag.c2;
    let alpha = BigInt::sample_below(&voter.get_q());
    let beta = BigInt::sample_below(&voter.get_q());
    let u_tilde = BigInt::sample_below(&voter.get_q());
    let a_tilde: BigInt = (BigInt::mod_pow(&voter.get_generator(), &u_tilde, &voter.get_p()) *
        BigInt::mod_inv(&div_and_pow(&x, &x_tag, &alpha, &voter.get_p())
                        , &voter.get_p())).mod_floor(&voter.get_p());
    let b_tilde: BigInt = (BigInt::mod_pow(&voter.get_pk(), &u_tilde, &voter.get_p()) *
        BigInt::mod_inv(&div_and_pow(&y, &y_tag, &alpha, &voter.get_p())
                        , &voter.get_p())).mod_floor(&voter.get_p());
    let s_tilde = BigInt::mod_pow(&voter.get_generator(), &beta, &voter.get_p());
    let c_tilde = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
        &[&x, &y, &x_tag, &y_tag, &a_tilde, &b_tilde, &s_tilde]
    ), &voter.get_q());
    // println!("dvrp fake prover {:#?}", [&x, &y,&x_tag, &y_tag,  &a_tilde, &b_tilde, &s_tilde]);
    let w_tilde = (&alpha - &c_tilde).mod_floor( &voter.get_q());
    let r_tilde = (&(&(&beta - &w_tilde) * BigInt::mod_inv(&voter.designation_key_pair.sk.x, &voter.get_q())))
        .mod_floor( &voter.get_q());
    DVRP_Proof{
        c: c_tilde,
        w: w_tilde,
        r: r_tilde,
        u: u_tilde
    }
}


