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
use crate::citivas::superviser::{SystemParameters, NUMBER_OF_CANDIDATES};
use crate::citivas::superviser;
use crate::citivas::Entity::Entity;
use crate::citivas::zkproofs::*;
use crate::citivas::registrar;
use crate::citivas::registrar::{CredetialShareOutput, Registrar};


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Voter{
    pub designation_key_pair: ElGamalKeyPair,
    voter_number: usize,
    KTT: ElGamalPublicKey,//public key of the tally tellers
    private_credential: Option<BigInt>,
    pub(crate) pp:ElGamalPP,
    chosen_candidate: Option<i8>, //the vote itself
    nonce_for_candidate_encryption: BigInt,
    eid: i32,
    encrypted_candidate_list: Vec<ElGamalCiphertext>
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Vote{
    es: ElGamalCiphertext,//encryption of the private credential
    ev: ElGamalCiphertext,//reencryption of the ciphertext, i.e., c_i is the encryption of the vote and ev is an encryption of c_i
    pf: VotePfProof,//a proof that shows that the voter knows the private credential and the vote
    // (This defends against an adversary who attempts to post functions of previously cast votes.)
    pw: ReencProof,//a proof that shows ev is an encryption of one cipher (c_i) in the list of L candidates
}

//a technical function that computes (x/x')^c mod p
pub fn div_and_pow(x: &BigInt, x_tag: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(x_tag * BigInt::mod_inv(&x, &p)).mod_floor(&p), &c, &p)
}


impl Voter {
    //The following function is used for debugging

    pub fn simple_create(voter_number: usize, pp: ElGamalPP)-> Self{
        let key_pair = ElGamalKeyPair::generate(&pp);
        //  let key_pair= ElGamalKeyPair{ pk: ElGamalPublicKey { pp:pp.clone(), h: BigInt::from(13) }, sk: ElGamalPrivateKey{ pp:pp.clone(), x: BigInt::from(29) } };
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp: pp.clone(),
            private_credential: None,
            nonce_for_candidate_encryption: BigInt::zero(),
            KTT: ElGamalPublicKey{ pp: pp.clone(), h:BigInt::one() },
            chosen_candidate: None,
            eid: 0,
            encrypted_candidate_list: Vec::new()
        }
    }





    pub fn create(voter_number: usize, params: &SystemParameters) -> Self {
        let key_pair = ElGamalKeyPair::generate(&params.pp);
        //  let key_pair= ElGamalKeyPair{ pk: ElGamalPublicKey { pp:pp.clone(), h: BigInt::from(13) }, sk: ElGamalPrivateKey{ pp:pp.clone(), x: BigInt::from(29) } };
        let h_v = BigInt::sample_below(&params.pp.p);
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp: params.pp.clone(),
            private_credential: None,
            nonce_for_candidate_encryption: params.nonce_for_candidate_encryption.clone(),
            KTT: params.KTT.clone(),
            chosen_candidate: None,
            eid: params.eid,
            encrypted_candidate_list: params.encrypted_candidate_list.clone()
        }
    }

    pub fn create_voter_from_given_sk(voter_number: usize, pp: ElGamalPP, x: BigInt, params: SystemParameters) -> Self {
        let h = BigInt::mod_pow(&pp.g, &x, &pp.p);
        let pk = ElGamalPublicKey { pp: pp.clone(), h };
        let sk = ElGamalPrivateKey { pp: pp.clone(), x };
        let key_pair = ElGamalKeyPair { pk, sk };
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp: params.pp,
            private_credential: None,
            nonce_for_candidate_encryption: params.nonce_for_candidate_encryption,
            KTT: params.KTT,
            chosen_candidate: None,
            eid: params.eid,
            encrypted_candidate_list: vec![]
        }
    }
}


impl Entity for Voter {
    fn get_pp(&self) -> &ElGamalPP {
        &self.pp
    }


    fn get_pk(&self) -> &BigInt {
        &self.designation_key_pair.pk.h
    }

    /*
    fn get_sk(&self) -> &BigInt {
        &self.designation_key_pair.sk.x
    }
*/
    fn get_p(&self) -> &BigInt {
        &self.pp.p
    }

    fn get_q(&self) -> &BigInt {
        &self.pp.q
    }

    fn get_tally_pk(&self) -> &ElGamalPublicKey{
        &self.KTT
    }

    fn get_generator(&self) -> &BigInt {
        &self.pp.g
    }

}

impl Voter{
    //The voter need to verify that:
    // 1. S'_i = Enc(s_i, r; KTT)
    // 2. S’_i is a reencryption of S_i using DVRP, where S_i is retrieved from the bulletin board
    pub fn verify_credentials(&self, cred_share: &CredetialShareOutput, S_i: &ElGamalCiphertext//comes from the bulletin board
         ) -> bool {
        println!("Si= {:?}",S_i);
        let verification_1: bool =
            cred_share.S_i_tag ==
                ElGamal::encrypt_from_predefined_randomness(&cred_share.s_i, &self.KTT, &cred_share.r_i).unwrap();
        let verification_2 = DVRP_verifier(
            self, &cred_share.get_dvrp_input(&self.designation_key_pair.pk.h, S_i), &cred_share.dvrp_proof
        );
        return  verification_1 && verification_2
    }

    /*
    pub fn combine_shares( credential_private_shares: Vec<BigInt>) -> BigInt{
        credential_private_shares.iter().fold(
            BigInt::zero(), |sum, i | sum + i)
    }
*/


    pub fn construct_private_credential_from_shares(&mut self, received_credentials: Vec<CredetialShareOutput>, S_i_vec: Vec<ElGamalCiphertext>) -> Option<BigInt>{
        let length = received_credentials.len();
        let cred_constructed_from_valid_shares = (0..length)
            .map(|registrar_index|  received_credentials.get(registrar_index).unwrap())
            .enumerate()
            .filter(|(registrar_index, cred)|
                self.verify_credentials(cred, S_i_vec.get(*registrar_index).unwrap()))
            .map(|(_,cred)| cred.clone().s_i)
            .fold(BigInt::zero(), |sum, i | sum + i);
        Some(cred_constructed_from_valid_shares)
    }

    pub fn set_private_credential(&mut self, private_cred: BigInt){
        self.private_credential = Some(private_cred);
    }

    pub fn set_vote(mut self, candidate: i8){
        self.chosen_candidate = Some(candidate);
    }



    pub fn vote(&self,  candidate_index: usize, params: SystemParameters)-> Vote{
        assert!(&self.private_credential.is_some());
        let nonce_for_encrypting_credentials = sample_from!(&self.get_q());
        let nonce_for_encrypting_credentials = BigInt::from(3);
        println!("private cred: {:?}", &self.private_credential.clone().unwrap());
        let ev = ElGamal::encrypt_from_predefined_randomness(
            &self.private_credential.clone().unwrap(), &self.KTT, &nonce_for_encrypting_credentials)
            .unwrap();//encryption of the credential
       // let nonce_for_reecryption = BigInt::sample_below(&self.get_q());
         let nonce_for_reecryption = BigInt::from(7);

        let es =reencrypt(&ElGamalCipherTextAndPK {
            ctx: self.encrypted_candidate_list.get(candidate_index).unwrap().clone(),
            pk: &self.KTT
        },
            &nonce_for_reecryption
        );//reencryption of the vote with the tellers public key
        println!("es {:?}", es.clone());
        let reenc_proof_input = ReencProofInput{ C_list: self.encrypted_candidate_list.clone(), c: es.clone()};
        println!("{:#?}", reenc_proof_input.clone());
        let pw = reenc_proof_input.reenc_1_out_of_L_prove(
            &self.get_pp(), &self.KTT, candidate_index,
            nonce_for_reecryption.clone(), params.num_of_candidates);
        let vote_pf_input = VotePfPublicInput{
            encrypted_credential: ev.clone(),
            encrypted_choice: es.clone(),
            eid: BigInt::from(self.eid as i32)
        };
        let witness = VoteWitness{ alpha_1: nonce_for_encrypting_credentials, alpha_2: &self.nonce_for_candidate_encryption + nonce_for_reecryption};
        let pf = vote_pf_input.votepf_prover(&self, witness);
        Vote{ev, es, pf, pw}
    }

    // Verify the proofs of votepf and reencryption
    // move function to tallies
    pub fn check_votes(voter: &Voter, vote: Vote, params: &SystemParameters) -> bool{
        let vote_pf_input = VotePfPublicInput{
            encrypted_credential: vote.ev.clone(),
            encrypted_choice: vote.es.clone(),
            eid:BigInt::from(voter.eid)
        };
        let check_1 = vote.pf.votepf_verifier(&vote_pf_input,&voter);
      //  assert!(check_1);
        let reenc_proof_input = ReencProofInput{ C_list: voter.encrypted_candidate_list.clone(), c: vote.es.clone()};
        println!("C list: {:#?}",  reenc_proof_input);
        let check_2 = reenc_proof_input.reenc_1_out_of_L_verifier(
            &voter.get_pp(), &voter.KTT,vote.pw,params.num_of_candidates
        );
        assert!(check_2);
        check_1 && check_2
    }
}

