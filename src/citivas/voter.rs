use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey, ElGamalPublicKey};

use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;

use serde::{Deserialize, Serialize};

use crate::citivas::encryption_schemes::{
    encrypt_from_predefined_randomness, reencrypt, ElGamalCipherTextAndPK,
};

use crate::citivas::supervisor::SystemParameters;

use crate::citivas::entity::Entity;
use crate::citivas::registrar::CredetialShareOutput;
use crate::citivas::zkproofs::*;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Voter {
    pub designation_key_pair: ElGamalKeyPair,
    voter_number: usize,
    ktt: ElGamalPublicKey, //public key of the tally tellers
    private_credential: Option<BigInt>,
    pub(crate) pp: ElGamalPP,
    chosen_candidate: Option<i8>, //the vote itself
    nonce_for_candidate_encryption: BigInt,
    eid: i32,
    encrypted_candidate_list: Vec<ElGamalCiphertext>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub(crate) es: ElGamalCiphertext, //encryption of the private credential
    pub(crate) ev: ElGamalCiphertext, //reencryption of the ciphertext, i.e., c_i is the encryption of the vote and ev is an encryption of c_i
    pub(crate) pf: VotepfProof, //a proof that shows that the voter knows the private credential and the vote
    // (This defends against an adversary who attempts to post functions of previously cast votes.)
    pub(crate) pw: ReencProof, //a proof that shows ev is an encryption of one cipher (c_i) in the list of L candidates
}

impl Voter {
    //The following function is used for debugging

    pub fn simple_create(voter_number: usize, pp: ElGamalPP) -> Self {
        let key_pair = ElGamalKeyPair::generate(&pp);
        //  let key_pair= ElGamalKeyPair{ pk: ElGamalPublicKey { pp:pp.clone(), h: BigInt::from(13) }, sk: ElGamalPrivateKey{ pp:pp.clone(), x: BigInt::from(29) } };
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp: pp.clone(),
            private_credential: None,
            nonce_for_candidate_encryption: BigInt::zero(),
            ktt: ElGamalPublicKey {
                pp: pp.clone(),
                h: BigInt::one(),
            },
            chosen_candidate: None,
            eid: 0,
            encrypted_candidate_list: Vec::new(),
        }
    }

    pub fn create(
        voter_number: usize,
        params: &SystemParameters,
        shared_pk: &ElGamalPublicKey,
    ) -> Self {
        if params.encrypted_candidate_list.is_none() {
            panic!("shared public must be set to the supervisor!");
        }
        let key_pair = ElGamalKeyPair::generate(&params.pp);
        //  let key_pair= ElGamalKeyPair{ pk: ElGamalPublicKey { pp:pp.clone(), h: BigInt::from(13) }, sk: ElGamalPrivateKey{ pp:pp.clone(), x: BigInt::from(29) } };
        Self {
            designation_key_pair: key_pair,
            voter_number,
            pp: params.pp.clone(),
            private_credential: None,
            nonce_for_candidate_encryption: params.nonce_for_candidate_encryption.clone(),
            ktt: shared_pk.clone(),
            chosen_candidate: None,
            eid: params.eid,
            encrypted_candidate_list: params.encrypted_candidate_list.clone().unwrap(),
        }
    }

    pub fn create_voter_from_given_sk(
        voter_number: usize,
        pp: ElGamalPP,
        x: BigInt,
        params: SystemParameters,
        public_key: ElGamalPublicKey,
    ) -> Self {
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
            ktt: public_key.clone(),
            chosen_candidate: None,
            eid: params.eid,
            encrypted_candidate_list: vec![],
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

    fn get_tally_pk(&self) -> &ElGamalPublicKey {
        &self.ktt
    }

    fn get_generator(&self) -> &BigInt {
        &self.pp.g
    }
}

impl Voter {
    //The voter need to verify that:
    // 1. S'_i = Enc(private_credential_i, r; ktt)
    // 2. S’_i is a reencryption of public_credential_i using dvrp, where public_credential_i is retrieved from the bulletin board
    pub fn verify_credentials(
        &self,
        cred_share: &CredetialShareOutput,
        public_credential_i: &ElGamalCiphertext, //comes from the bulletin board
    ) -> bool {
        let verification_1: bool = cred_share.public_credential_i_tag
            == encrypt_from_predefined_randomness(
                &cred_share.private_credential_i,
                &self.ktt,
                &cred_share.r_i,
            )
            .unwrap();
        let verification_2 = dvrp_verifier(
            self,
            &cred_share.get_dvrp_input(&self.designation_key_pair.pk.h, public_credential_i),
            &cred_share.dvrp_proof,
        );
        return verification_1 && verification_2;
    }

    pub fn construct_private_credential_from_shares(
        &mut self,
        received_credentials: Vec<CredetialShareOutput>,
        public_credential_i_vec: Vec<ElGamalCiphertext>,
    ) -> Option<BigInt> {
        let length = received_credentials.len();
        let cred_constructed_from_valid_shares = (0..length)
            .map(|registrar_index| received_credentials.get(registrar_index).unwrap())
            .enumerate()
            .filter(|(registrar_index, cred)| {
                self.verify_credentials(
                    cred,
                    public_credential_i_vec.get(*registrar_index).unwrap(),
                )
            })
            .map(|(_, cred)| cred.clone().private_credential_i)
            .fold(BigInt::zero(), |sum, i| sum + i);
        return if cred_constructed_from_valid_shares.is_zero() {
            None
        } else {
            Some(cred_constructed_from_valid_shares)
        }
    }

    pub fn set_private_credential(&mut self, private_cred: BigInt) {
        self.private_credential = Some(private_cred);
    }

    pub fn set_vote(mut self, candidate: i8) {
        self.chosen_candidate = Some(candidate);
    }

    pub fn vote(&self, candidate_index: usize, params: &SystemParameters) -> Vote {
        assert!(&self.private_credential.is_some());
        let nonce_for_encrypting_credentials = sample_from!(&self.get_q());
        let es = encrypt_from_predefined_randomness(
            &self.private_credential.clone().unwrap(),
            &self.ktt,
            &nonce_for_encrypting_credentials,
        )
        .unwrap(); //encryption of the credential
        let nonce_for_reecryption = BigInt::sample_below(&self.get_q());
        let ev = reencrypt(
            &ElGamalCipherTextAndPK {
                ctx: self
                    .encrypted_candidate_list
                    .get(candidate_index)
                    .unwrap()
                    .clone(),
                pk: &self.ktt,
            },
            &nonce_for_reecryption,
        ); //reencryption of the vote with the tellers public key
        let reenc_proof_input = ReencProofInput {
            c_list: self.encrypted_candidate_list.clone(),
            c: ev.clone(),
        };
        let pw = reenc_proof_input.reenc_out_of_list_1_out_of_l_prove(
            &self.get_pp(),
            &self.ktt,
            candidate_index,
            nonce_for_reecryption.clone(),
            params.num_of_candidates,
        );
        let vote_pf_input = VotepfPublicInput {
            encrypted_credential: es.clone(),
            encrypted_choice: ev.clone(),
            eid: BigInt::from(self.eid as i32),
        };
        let witness = VoteWitness {
            alpha_1: nonce_for_encrypting_credentials,
            alpha_2: &self.nonce_for_candidate_encryption + nonce_for_reecryption.clone(),
        };
        let pf = vote_pf_input.votepf_prover(witness, params);
        Vote { ev, es, pf, pw }
    }

    // Verify the proofs of votepf and reencryption
    // move function to tallies
    pub fn check_votes(voter: &Voter, vote: &Vote, params: &SystemParameters) -> bool {
        let vote_pf_input = VotepfPublicInput {
            encrypted_credential: vote.es.clone(),
            encrypted_choice: vote.ev.clone(),
            eid: BigInt::from(voter.eid),
        };
        let check_1 = vote.pf.votepf_verifier(&vote_pf_input, &params);
        let reenc_proof_input = ReencProofInput {
            c_list: voter.encrypted_candidate_list.clone(),
            c: vote.clone().ev,
        };
        let check_2 = reenc_proof_input.reenc_1_out_of_l_verifier(
            &voter.get_pp(),
            &voter.ktt,
            &vote.pw,
            params.num_of_candidates,
        );
        check_1 && check_2
    }
}
