use curv::BigInt;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalCiphertext, ElGamalError, ElGamalKeyPair,
    ElGamalPP, ElGamalPrivateKey, ElGamalPublicKey, ExponentElGamal,
};

use crate::citivas::encryption_schemes::{reencrypt, ElGamalCipherTextAndPK};
use curv::arithmetic::traits::Samplable;
use serde::{Deserialize, Serialize};

use crate::citivas::zkproofs::{DVRP_Proof, DVRP_Public_Input, DVRP_prover, DVRP_verifier};
use crate::citivas::Entity::Entity;
use crate::citivas::superviser::SystemParameters;
use crate::citivas::voter::Voter;
//use crate::macros;

pub struct RegistrationTeller {
    KTT: BigInt, // Tabulate tellers public keys (yes not registration tellers!)
    CredentialShare: Vec<CredentialShare>,
}

pub struct Registrar {
    registrar_index: usize,
    pp: ElGamalPP,
    //key_pair: ElGamalKeyPair,
    num_of_voters: usize,
    KTT: ElGamalPublicKey, //PK of the tellers (tally tellers)
    cred_vec: Vec<CredentialShare>,
}

impl Entity for Registrar {
    fn get_pp(&self) -> &ElGamalPP {
        &self.pp
    }

    fn get_pk(&self) -> &BigInt {
        &self.KTT.h
    }

    fn get_p(&self) -> &BigInt {
        &self.pp.p
    }

    fn get_q(&self) -> &BigInt {
        &self.pp.q
    }

    fn get_tally_pk(&self) -> &ElGamalPublicKey {
        &self.KTT
    }

    fn get_generator(&self) -> &BigInt {
        &self.pp.g
    }
}

impl Registrar {
    pub fn create(
        registrar_index: usize,
        pp: &ElGamalPP,
        num_of_voters: usize,
        KTT: ElGamalPublicKey,
    ) -> Self {
        //PK of the tellers (tally tellers)
        Self {
            registrar_index,
            pp: pp.clone(),
            //key_pair,
            num_of_voters,
            KTT,
            cred_vec: vec![],
        }
    }

    pub fn create_toy(
        registrar_index: usize,
        pp: &ElGamalPP,
        num_of_voters: usize,
        KTT: ElGamalPublicKey,
    ) -> Self {
        //PK of the tellers (tally tellers)
        Self {
            registrar_index,
            pp: pp.clone(),
            //key_pair,
            num_of_voters,
            KTT,
            cred_vec: vec![],
        }
    }
}

#[derive(Debug)]
pub struct CredentialShare {
    pub s_i: BigInt,                //private credential share
    pub S_i: ElGamalCiphertext,     // Public credential share
    pub S_i_tag: ElGamalCiphertext, // Public credential share
    pub r_i: BigInt,                // randomness for encrypting S_i_tag
    pub eta: BigInt,                // randomness for reencryption to obtain S_i
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CredetialShareOutput {
    pub s_i: BigInt,                //private credential share
    pub S_i_tag: ElGamalCiphertext, // Public credential share
    pub r_i: BigInt,                // randomness for encrypting S_i_tag
    pub dvrp_proof: DVRP_Proof,
    pub dvrp_prover_pk: BigInt,
}

impl CredetialShareOutput {
    pub fn get_dvrp_input<'a>(
        &'a self,
        voter_pk: &'a BigInt,
        S_i: &'a ElGamalCiphertext,
    ) -> DVRP_Public_Input<'a> {
        DVRP_Public_Input {
            voter_public_key: voter_pk,
            prover_public_key: &self.dvrp_prover_pk,
            e: &self.S_i_tag,
            e_tag: &S_i,
        }
    }
}

impl Registrar {
    pub fn create_credential_share(&self) -> CredentialShare {
        let pp = &self.pp.clone();
        let s_i = BigInt::sample_below(&pp.q);
        let r_i = BigInt::sample_below(&pp.q);
        let S_i_tag = ElGamal::encrypt_from_predefined_randomness(&s_i, &self.KTT, &r_i).unwrap();
        let eta = BigInt::sample_below(&pp.q);
        let S_i = reencrypt(
            &ElGamalCipherTextAndPK {
                ctx: S_i_tag.clone(),
                pk: &self.KTT,
            },
            &eta,
        );
        CredentialShare {
            s_i,
            S_i,
            S_i_tag,
            r_i,
            eta,
        }
    }

    pub fn create_credential_share_toy_1(&self) -> CredentialShare {
        let pp = &self.pp.clone();
        let s_i = BigInt::from(1);
        let r_i = BigInt::sample_below(&pp.q);
        let S_i_tag = ElGamal::encrypt_from_predefined_randomness(&s_i, &self.KTT, &r_i).unwrap();
        let eta = BigInt::sample_below(&pp.q);
        let S_i = reencrypt(
            &ElGamalCipherTextAndPK {
                ctx: S_i_tag.clone(),
                pk: &self.KTT,
            },
            &eta,
        );
        CredentialShare {
            s_i,
            S_i,
            S_i_tag,
            r_i,
            eta,
        }
    }

    pub fn create_credential_share_toy_2(&self) -> CredentialShare {
        let pp = &self.pp.clone();
        let s_i = BigInt::from(2);
        let r_i = BigInt::sample_below(&pp.q);
        let S_i_tag = ElGamal::encrypt_from_predefined_randomness(&s_i, &self.KTT, &r_i).unwrap();
        let eta = BigInt::sample_below(&pp.q);
        let S_i = reencrypt(
            &ElGamalCipherTextAndPK {
                ctx: S_i_tag.clone(),
                pk: &self.KTT,
            },
            &eta,
        );
        CredentialShare {
            s_i,
            S_i,
            S_i_tag,
            r_i,
            eta,
        }
    }

    //publish credential share (s_i, S'_i, r_i) and a DVRP proof that S_i is reenc of S_i
    pub fn publish_credential_with_proof(
        &self,
        cred_share: &CredentialShare,
        dvrp_input: DVRP_Public_Input,
    ) -> CredetialShareOutput {
        //  let cred_share = &self.cred_vec.get(voter_index).unwrap();
        // let dvrp_input = &DVRP_Public_Input{ e: &cred_share.S_i_tag, e_tag: &cred_share.S_i };
        let proof = DVRP_prover(self, &dvrp_input, cred_share.eta.clone());
        CredetialShareOutput {
            s_i: cred_share.s_i.clone(),
            S_i_tag: cred_share.S_i_tag.clone(),
            r_i: cred_share.r_i.clone(),
            dvrp_proof: proof,
            dvrp_prover_pk: dvrp_input.prover_public_key.clone(),
        }
    }
}

#[cfg(test)]
pub mod test_registrar{
use super::*;
    #[test]

//This checks using DVRP that S’_i is a reencryption of S_i using DVRP
pub fn check_credential_proof() {
    let group_id = SupportedGroups::FFDHE4096;
    let pp = &ElGamalPP::generate_from_rfc7919(group_id);
    let params = &SystemParameters::create_supervisor(&pp);
    let registrar = Registrar::create(0, pp, params.num_of_voters.clone(), params.KTT.clone());
    let share = registrar.create_credential_share();
    let voter_pk = &Voter::create(1, params).designation_key_pair.pk.h;
    let dvrp_input =
        DVRP_Public_Input::create_input(voter_pk, registrar.get_pk(), &share.S_i_tag, &share.S_i);
    let cred_share_output = registrar.publish_credential_with_proof(&share, dvrp_input.clone());
    let check = DVRP_verifier(&registrar, &dvrp_input, &cred_share_output.dvrp_proof);
    assert!(check)
}
}