use curv::BigInt;

use crate::citivas::encryption_schemes::{reencrypt, ElGamalCipherTextAndPK};
use crate::citivas::entity::Entity;
use crate::citivas::supervisor::SystemParameters;
use crate::citivas::zkproofs::{dvrp_prover, DvrpProof, DvrpPublicInput};
use curv::arithmetic::traits::Samplable;
use elgamal::{ElGamal, ElGamalCiphertext, ElGamalPP, ElGamalPublicKey};
use serde::{Deserialize, Serialize};

//use crate::macros;

pub struct Registrar {
    #[allow(dead_code)]
    registrar_index: usize,
    params: SystemParameters,
    //key_pair: ElGamalKeyPair,
    ktt: ElGamalPublicKey, //PK of the tellers (tally tellers)
}

impl Entity for Registrar {
    fn get_pp(&self) -> &ElGamalPP {
        &self.params.pp
    }

    fn get_pk(&self) -> &BigInt {
        &self.ktt.h
    }

    fn get_p(&self) -> &BigInt {
        &self.params.pp.p
    }

    fn get_q(&self) -> &BigInt {
        &self.params.pp.q
    }

    fn get_tally_pk(&self) -> &ElGamalPublicKey {
        &self.ktt
    }

    fn get_generator(&self) -> &BigInt {
        &self.params.pp.g
    }
}

impl Registrar {
    pub fn create(registrar_index: usize, params: SystemParameters, ktt: ElGamalPublicKey) -> Self {
        //PK of the tellers (tally tellers)
        Self {
            registrar_index,
            params: params.clone(),
            //key_pair,
            ktt,
        }
    }
}

#[derive(Debug)]
pub struct CredentialShare {
    pub private_credential_i: BigInt, //private credential share
    pub public_credential_i: ElGamalCiphertext, // Public credential share
    pub public_credential_i_tag: ElGamalCiphertext, // Public credential share
    pub r_i: BigInt,                  // randomness for encrypting public_credential_i_tag
    pub eta: BigInt,                  // randomness for reencryption to obtain public_credential_i
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CredetialShareOutput {
    pub private_credential_i: BigInt, //private credential share
    pub public_credential_i_tag: ElGamalCiphertext, // Public credential share
    pub r_i: BigInt,                  // randomness for encrypting public_credential_i_tag
    pub dvrp_proof: DvrpProof,
    pub dvrp_prover_pk: BigInt,
}

impl CredetialShareOutput {
    pub fn get_dvrp_input<'a>(
        &'a self,
        voter_pk: &'a BigInt,
        public_credential_i: &'a ElGamalCiphertext,
    ) -> DvrpPublicInput<'a> {
        DvrpPublicInput {
            voter_public_key: voter_pk,
            prover_public_key: &self.dvrp_prover_pk,
            e: &self.public_credential_i_tag,
            e_tag: &public_credential_i,
        }
    }
}

impl Registrar {
    pub fn create_credential_share(&self) -> CredentialShare {
        let pp = &self.params.pp.clone();
        let private_credential_i = BigInt::sample_below(&pp.q);
        // let private_credential_i = encoding_quadratic_residue(BigInt::sample_below(&pp.q);
        let r_i = BigInt::sample_below(&pp.q);
        let public_credential_i_tag =
            ElGamal::encrypt_from_predefined_randomness(&private_credential_i, &self.ktt, &r_i)
                .unwrap();
        let eta = BigInt::sample_below(&pp.q);
        let public_credential_i = reencrypt(
            &ElGamalCipherTextAndPK {
                ctx: public_credential_i_tag.clone(),
                pk: &self.ktt,
            },
            &eta,
        );
        CredentialShare {
            private_credential_i,
            public_credential_i,
            public_credential_i_tag,
            r_i,
            eta,
        }
    }

    //publish credential share (private_credential_i, S'_i, r_i) and a dvrp proof that public_credential_i is reenc of public_credential_i
    pub fn publish_credential_with_proof(
        &self,
        cred_share: &CredentialShare,
        dvrp_input: DvrpPublicInput,
    ) -> CredetialShareOutput {
        //  let cred_share = &self.cred_vec.get(voter_index).unwrap();
        // let dvrp_input = &dvrpPublicInput{ e: &cred_share.public_credential_i_tag, e_tag: &cred_share.public_credential_i };
        let proof = dvrp_prover(self, &dvrp_input, cred_share.eta.clone());
        CredetialShareOutput {
            private_credential_i: cred_share.private_credential_i.clone(),
            public_credential_i_tag: cred_share.public_credential_i_tag.clone(),
            r_i: cred_share.r_i.clone(),
            dvrp_proof: proof,
            dvrp_prover_pk: dvrp_input.prover_public_key.clone(),
        }
    }
}

#[cfg(test)]
pub mod test_registrar {
    use super::*;
    use crate::citivas::supervisor::SystemParameters;
    use crate::citivas::voter::Voter;
    use crate::citivas::zkproofs::dvrp_verifier;
    use elgamal::rfc7919_groups::SupportedGroups;

    #[test]
    //This checks using dvrp that S’_i is a reencryption of public_credential_i using dvrp
    pub fn check_credential_proof() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let mut params = SystemParameters::create_supervisor(&pp);
        let pk = ElGamalPublicKey {
            pp,
            h: BigInt::from(4),
        };
        params.set_encrypted_list(pk.clone());
        let registrar = Registrar::create(0, params.clone(), pk.clone());
        let share = registrar.create_credential_share();
        let voter_pk = &Voter::create(1, &params, &pk).designation_key_pair.pk.h;
        let dvrp_input = DvrpPublicInput::create_input(
            voter_pk,
            registrar.get_pk(),
            &share.public_credential_i_tag,
            &share.public_credential_i,
        );
        let cred_share_output = registrar.publish_credential_with_proof(&share, dvrp_input.clone());
        let check = dvrp_verifier(&registrar, &dvrp_input, &cred_share_output.dvrp_proof);
        assert!(check)
    }
}
