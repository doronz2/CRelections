use elgamal::{ElGamal, ElGamalPP,
              ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
              ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::BigInt;


use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;

use serde::{Deserialize, Serialize};

use crate::citivas::encryption_schemes::{reencrypt, ElGamalCipherTextAndPK, encoding_quadratic_residue};
use rand::seq::SliceRandom;
use rand::thread_rng;
use crate::citivas::supervisor::SystemParameters;
use crate::citivas::voter;
use crate::citivas::voter::{Vote, Voter};
use crate::citivas::tellers::Teller;
use crate::citivas::zkproofs::{VotePfPublicInput, ReencProofInput, DvrpPublicInput, DVRP_verifier};
use crate::SupportedGroups;
use crate::citivas::registrar::Registrar;
use crate::citivas::entity::Entity;
use crate::citivas::dist_el_gamal::{DistDecryptEGMsg, DistElGamal};


pub struct Results{
    candidate_id: i32,
    score: i32
}

#[test]
pub fn integration_test(){
    let group_id = SupportedGroups::FFDHE4096;
    let pp = ElGamalPP::generate_from_rfc7919(group_id);
    let params = &SystemParameters::create_supervisor(&pp);
  // *** basic methodology ***
    //create tellers, registrar, supervisor,and voter
    //supervisor create params
    //tellers create KTT public key
    //registrar create credentials
    // voters construct credential and vote
    // tellers decrypt all the massages, read all the vote, and score each candidate

    //Three candidates

    let candidate_1 = 1;
    let candidate_2 = 2;
    let candidate_3 = 3;

    // Each teller generates a share (while being generated)
    let teller_1 = Teller::create_teller(params.clone(),0);
    let teller_2 = Teller::create_teller(params.clone(),1);
    let teller_3 = Teller::create_teller(params.clone(),2);

    //add all the tellers to a vector (this will not happen in practice, but is here only for simulation)
    let mut tellers = Vec::new();
    tellers.push(&teller_1);
    tellers.push(&teller_2);
    tellers.push(&teller_3);

    //each teller publishes a commitment to the share
    let commitments = &tellers
        .iter()
        .map(|&teller| teller.get_share().publish_commitment_key_gen())
        .collect();

    //each teller publish a proof to the share that is consistent with with the commitment it published
    let shares_and_proofs = tellers.clone()
        .iter()
        .map(|&party| party.clone().get_share().publish_proof_for_key_share())
        .collect();

    //each teller construct the public key from the shares

    let shared_public_key =
        teller_1.get_share().construct_shared_public_key(commitments, shares_and_proofs);

    let shared_public_key_2 =
        teller_2.get_share().construct_shared_public_key(commitments, shares_and_proofs);

    let shared_public_key_3 =
        teller_3.get_share().construct_shared_public_key(commitments, shares_and_proofs);


    assert_eq!(shared_public_key, shared_public_key_2);
    assert_eq!(shared_public_key, shared_public_key_3);

    let registrar_1 = Registrar::create(0, params.clone(),  shared_public_key.clone());
    let registrar_2 = Registrar::create(1, params.clone(),  shared_public_key.clone());

    let credential_share_1_for_voter_1 = registrar_1.create_credential_share();
    let credential_share_1_for_voter_2 = registrar_1.create_credential_share();
    let credential_share_1_for_voter_3 = registrar_1.create_credential_share();

    let credential_share_2_for_voter_1 = registrar_2.create_credential_share();
    let credential_share_2_for_voter_2 = registrar_2.create_credential_share();
    let credential_share_2_for_voter_3 = registrar_2.create_credential_share();



    let mut voter_1 = Voter::create(0, params);
    let mut voter_2 = Voter::create(1, params);
    let mut voter_3 = Voter::create(2, params);

    let dvrp_input_voter_1_cred_1 = DvrpPublicInput::create_input(&voter_1.get_pk(), registrar_1.get_pk(), &credential_share_1_for_voter_1.S_i_tag, &credential_share_1_for_voter_1.S_i);
    let dvrp_input_voter_1_cred_2 = DvrpPublicInput::create_input(&voter_1.get_pk(), registrar_2.get_pk(), &credential_share_2_for_voter_1.S_i_tag, &credential_share_2_for_voter_1.S_i);
    let dvrp_input_voter_2_cred_1 = DvrpPublicInput::create_input(&voter_2.get_pk(), registrar_1.get_pk(), &credential_share_1_for_voter_2.S_i_tag, &credential_share_1_for_voter_2.S_i);
    let dvrp_input_voter_2_cred_2 = DvrpPublicInput::create_input(&voter_2.get_pk(), registrar_2.get_pk(), &credential_share_2_for_voter_2.S_i_tag, &credential_share_2_for_voter_2.S_i);
    let dvrp_input_voter_3_cred_1 = DvrpPublicInput::create_input(&voter_3.get_pk(), registrar_1.get_pk(), &credential_share_1_for_voter_3.S_i_tag, &credential_share_1_for_voter_3.S_i);
    let dvrp_input_voter_3_cred_2 = DvrpPublicInput::create_input(&voter_3.get_pk(), registrar_2.get_pk(), &credential_share_2_for_voter_3.S_i_tag, &credential_share_2_for_voter_3.S_i);

    //publish credential and proof (via DVRP proof) that S'_i is reencryption of S_i
    let cred_share_output_1_voter_1 = registrar_1.publish_credential_with_proof(&credential_share_1_for_voter_1, dvrp_input_voter_1_cred_1);
    let cred_share_output_2_voter_1 = registrar_2.publish_credential_with_proof(&credential_share_2_for_voter_1, dvrp_input_voter_1_cred_2);
    let cred_share_output_1_voter_2 = registrar_1.publish_credential_with_proof(&credential_share_1_for_voter_2, dvrp_input_voter_2_cred_1);
    let cred_share_output_2_voter_2 = registrar_2.publish_credential_with_proof(&credential_share_2_for_voter_2, dvrp_input_voter_2_cred_2);
    let cred_share_output_1_voter_3 = registrar_1.publish_credential_with_proof(&credential_share_1_for_voter_3, dvrp_input_voter_3_cred_1);
    let cred_share_output_2_voter_3 = registrar_2.publish_credential_with_proof(&credential_share_2_for_voter_3, dvrp_input_voter_3_cred_2);

    //Each voter combines its credential shares
    let voter_1_private_credential = voter_1.construct_private_credential_from_shares(
        vec![cred_share_output_1_voter_1, cred_share_output_2_voter_1],
        vec![credential_share_1_for_voter_1.S_i, credential_share_2_for_voter_1.S_i]);

    let voter_2_private_credential = voter_2.construct_private_credential_from_shares(
        vec![cred_share_output_1_voter_2, cred_share_output_2_voter_2],
        vec![credential_share_1_for_voter_2.S_i, credential_share_2_for_voter_2.S_i]);

    let voter_3_private_credential = voter_3.construct_private_credential_from_shares(
        vec![cred_share_output_1_voter_3, cred_share_output_2_voter_3],
        vec![credential_share_1_for_voter_3.S_i, credential_share_2_for_voter_3.S_i]);

    voter_1.set_private_credential(voter_1_private_credential.unwrap());
    voter_2.set_private_credential(voter_2_private_credential.unwrap());
    voter_3.set_private_credential(voter_3_private_credential.unwrap());

    //voting among candidates!!!!
    let vote_1 = voter_1.vote(candidate_1, &params.clone());
    let vote_2 = voter_2.vote(candidate_3, &params.clone());
    let vote_3 = voter_3.vote(candidate_1, &params.clone());

    assert!(Voter::check_votes(&voter_1, &vote_1, &params));
    assert!(Voter::check_votes(&voter_2, &vote_2, &params));
    assert!(Voter::check_votes(&voter_3, &vote_3, &params));



    let shares_and_proofs: Vec<DistDecryptEGMsg> = tellers
        .iter()
        .map(|teller| teller.get_share().publish_shares_and_proofs_for_decryption(&vote_1.ev))
        .collect();
    let valid_shares_for_decryption: Vec<BigInt> = tellers
        .iter()
        .zip(shares_and_proofs)
        .filter(|(teller, share_and_proof)| teller.get_share().verify_proof_for_decryption(&vote_1.ev, share_and_proof, teller.party_index) )
        .map(|(_, shares_and_proof)| shares_and_proof.share)
        .collect();
    if valid_shares_for_decryption.len() == 0{
        panic!("no share has been validated");
    }
    println!("number of valid shares = {:?}", valid_shares_for_decryption.len());
    let plain_text_msg = DistElGamal::combine_shares_and_decrypt( &vote_1.ev, valid_shares_for_decryption, &pp);
    assert_eq!(candidate_1, plain_text_msg);


    //left to do
    //tellers decrypt vote
    //crating array of the votes and declaring the winner

    /*
    let shared_private_key = ElGamalPrivateKey {
        x: (teller_1.get_private_share() + teller_2.get_private_share() + teller_3.get_private_share()).mod_floor(&pp.q),
        pp: pp.clone()
    };
    let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
    let r = BigInt::sample_below(&pp.q);
    let encrypted_msg = elgamal::ElGamal::encrypt_from_predefined_randomness(
        &BigInt::from(encoded_msg.clone()),&shared_public_key, &r).unwrap();


    println!("msg1: {:?}", encoded_msg);
    let encrypted_msg = ElGamal::encrypt(&encoded_msg, &shared_public_key).unwrap();
    let decrypted_msg = ElGamal::decrypt(&encrypted_msg, &shared_private_key).unwrap();
    assert_eq!(encoded_msg, decrypted_msg);
    */






    // let registrar1 = Registrar::create()



}

