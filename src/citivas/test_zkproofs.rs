#[cfg(test)]
pub mod test_zk_proofs {
    use crate::citivas::zkproofs::*;
    use crate::{SupportedGroups, ElGamalPP, ElGamalKeyPair, ElGamal, ElGamalCiphertext};
    use crate::citivas::supervisor::SystemParameters;
    use crate::citivas::voter::Voter;
    use crate::citivas::encryption_schemes::{ElGamalCipherTextAndPK, reencrypt, encoding_quadratic_residue};
    use crate::citivas::entity::Entity;
    use crate::BigInt;
    use curv::arithmetic::traits::{Samplable, Modulo};
    use elgamal::ElGamalPublicKey;


    #[test]
    fn test_votePF(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let witness = VoteWitness::generate_random_witness(&pp);
        let inputPF = VotePfPublicInput::generate_random_input(&pp, &witness);
        let voter_number = 1;
        let pk =  ElGamalPublicKey {
            pp: pp.clone(),
            h: BigInt::from(4)
        };
        let params = &SystemParameters::create_supervisor(&pp);
        let voter = Voter::create(voter_number, params, &pk);
        let proof  = inputPF.votepf_prover( witness, &params,);
        let verification = proof.votepf_verifier(&inputPF,&params);
        assert!(verification);
    }

    #[test]
    pub fn test_reenc_in_list_1_out_of_L(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let msg = BigInt::from(72364932);
        let ctx = &ElGamal::encrypt(&msg, &key_pair.pk).unwrap();
        let L = 3;
        let mut C_list: Vec<ElGamalCiphertext> = (0..L)
            .map(|_| ElGamal::encrypt(&BigInt::sample_below(&pp.q),&key_pair.pk ).unwrap())
            .collect();

        let t = 1;
        let enc_key = BigInt::from(17);
        let cipher = ElGamalCipherTextAndPK{ ctx: ctx.clone(), pk: &key_pair.pk };
        C_list[t] = reencrypt(&cipher,&enc_key);
        let input = ReencProofInput{ c_list: C_list, c: ctx.clone() };
        let proof = input.reenc_in_list_1_out_of_L_prove(&pp,&key_pair.pk, t, enc_key, L);
        let verification = input.reenc_1_out_of_L_verifier(&pp, &key_pair.pk, &proof, L);
        assert!(verification);
    }

    #[test]
    pub fn test_reenc_out_list_1_out_of_L(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let L = 3;
        let C_list: Vec<ElGamalCiphertext> = (0..L)
            .map(|_| ElGamal::encrypt(&BigInt::sample_below(&pp.q),&key_pair.pk ).unwrap())
            .collect();
        let t = 1;
        let c_t = ElGamalCipherTextAndPK{ ctx: C_list[t].clone(), pk: &key_pair.pk };
        let nonce = BigInt::from(17);
        //assert_eq!(nonce.clone() + nonce.clone().neg(), BigInt::zero());

        let ctx = reencrypt(&c_t, &nonce);
         let input = ReencProofInput{ c_list: C_list, c: ctx };
        let proof = input.reenc_out_of_list_1_out_of_L_prove(&pp,&key_pair.pk, t, nonce, L);
        let verification = input.reenc_1_out_of_L_verifier(&pp,&key_pair.pk, &proof, L);
        assert!(verification);
    }

    #[test]
    fn test_DVRP(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        //println!("pk = {:?}, g={:?}", key_pair.pk.h, key_pair.pk.pp.g);
        let voter_number = 1;
        let voter = Voter::simple_create(voter_number,pp.clone());
        let eta = BigInt::from(7);
        let _msg = 269;
        let r = BigInt::sample_below(&pp.q);
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let e = ElGamal::encrypt_from_predefined_randomness(
            &encoded_msg, &voter.designation_key_pair.pk,&r
        ).unwrap();
        let e_with_pk = ElGamalCipherTextAndPK{ ctx:e.clone() , pk: &voter.designation_key_pair.pk};//need to get read of the struct  ElGamalCipherTextAndPK and create voter with pk
        let e_tag = reencrypt(&e_with_pk, &eta);
        let _div = BigInt::mod_mul(&BigInt::mod_inv(&e.c2,&pp.p),
                                  &e_tag.clone().c2.mod_floor(&pp.p)
                                  , &pp.p);

        let dvrp_input = DvrpPublicInput::create_input(voter.get_pk(), voter.get_pk(), &e, &e_tag);
        let dvrp_proof = DVRP_prover(&voter, &dvrp_input,eta);
        let dvrp_verfication_pass = DVRP_verifier(&voter, &dvrp_input, &dvrp_proof);
        assert!(dvrp_verfication_pass);
    }

    #[test]
    fn test_fake_DVRP(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let voter = Voter::simple_create(voter_number,pp.clone());
        let eta = BigInt::from(7);
        let _msg = 269;
        let r = BigInt::sample_below(&pp.q);
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let e = ElGamal::encrypt_from_predefined_randomness(
            &encoded_msg, &voter.designation_key_pair.pk,&r
        ).unwrap();
        let e_with_pk = ElGamalCipherTextAndPK{ ctx:e.clone() , pk: &voter.designation_key_pair.pk};//need to get read of the struct  ElGamalCipherTextAndPK and create voter with pk
        let e_tag = reencrypt(&e_with_pk, &eta);
        let _div = BigInt::mod_mul(&BigInt::mod_inv(&e.c2,&pp.p),
                                  &e_tag.clone().c2.mod_floor(&pp.p)
                                  , &pp.p);

        let dvrp_input = DvrpPublicInput::create_input(voter.get_pk(), voter.get_pk(), &e, &e_tag);
        let dvrp_proof = fakeDVRP_prover(&voter, &dvrp_input);
        let dvrp_verfication_pass = DVRP_verifier(&voter,&dvrp_input, &dvrp_proof);
        assert!(dvrp_verfication_pass);
    }


}

