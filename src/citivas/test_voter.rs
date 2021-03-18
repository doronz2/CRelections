pub mod test_voter {
    use elgamal::{ElGamal, rfc7919_groups::SupportedGroups, ElGamalPP,
                  ElGamalKeyPair, ElGamalError, ElGamalCiphertext,
                  ElGamalPrivateKey, ElGamalPublicKey, ExponentElGamal};
    use curv::BigInt;

    use curv::arithmetic::traits::Modulo;
    use curv::arithmetic::traits::Samplable;
    use curv::cryptographic_primitives::hashing::hash_sha256;
    use curv::cryptographic_primitives::hashing::traits::Hash;
    use crate::citivas::encryption_schemes::*;
    use crate::citivas::zkproofs::*;
    use crate::citivas::voter::*;
    use crate::citivas::Entity::Entity;
    use crate::citivas::superviser::*;
    use crate::citivas::registrar::*;

    #[test]
    pub fn validate_credential_shares() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let params = &SystemParameters::create_supervisor(&pp);
        let voter = Voter::create(voter_number, &params);
        let registrar = Registrar::create(0, &pp, params.num_of_voters, params.KTT.clone());
        let share = registrar.create_credential_share();
        let dvrp_input = DVRP_Public_Input::create_input(&voter.designation_key_pair.pk.h, registrar.get_pk(), &share.S_i_tag, &share.S_i);
        let cred_share_output = registrar.publish_credential_with_proof(&share, dvrp_input);
        assert!(voter.verify_credentials(&cred_share_output, &share.S_i));
    }

    #[test]
    pub fn test_credential_shares_construction() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let params = &SystemParameters::create_supervisor(&pp);
        let mut voter = Voter::create(voter_number, &params);
        let registrar_1 = Registrar::create(0, &pp, params.num_of_voters, params.KTT.clone());
        let registrar_2 = Registrar::create(0, &pp, params.num_of_voters, params.KTT.clone());
        let registrar_3 = Registrar::create(0, &pp, params.num_of_voters, params.KTT.clone());

        let share_1 = registrar_1.create_credential_share_toy_1();
        let share_2 = registrar_2.create_credential_share_toy_2();
        let share_3 = registrar_2.create_credential_share_toy_2();

        let dvrp_input_1 = DVRP_Public_Input::create_input(&voter.designation_key_pair.pk.h, registrar_1.get_pk(), &share_1.S_i_tag, &share_1.S_i);
        let dvrp_input_2 = DVRP_Public_Input::create_input(&voter.designation_key_pair.pk.h, registrar_2.get_pk(), &share_2.S_i_tag, &share_2.S_i);
        let dvrp_input_3 = DVRP_Public_Input::create_input(&voter.designation_key_pair.pk.h, registrar_3.get_pk(), &share_3.S_i_tag, &share_3.S_i);

        let cred_share_output_1 = registrar_1.publish_credential_with_proof(&share_1, dvrp_input_1);
        let cred_share_output_2 = registrar_2.publish_credential_with_proof(&share_2, dvrp_input_2);
        let cred_share_output_3 = registrar_3.publish_credential_with_proof(&share_3, dvrp_input_3);
        //this bad share of registrar 3 should not be counted as the dvrp proof is false
        let bad_encryption = ElGamal::encrypt(&BigInt::from(1234),&voter.designation_key_pair.pk).unwrap();

        let private_credential = voter.construct_private_credential_from_shares(
            vec![cred_share_output_1, cred_share_output_2, cred_share_output_3], vec![share_1.S_i, share_2.S_i, bad_encryption]);
    }

    #[test]
    pub fn test_vote() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let params = &SystemParameters::create_supervisor(&pp);
        let mut voter = Voter::create(voter_number, &params);
        let private_credential = sample_from!(&pp.p);

        let candidate_index = 1;
        let vote = voter.vote(candidate_index);
        assert!(Voter::check_votes(&voter, vote));
    }

}