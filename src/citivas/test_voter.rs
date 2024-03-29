#[cfg(test)]
pub mod test_voter {
    use crate::citivas::encryption_schemes::encoding_quadratic_residue;
    use crate::citivas::entity::Entity;
    use crate::citivas::registrar::Registrar;
    use crate::citivas::supervisor::SystemParameters;
    use crate::citivas::voter::Voter;
    use crate::citivas::zkproofs::DvrpPublicInput;
    use crate::BigInt;
    use crate::{ElGamal, ElGamalPP, ElGamalPublicKey, SupportedGroups};
    use curv::arithmetic::traits::Samplable;

    #[test]
    pub fn validate_credential_shares() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let mut params = SystemParameters::create_supervisor(&pp);
        let pk = ElGamalPublicKey {
            pp,
            h: BigInt::from(4),
        };
        params.set_encrypted_list(pk.clone());
        let voter = Voter::create(voter_number, &params, &pk);
        let registrar = Registrar::create(0, params.clone(), pk.clone());
        let share = registrar.create_credential_share();
        let dvrp_input = DvrpPublicInput::create_input(
            &voter.designation_key_pair.pk.h,
            registrar.get_pk(),
            &share.public_credential_i_tag,
            &share.public_credential_i,
        );
        let cred_share_output = registrar.publish_credential_with_proof(&share, dvrp_input);
        assert!(voter.verify_credentials(&cred_share_output, &share.public_credential_i));
    }

    #[test]
    pub fn test_credential_shares_construction() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let mut params = SystemParameters::create_supervisor(&pp);
        let pk = ElGamalPublicKey {
            pp,
            h: BigInt::from(4),
        };
        params.set_encrypted_list(pk.clone());

        let mut voter = Voter::create(voter_number, &params, &pk);
        let registrar_1 = Registrar::create(0, params.clone(), pk.clone());
        let registrar_2 = Registrar::create(0, params.clone(), pk.clone());
        let registrar_3 = Registrar::create(0, params.clone(), pk.clone());

        let share_1 = registrar_1.create_credential_share();
        let share_2 = registrar_2.create_credential_share();
        let share_3 = registrar_3.create_credential_share();

        let dvrp_input_1 = DvrpPublicInput::create_input(
            &voter.designation_key_pair.pk.h,
            registrar_1.get_pk(),
            &share_1.public_credential_i_tag,
            &share_1.public_credential_i,
        );
        let dvrp_input_2 = DvrpPublicInput::create_input(
            &voter.designation_key_pair.pk.h,
            registrar_2.get_pk(),
            &share_2.public_credential_i_tag,
            &share_2.public_credential_i,
        );
        let dvrp_input_3 = DvrpPublicInput::create_input(
            &voter.designation_key_pair.pk.h,
            registrar_3.get_pk(),
            &share_3.public_credential_i_tag,
            &share_3.public_credential_i,
        );

        let cred_share_output_1 = registrar_1.publish_credential_with_proof(&share_1, dvrp_input_1);
        let cred_share_output_2 = registrar_2.publish_credential_with_proof(&share_2, dvrp_input_2);
        let cred_share_output_3 = registrar_3.publish_credential_with_proof(&share_3, dvrp_input_3);
        //this bad share of registrar 3 should not be counted as it's dvrp proof does not pass verification
        let bad_encryption =
            ElGamal::encrypt(&BigInt::from(1234), &voter.designation_key_pair.pk).unwrap();
        let private_credential = voter.construct_private_credential_from_shares(
            vec![
                cred_share_output_1,
                cred_share_output_2,
                cred_share_output_3,
            ],
            vec![
                share_1.public_credential_i,
                share_2.public_credential_i,
                bad_encryption,
            ],
        );
        assert!(private_credential.is_some())
    }

    #[test]
    pub fn test_vote() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let voter_number = 1;
        let mut params = SystemParameters::create_supervisor(&pp);
        let pk = ElGamalPublicKey {
            pp: pp.clone(),
            h: BigInt::from(4),
        };
        params.set_encrypted_list(pk.clone());
        let mut voter = Voter::create(voter_number, &params, &pk);
        let private_cred = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
        //let private_cred = encoding_quadratic_residue(BigInt::from(3),&pp);

        voter.set_private_credential(private_cred);
        let candidate_index = 1;
        let vote = voter.vote(candidate_index, &params.clone());
        assert!(Voter::check_votes(&voter, &vote, &params));
    }
}
