pub mod test_zk_proofs {
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
    use crate::{generate_keys_toy, encrypt_toy, generate_pp_toy};
    use crate::citivas::Entity::Entity;

    #[test]
    fn test_votePF(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let witness = VoteWitness::generate_random_witness(&pp);
        let inputPF = VotePfPublicInput::generateRandomInput(&pp, &witness);
        let voter_number = 1;
        let voter = Voter::simple_create(voter_number,pp.clone());
        let proof  = inputPF.votepf_prover(&voter, witness);
        let verification = proof.votepf_verifier(&inputPF,&voter);
        assert!(verification);
    }

    #[test]
    pub fn test_reenc_1_out_of_L(){
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
        let input = ReencProofInput{ C_list, c: ctx.clone() };
        let proof = input.reenc_1_out_of_L_prove(&pp,&key_pair.pk, t, enc_key, L);
        let verification = input.reenc_1_out_of_L_verifier(&pp,&key_pair.pk, proof, L);
        assert!(verification);
    }


}

