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

    #[test]
    fn test_votePF(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let witness = VoteWitness::generate_random_witness(&pp);
        let inputPF = VotePfPublicInput::generateRandomInput(&pp, &witness);
        let voter_number = 1;
        let voter = Voter::create_voter(voter_number,pp.clone());
        let proof  = inputPF.votepf_prover(&voter, witness, );
        let verification = inputPF.votepf_verifier(&voter, proof);
        assert!(verification);
    }



}

