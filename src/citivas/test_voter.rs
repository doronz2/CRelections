pub mod test_voter{
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
    use crate::citivas::superviser;



    #[test]
    fn test_div_and_pow(){
        let x = BigInt::from(7);
        let x_tag = BigInt::from(7*9);
        let c = BigInt::from(2);
        let p  = BigInt::from(1000);
        let res = div_and_pow(&x,&x_tag,&c,&p);
        println!("res div and pow = {}",res);
    }

#[test]
    fn test_DVRP(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
     //println!("pk = {:?}, g={:?}", key_pair.pk.h, key_pair.pk.pp.g);
        let voter_number = 1;
        let voter = Voter::simple_create(voter_number,pp.clone());
        let eta = BigInt::from(7);
        let msg = 269;
        let r = BigInt::sample_below(&pp.q);
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let e = ElGamal::encrypt_from_predefined_randomness(
            &encoded_msg, &voter.get_key_pair().pk,&r
        ).unwrap();
        let e_with_pk = ElGamalCipherTextAndPK{ ctx:e.clone() , pk: &voter.get_key_pair().pk};//need to get read of the struct  ElGamalCipherTextAndPK and create voter with pk
        let e_tag = reencrypt(&e_with_pk, &eta);
    let div = BigInt::mod_mul(&BigInt::mod_inv(&e.c2,&pp.p),
                                  &e_tag.clone().c2.mod_floor(&pp.p)
            , &pp.p);

        let dvrp_input = DVRP_Public_Input::create_input(&e,&e_tag);
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
        let msg = 269;
        let r = BigInt::sample_below(&pp.q);
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let e = ElGamal::encrypt_from_predefined_randomness(
            &encoded_msg, &voter.get_key_pair().pk,&r
        ).unwrap();
        let e_with_pk = ElGamalCipherTextAndPK{ ctx:e.clone() , pk: &voter.get_key_pair().pk};//need to get read of the struct  ElGamalCipherTextAndPK and create voter with pk
        let e_tag = reencrypt(&e_with_pk, &eta);
        let div = BigInt::mod_mul(&BigInt::mod_inv(&e.c2,&pp.p),
                                  &e_tag.clone().c2.mod_floor(&pp.p)
                                  , &pp.p);

        let dvrp_input = DVRP_Public_Input::create_input(&e,&e_tag);
        let dvrp_proof = fakeDVRP_prover(&voter, &dvrp_input);
        let dvrp_verfication_pass = DVRP_verifier(&voter,&dvrp_input, &dvrp_proof);
        assert!(dvrp_verfication_pass);
    }
}
