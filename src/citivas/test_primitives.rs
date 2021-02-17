pub mod test {
    use elgamal::{ElGamal,rfc7919_groups::SupportedGroups,ElGamalPP,
                  ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
                  ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
    use curv::BigInt;

    use curv::arithmetic::traits::Modulo;
    use curv::arithmetic::traits::Samplable;
    use curv::cryptographic_primitives::hashing::hash_sha256;
    use curv::cryptographic_primitives::hashing::traits::Hash;
    use crate::citivas::encryption_schemes::*;

    #[test]
    fn test_basic_el_gamal() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);

        let alice_key_pair = ElGamalKeyPair::generate(&pp);

        let msg = BigInt::from(987);

        let cipher = elgamal::ElGamal::encrypt(&msg, &alice_key_pair.pk).unwrap();
        let plain = elgamal::ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();
        println!("the plaintext is {}", plain);

        let factor1 = elgamal::ElGamal::
        encrypt(&BigInt::from(5), &alice_key_pair.pk).unwrap();
        let factor2 = elgamal::ElGamal::
        encrypt(&BigInt::from(3), &alice_key_pair.pk).unwrap();
        let cipher_prod = ElGamal::mul(&factor1, &factor2).unwrap();
        let homomorphic_result = ElGamal::decrypt(&cipher_prod, &alice_key_pair.sk).unwrap();
        println!(" the plaintext result after applying homomorphic multiplication is {}", homomorphic_result);
        assert_eq!(BigInt::from(15), homomorphic_result);
    }

    #[test]
    fn test_exp_el_gamal() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let alice_key_pair = ElGamalKeyPair::generate(&pp);
        let msg = BigInt::from(8283);
        let cipher = ExponentElGamal::encrypt(&msg, &alice_key_pair.pk).unwrap();
        let dec = ExponentElGamal::decrypt_exp(&cipher, &alice_key_pair.sk).unwrap();
        let mut plain = BigInt::from(0);
        for i in 0..1000000 {
            let res = BigInt::mod_pow(&alice_key_pair.pk.pp.g, &BigInt::from(i), &alice_key_pair.pk.pp.p);
            if res.eq(&dec) {
                plain = BigInt::from(i);
                break;
            }
        }
        assert_eq!(plain, msg);
    }


    #[test]
    fn test_primitives(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        for msg in 1..40 {
            let encoded_msg = encoding_quadratic_residue(BigInt::from(msg), &pp);
            println!("{}",encoded_msg);
        }
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let encrypted_msg = NonMellableElgamal::encrypt(&encoded_msg,&key_pair.pk).unwrap();
        let decrypted_msg = NonMellableElgamal::decrypt(encrypted_msg,&key_pair.sk).unwrap();
        println!("Decrypted msg {}", decrypted_msg);


        let credential_key_pair = ElGamalKeyPair::generate(&pp);
        let rid: i32 = 76876;
        let vid: i32 = 4238976;
        let credential_nonce = BigInt::sample_below(&pp.q);
        let encrypted_credential = NonMellableElgamal::encrypt_credential(&encoded_msg,&key_pair.pk,&credential_nonce,rid,vid).unwrap();
        let verify_credential = NonMellableElgamal::decrypt(encrypted_credential,&key_pair.sk).unwrap();
    }

}