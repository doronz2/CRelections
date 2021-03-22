#[cfg(test)]
pub mod test_encryption {
    use crate::{SupportedGroups, ElGamalPP, ElGamalKeyPair, ElGamal, ExponentElGamal};
    use crate::citivas::encryption_schemes::
    {encoding_quadratic_residue, NonMellableElgamal, ElGamalCipherTextAndPK, reencrypt};
    use crate::BigInt;
    use curv::arithmetic::traits::{Modulo, Samplable};

    #[test]
    fn test_basic_el_gamal() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let alice_key_pair = ElGamalKeyPair::generate(&pp);
        let msg = BigInt::from(987);
        let cipher = elgamal::ElGamal::encrypt(&msg, &alice_key_pair.pk).unwrap();
        let _plain = elgamal::ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();
        let factor1 = elgamal::ElGamal::
        encrypt(&BigInt::from(5), &alice_key_pair.pk).unwrap();
        let factor2 = elgamal::ElGamal::
        encrypt(&BigInt::from(3), &alice_key_pair.pk).unwrap();
        let cipher_prod = ElGamal::mul(&factor1, &factor2).unwrap();
        let homomorphic_result = ElGamal::decrypt(&cipher_prod, &alice_key_pair.sk).unwrap();
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
    fn test_QR_encoding() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        for msg in 1..40 {
            let _encoded_msg = encoding_quadratic_residue(BigInt::from(msg), &pp);
        }
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let encrypted_msg = NonMellableElgamal::encrypt(&encoded_msg, &key_pair.pk).unwrap();
        let decrypted_msg = NonMellableElgamal::decrypt(encrypted_msg, &key_pair.sk).unwrap();
        assert_eq!(encoded_msg, decrypted_msg);
    }

    #[test]
    fn test_encrypt_credentials(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let rid: i32 = 76876;
        let vid: i32 = 4238976;
        let credential_nonce = BigInt::sample_below(&pp.q);
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let encrypted_credential = NonMellableElgamal::encrypt_credential(&encoded_msg,&key_pair.pk,&credential_nonce,rid.clone(),vid.clone()).unwrap();
        let verify_credential = NonMellableElgamal::verify_credential(&encrypted_credential,rid, vid, &pp);
        assert!(verify_credential);
    }

    #[test]
    fn test_reencryption(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let _msg = 269;
        let encoded_msg = encoding_quadratic_residue(BigInt::from(17), &pp);
        let r = BigInt::sample_below(&pp.q);
        let ctx = elgamal::ElGamal::encrypt_from_predefined_randomness(
            &BigInt::from(encoded_msg.clone()),&key_pair.pk, &r).unwrap();
        let ctx_and_pk = ElGamalCipherTextAndPK{ ctx, pk: &key_pair.pk };//need to get read of the struct  ElGamalCipherTextAndPK and create voter with pk
        let reencrypted_ctx = reencrypt(&ctx_and_pk,&r);
        let decrypted_msg = ElGamal::decrypt(&reencrypted_ctx, &key_pair.sk).unwrap();
        assert_eq!(encoded_msg, decrypted_msg);
    }
}

