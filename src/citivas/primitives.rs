use elgamal::{ElGamal,rfc7919_groups::SupportedGroups,ElGamalPP,
              ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
              ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::BigInt;

use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;


//use elgamal::ElGamalKeyPair;

//General comment. Citivas encoding messages are via exponent, i.e., G^m mod p. This is done to achieve semantic security
// Much more efficient encoding to achieve semantic security is via quadratic residue

pub struct NonMellableElgamal{
    a: BigInt,
    b: BigInt,
    c: BigInt,
    d: BigInt,
}



impl NonMellableElgamal {

    //this is an encoding of a message in the field Z   q to a multiplicative subgroup group Gq
    //that maintains quadratic residue and believed to maintain semantic security if p is a safe prime
    //it does not appear in Citivas
    pub fn encoding_quadratic_residue(m: BigInt, pp: &elgamal::ElGamalPP)-> BigInt{
        //modify m by adding 1 to m because the subgroup Gq does not include the value zero
        let m_modified = BigInt::mod_add(&m, &BigInt::one(), &pp.p);
        //check if m is QR according to Euler criterion
        let test_QR = BigInt::mod_pow(&m_modified, &pp.q, &pp.p);
        //if m is QR then return m otherwise return p - m
        return if test_QR == BigInt::one() {
            m_modified
        } else {
            BigInt::mod_sub(&pp.p, &m_modified, &pp.p)
        }
    }

    //a simple EG encryption (a,b) that is signed with Schnorr (c,d)
    pub fn non_malleable_encrypt(m: BigInt, y: ElGamalPublicKey) -> Result<NonMellableElgamal, ElGamalError>{
        if m.ge(&y.pp.p)  {
            return Err(ElGamalError::EncryptionError)
        }

        let r = BigInt::sample_below(&y.pp.q);
        let cipher = ElGamal::encrypt_from_predefined_randomness(&m, &y, &r).unwrap();
        let s = BigInt::sample_below(&y.pp.q);
        let g_s = BigInt::mod_pow(&y.pp.g, &s, &y.pp.p);
        let a = cipher.c1;
        let b = cipher.c2;
        let c = BigInt::mod_mul(&hash_sha256::HSha256::create_hash(
            &[&g_s,&a, &b ]), &BigInt::from(1), &y.pp.q
        );
        let d = BigInt::mod_add(&s, &BigInt::mod_mul(&c, &r, &y.pp.q), &&y.pp.q);
        Ok(NonMellableElgamal{a, b, c, d})
    }

    pub fn non_malleable_decrypt(NMcipher: Self, x: ElGamalPrivateKey) -> Result<BigInt, ElGamalError>  {
        let g_d = BigInt::mod_pow(&x.pp.g, &NMcipher.d, &x.pp.p);
        let a_c_inv = BigInt::mod_inv(
            &BigInt::mod_pow(&NMcipher.a, &NMcipher.c, &x.pp.p)
            , &&x.pp.p) ;
        let pre_hash_left_term = BigInt::mod_mul(&g_d,&a_c_inv, &x.pp.p);
        let V = hash_sha256::HSha256::create_hash(&[&pre_hash_left_term, &NMcipher.a,&NMcipher.b]);
        if V != NMcipher.c{
            panic!("received an invalid non malleable cipher!");
        }
        let cipher = ElGamalCiphertext{c1: NMcipher.a, c2: NMcipher.b, pp: x.pp};
        ExponentElGamal::decrypt_exp(&cipher, &alice_key_pair.sk).unwrap()?
        }
}



pub fn encrypt_credential(share: &BigInt, KTT: &ElGamalPublicKey, r: &BigInt, rid: &BigInt, vid: &BigInt)
    -> Result<NonMellableElgamal, ElGamalError> {
        //Public key KTT
        //private credential share s ∈ M
        //Randomization factor r ∈ Z∗q ,
        //Identifiers of registration teller, rid , and voter, vid
    if share.ge(&KTT.pp.p) || r.ge(&KTT.pp.q) {
        return Err(ElGamalError::EncryptionError)
    }
    let cipher = ElGamal::encrypt_from_predefined_randomness(&share, &KTT, &r).unwrap();
    let t = BigInt::sample_below(&KTT.pp.q);
    let g_t = BigInt::mod_pow(&KTT.pp.g, &t, &KTT.pp.p);
    let a = cipher.c1;
    let b = cipher.c2;
    let c = BigInt::mod_mul(&hash_sha256::HSha256::create_hash(
        &[ &g_t,&a, &b, &rid, &vid]), &BigInt::from(1), &KTT.pp.q
    );
    let d = BigInt::mod_add(&t, &BigInt::mod_mul(&c, &r, &KTT.pp.q), &&KTT.pp.q);
    Ok(NonMellableElgamal{a, b, c, d})
}


pub fn verify_credential(public_credential_share: &NonMellableElgamal, rid: &BigInt, vid: &BigInt, pp: elgamal::ElGamalPP) -> bool {

    let g_d = BigInt::mod_pow(&x.pp.g, &public_credential_share.d, &pp.p);
    let a_c_inv = BigInt::mod_inv(
        &BigInt::mod_pow(&public_credential_share.a, &public_credential_share.c, &pp.p)
        , &&pp.p) ;
    let pre_hash_left_term = BigInt::mod_mul(&g_d,&a_c_inv, &pp.p);
    let V = hash_sha256::HSha256::create_hash(
        &[&pre_hash_left_term, &public_credential_share.a,&public_credential_share.b]
    );
     V == public_credential_share.c
   }




pub fn reencrypt(c: ElGamalCiphertext, pk: ElGamalPublicKey)-> ElGamalCiphertext{
    let a = c.c1;
    let b = c.c2;
    let r = BigInt::sample_below(&pk.pp.q);
    let g_r = BigInt::mod_pow(&pk.pp.g, &r, &pk.pp.p);
    let c1 = BigInt::mod_mul(&g_r, &a,&pk.pp.p);
    let s = BigInt::mod_pow(&pk.h, &r, &pk.pp.p);
    let c2 = BigInt::mod_mul(&s, &b, &pk.pp.p);
    ElGamalCiphertext {
        c1,
        c2,
        pp: pk.pp.clone()
    }
}


pub fn distributed_el_gamal_generation(pp: &ElGamalPP){

}


pub mod test{
    use super::*;
    use crate::citivas::primitives::*;

    #[test]
    fn test_regular_el_gamal(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);

        let alice_key_pair = ElGamalKeyPair::generate(&pp);

        let msg = BigInt::from(987);

        let cipher = elgamal::ElGamal::encrypt(&msg, &alice_key_pair.pk).unwrap();
        let plain = elgamal::ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();
        println!("the plaintext is {}",plain);

        let factor1 = elgamal::ElGamal::
        encrypt(&BigInt::from(5), &alice_key_pair.pk).unwrap();
        let factor2 = elgamal::ElGamal::
        encrypt(&BigInt::from(3), &alice_key_pair.pk).unwrap();
        let cipher_prod =  ElGamal::mul(&factor1,&factor2).unwrap();
        let homomorphic_result = ElGamal::decrypt(&cipher_prod,&alice_key_pair.sk).unwrap();
        println!(" the plaintext result after applying homomorphoc multiplication is {}", homomorphic_result);
        assert_eq!(BigInt::from(15), homomorphic_result);
    }

    #[test]
    fn test_exp_el_gamal(){
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let alice_key_pair = ElGamalKeyPair::generate(&pp);
        let msg =  BigInt::from(8283);
        let cipher = ExponentElGamal::encrypt(&msg, &alice_key_pair.pk).unwrap();
        let dec = ExponentElGamal::decrypt_exp(&cipher, &alice_key_pair.sk).unwrap();
        let mut plain =  BigInt::from(0);
        for i in 0..1000000 {
            let res = BigInt::mod_pow(&alice_key_pair.pk.pp.g, &BigInt::from(i), &alice_key_pair.pk.pp.p);
            if res.eq(&dec) {
                plain = BigInt::from(i);
                break;
            }
        }
        assert_eq!(plain, msg);


    }



}