use curv::BigInt;
use elgamal::{
     ElGamal, ElGamalCiphertext, ElGamalError,
     ElGamalPrivateKey, ElGamalPublicKey, ExponentElGamal,
};

use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use serde::{Deserialize, Serialize};


//use elgamal::ElGamalKeyPair;

//General comment. Citivas implements the encoding messages are via exponent, i.e., G^m mod p. This is done to achieve semantic security
// Much more efficient encoding to achieve semantic security is via quadratic residue

#[derive(Clone, PartialEq, Debug)]
pub struct ElGamalCipherTextAndPK<'a> {
    pub ctx: ElGamalCiphertext,
    pub pk: &'a ElGamalPublicKey,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct NonMellableElgamal {
    a: BigInt,
    b: BigInt,
    c: BigInt,
    d: BigInt,
}

//this is an encoding of a message in the field Z   q to a multiplicative subgroup group Gq
//that maintains quadratic residue and believed to maintain semantic security if p is a safe prime
//it does not appear in Citivas
pub fn encoding_quadratic_residue(m: BigInt, pp: &elgamal::ElGamalPP) -> BigInt {
    //modify m by adding 1 to m because the subgroup Gq does not include the value zero
    //Be very aware of that as it may originate a bug somewhere in the code!!!
    let m_modified = BigInt::mod_add(&m, &BigInt::one(), &pp.p);
    //check if m is QR according to Euler criterion
    let test_if_QR = BigInt::mod_pow(&m_modified, &pp.q, &pp.p);
    //if m is QR then return m otherwise return p - m
    return if test_if_QR == BigInt::one() {
        m_modified
    } else {
        BigInt::mod_sub(&pp.p, &m_modified, &pp.p)
    };
}

pub fn decoding_quadratic_residue(encoded_vote: BigInt, pp: &elgamal::ElGamalPP) -> BigInt {
    //modify m by adding 1 to m because the subgroup Gq does not include the value zero
    //Be very aware of that as it may originate a bug somewhere in the code!!!
    let encoded_modified = BigInt::mod_sub(&m, &BigInt::one(), &pp.p);
    //check if m is QR according to Euler criterion
    let test_if_QR = BigInt::mod_pow(&m_modified, &pp.q, &pp.p);
    //if m is QR then return m otherwise return p - m
    return if test_if_QR == BigInt::one() {
        encoded_modified
    } else {
        BigInt::mod_sub(&pp.p, &encoded_vote, &pp.p)
    };
}

impl NonMellableElgamal {
    //a simple EG encryption (a,b) that is signed with Schnorr (c,d)
    pub fn encrypt(m: &BigInt, y: &ElGamalPublicKey) -> Result<NonMellableElgamal, ElGamalError> {
        if m.ge(&y.pp.p) {
            return Err(ElGamalError::EncryptionError);
        }

        let r = BigInt::sample_below(&y.pp.q);
        let cipher = ElGamal::encrypt_from_predefined_randomness(&m, &y, &r).unwrap();
        let s = BigInt::sample_below(&y.pp.q);
        let g_s = BigInt::mod_pow(&y.pp.g, &s, &y.pp.p);
        let a = cipher.c1;
        let b = cipher.c2;
        let c = BigInt::mod_mul(
            &hash_sha256::HSha256::create_hash(&[&g_s, &a, &b]),
            &BigInt::from(1),
            &y.pp.q,
        );
        let d = BigInt::mod_add(&s, &BigInt::mod_mul(&c, &r, &y.pp.q), &&y.pp.q);
        Ok(Self { a, b, c, d })
    }

    pub fn decrypt(
        NMcipher: NonMellableElgamal,
        x: &ElGamalPrivateKey,
    ) -> Result<BigInt, ElGamalError> {
        let g_d = BigInt::mod_pow(&x.pp.g, &NMcipher.d, &x.pp.p);
        let a_c_inv = BigInt::mod_inv(
            &BigInt::mod_pow(&NMcipher.a, &NMcipher.c, &x.pp.p),
            &&x.pp.p,
        );
        let pre_hash_left_term = BigInt::mod_mul(&g_d, &a_c_inv, &x.pp.p);
        let V = hash_sha256::HSha256::create_hash(&[&pre_hash_left_term, &NMcipher.a, &NMcipher.b]);
        if V != NMcipher.c {
            panic!("received an invalid non malleable cipher!");
        }
        let cipher = ElGamalCiphertext {
            c1: NMcipher.a,
            c2: NMcipher.b,
            pp: x.pp.clone(),
        };
        ExponentElGamal::decrypt_exp(&cipher, &x)
    }

    pub fn encrypt_credential(
        share: &BigInt,
        KTT: &ElGamalPublicKey,
        r: &BigInt,
        rid: i32,
        vid: i32,
    ) -> Result<NonMellableElgamal, ElGamalError> {
        //Public key KTT
        //private credential share s ∈ M
        //Randomization factor r ∈ Z∗q ,
        //Identifiers of registration teller, rid , and voter, vid
        if share.ge(&KTT.pp.p) || r.ge(&KTT.pp.q) {
            return Err(ElGamalError::EncryptionError);
        }
        let cipher = ElGamal::encrypt_from_predefined_randomness(&share, &KTT, &r).unwrap();
        let t = BigInt::sample_below(&KTT.pp.q);
        let g_t = BigInt::mod_pow(&KTT.pp.g, &t, &KTT.pp.p);
        let a = cipher.c1;
        let b = cipher.c2;
        let c = hash_sha256::HSha256::create_hash(&[
            &g_t,
            &a,
            &b,
            &BigInt::from(rid),
            &BigInt::from(vid),
        ])
        .mod_floor(&KTT.pp.q);
        let d = BigInt::mod_add(&t, &BigInt::mod_mul(&c, &r, &KTT.pp.q), &&KTT.pp.q);
        Ok(Self { a, b, c, d })
    }

    pub fn verify_credential(
        public_credential_share: &NonMellableElgamal,
        rid: i32,
        vid: i32,
        pp: &elgamal::ElGamalPP,
    ) -> bool {
        let g_d = BigInt::mod_pow(&pp.g, &public_credential_share.d, &pp.p);
        let a_c_inv = BigInt::mod_inv(
            &BigInt::mod_pow(
                &public_credential_share.a,
                &public_credential_share.c,
                &pp.p,
            ),
            &&pp.p,
        );
        let pre_hash_left_term = BigInt::mod_mul(&g_d, &a_c_inv, &pp.p);
        let V = hash_sha256::HSha256::create_hash(&[
            &pre_hash_left_term,
            &public_credential_share.a,
            &public_credential_share.b,
            &BigInt::from(rid),
            &BigInt::from(vid),
        ]);
        V == public_credential_share.c
    }
}

pub fn reencrypt(c: &ElGamalCipherTextAndPK, random_nonce: &BigInt) -> ElGamalCiphertext {
    assert!(random_nonce.le(&c.pk.pp.q));
    let a = &c.ctx.c1;
    let b = &c.ctx.c2;
    let g_r = BigInt::mod_pow(&c.pk.pp.g, &random_nonce, &c.pk.pp.p);
    let c1 = BigInt::mod_mul(&g_r, &a, &c.pk.pp.p);
    // println!("g_r {:?}, rand = {:?}, a = {:?}, c1 = {:?}", g_r, random_nonce, a,c1);
    let s = BigInt::mod_pow(&c.pk.h, &random_nonce, &c.pk.pp.p);
    let c2 = BigInt::mod_mul(&s, &b, &c.pk.pp.p);
    ElGamalCiphertext {
        c1,
        c2,
        pp: c.pk.pp.clone(),
    }
}


//The only difference between this function and Zengo's is that here we exect to get a quadratic residue encoding, so that
// m is taken from z_p and not z_q
pub fn encrypt_from_predefined_randomness(
    m: &BigInt,
    pk: &ElGamalPublicKey,
    randomness: &BigInt,
) -> Result<ElGamalCiphertext, ElGamalError> {
    //test 0<m<p
    if m.ge(&pk.pp.p) || m.le(&BigInt::zero()) {
        println!("1!");
        println!("m:{:?}",m);
        println!("p:{:?}",pk.pp.p);

        return Err(ElGamalError::EncryptionError);
    }
    if randomness.ge(&pk.pp.q) || randomness.le(&BigInt::zero()) {
        println!("2!");
        return Err(ElGamalError::EncryptionError);
    }
    let y = randomness;
    let c1 = BigInt::mod_pow(&pk.pp.g, y, &pk.pp.p);
    let s = BigInt::mod_pow(&pk.h, y, &pk.pp.p);
    //  let sm = &s * &m;
    let c2 = BigInt::mod_mul(&s, &m, &pk.pp.p);
    Ok(ElGamalCiphertext {
        c1,
        c2,
        pp: pk.pp.clone(),
    })
}


pub fn reencrypt_disjoint_structs(
    c: &ElGamalCiphertext,
    pk: ElGamalPublicKey,
    r: &BigInt,
) -> ElGamalCiphertext {
    if r.ge(&c.pp.q) {
        panic!("not a valid random r");
    };
    if pk.pp != c.pp {
        panic!("mismatch pp");
    }
    let a = &c.c1;
    let b = &c.c2;
    let g_r = BigInt::mod_pow(&c.pp.g, &r, &c.pp.p);
    let c1 = BigInt::mod_mul(&g_r, &a, &c.pp.p);
    let s = BigInt::mod_pow(&pk.h, &r, &c.pp.p);
    let c2 = BigInt::mod_mul(&s, &b, &c.pp.p);
    ElGamalCiphertext {
        c1,
        c2,
        pp: c.pp.clone(),
    }
}
