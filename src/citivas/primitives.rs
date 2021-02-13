use elgamal::{ElGamal,rfc7919_groups::SupportedGroups,ElGamalPP,
              ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
              ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use curv::BigInt;

use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;


//use elgamal::ElGamalKeyPair;

//General comment. Citivas implements the encoding messages are via exponent, i.e., G^m mod p. This is done to achieve semantic security
// Much more efficient encoding to achieve semantic security is via quadratic residue


pub struct NonMellableElgamal{
    a: BigInt,
    b: BigInt,
    c: BigInt,
    d: BigInt,
}

pub struct DVRP_PublicInput{ //stands for designated-verifier reencryption proof
    x: ElGamalPublicKey, //El-Gamal cipher
    y: ElGamalPublicKey, //El-Gamal cipher
    x_tag: ElGamalPublicKey, //El-Gamal cipher reencyption of x
    y_tag: ElGamalPublicKey, //El-Gamal cipher reencyption of y
    h_v: ElGamalKeyPair, //public key pair
    g: BigInt, //generator of the x group
    h: BigInt, //generator of the y group
    q: BigInt, //order of the groups
    p: BigInt //field size
  }

pub struct DVRP_ProverOutput{ //stands for designated-verifier reencryption proof
    c: BigInt,
    w: BigInt,
    r: BigInt,
    u: BigInt,
}

const L:usize = 8; //number of alternatives to the encryption

pub struct ReencPF_Input{
    U : [BigInt;L],//list of candidate for encryption
    V : [BigInt;L],//list of candidate for encryption
    c : (BigInt, BigInt),
    g: BigInt, //u's generator
    y: BigInt, //v's generator
    p: BigInt,
    q: BigInt
  }


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





impl NonMellableElgamal {
    //a simple EG encryption (a,b) that is signed with Schnorr (c,d)
    pub fn encrypt(m: &BigInt, y: &ElGamalPublicKey) -> Result<NonMellableElgamal, ElGamalError> {
        if m.ge(&y.pp.p) {
            return Err(ElGamalError::EncryptionError)
        }

        let r = BigInt::sample_below(&y.pp.q);
        let cipher = ElGamal::encrypt_from_predefined_randomness(&m, &y, &r).unwrap();
        let s = BigInt::sample_below(&y.pp.q);
        let g_s = BigInt::mod_pow(&y.pp.g, &s, &y.pp.p);
        let a = cipher.c1;
        let b = cipher.c2;
        let c = BigInt::mod_mul(&hash_sha256::HSha256::create_hash(
            &[&g_s, &a, &b]), &BigInt::from(1), &y.pp.q
        );
        let d = BigInt::mod_add(&s, &BigInt::mod_mul(&c, &r, &y.pp.q), &&y.pp.q);
        Ok(Self{ a, b, c, d })
    }

    pub fn decrypt(NMcipher: NonMellableElgamal, x: &ElGamalPrivateKey) -> Result<BigInt, ElGamalError> {
        let g_d = BigInt::mod_pow(&x.pp.g, &NMcipher.d, &x.pp.p);
        let a_c_inv = BigInt::mod_inv(
            &BigInt::mod_pow(&NMcipher.a, &NMcipher.c, &x.pp.p)
            , &&x.pp.p);
        let pre_hash_left_term = BigInt::mod_mul(&g_d, &a_c_inv, &x.pp.p);
        let V = hash_sha256::HSha256::create_hash(&[&pre_hash_left_term, &NMcipher.a, &NMcipher.b]);
        if V != NMcipher.c {
            panic!("received an invalid non malleable cipher!");
        }
        let cipher = ElGamalCiphertext { c1: NMcipher.a, c2: NMcipher.b, pp: x.pp.clone() };
        ExponentElGamal::decrypt_exp(&cipher, &x)
    }


    pub fn encrypt_credential(share: &BigInt, KTT: &ElGamalPublicKey, r: &BigInt, rid: i32, vid: i32)
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
            &[&g_t, &a, &b, &BigInt::from(rid), &BigInt::from(vid)]), &BigInt::from(1), &KTT.pp.q
        );
        let d = BigInt::mod_add(&t, &BigInt::mod_mul(&c, &r, &KTT.pp.q), &&KTT.pp.q);
        Ok(Self{ a, b, c, d })
    }


    pub fn verify_credential(public_credential_share: &NonMellableElgamal, rid: &BigInt, vid: &BigInt, pp: elgamal::ElGamalPP) -> bool {
        let g_d = BigInt::mod_pow(&pp.g, &public_credential_share.d, &pp.p);
        let a_c_inv = BigInt::mod_inv(
            &BigInt::mod_pow(&public_credential_share.a, &public_credential_share.c, &pp.p)
            , &&pp.p);
        let pre_hash_left_term = BigInt::mod_mul(&g_d, &a_c_inv, &pp.p);
        let V = hash_sha256::HSha256::create_hash(
            &[&pre_hash_left_term, &public_credential_share.a, &public_credential_share.b]
        );
        V == public_credential_share.c
    }
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

//a technical function that computes (x/x')^c mod p
fn div_and_pow(x: &BigInt, x_tag: &BigInt, c: &BigInt, p: &BigInt) -> BigInt {
    BigInt::mod_pow(&(x_tag * BigInt::mod_inv(&x, &p)), &c, &p)
}

impl DVRP_PublicInput {
    pub fn DVRP_prover(self, eta: BigInt) -> DVRP_ProverOutput {
        let d = BigInt::sample_below(&self.q);
        let w = BigInt::sample_below(&self.q);
        let r = BigInt::sample_below(&self.q);
        let a = BigInt::mod_pow(&self.g, &d, &self.p);
        let b = BigInt::mod_pow(&self.h, &d, &self.p);
        let s = BigInt::mod_mul(&BigInt::mod_pow(&self.g, &w, &self.p),
                                &BigInt::mod_pow(&self.h_v.pk.h, &r, &self.p),
                                &self.p);
        let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &[&self.x.h, &self.y.h, &self.x_tag.h, &self.y_tag.h, &a, &b, &s]
        ), &self.q);
        let u = &d + &eta * (&c + &w);
        DVRP_ProverOutput { c, w, r, u }
    }


    pub fn DVRP_verifier(self, po: DVRP_ProverOutput) -> bool {
        //a′ = g^u/(x′/x)^(c+w) mod p
        let a_tag: BigInt = BigInt::mod_pow(&self.g, &po.u, &self.p) *
            BigInt::mod_inv(&Self::div_and_pow(&self.x.h, &self.x_tag.h, &(&po.c + &po.w), &self.p)
                            , &self.p);
        let b_tag: BigInt = BigInt::mod_pow(&self.h, &po.u, &self.p) *
            BigInt::mod_inv(&Self::div_and_pow(&self.y.h, &self.y_tag.h, &(&po.c + &po.w), &self.p)
                            , &self.p);
        let s_tag = BigInt::mod_mul(&BigInt::mod_pow(&self.g, &po.w, &self.p),
                                    &BigInt::mod_pow(&self.h_v.pk.h, &po.r, &self.p),
                                    &self.p);
        let c_tag = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &[&self.x.h, &self.y.h, &self.x_tag.h, &self.y_tag.h, &a_tag, &b_tag, &s_tag]
        ), &self.q);
        c_tag == po.c
    }

    pub fn fakeDVRP_prover(self, eta: BigInt) -> DVRP_ProverOutput {
        let alpha = BigInt::sample_below(&self.q);
        let beta = BigInt::sample_below(&self.q);
        let u_tilde = BigInt::sample_below(&self.q);
        let a_tilde: BigInt = BigInt::mod_pow(&self.g, &u_tilde, &self.p) *
            BigInt::mod_inv(&div_and_pow(&self.x.h, &self.x_tag.h, &alpha, &self.p)
                            , &self.p);
        let b_tilde: BigInt = BigInt::mod_pow(&self.h, &u_tilde, &self.p) *
            BigInt::mod_inv(&div_and_pow(&self.y.h, &self.y_tag.h, &alpha, &self.p)
                            , &self.p);
        let s_tilde = BigInt::mod_pow(&self.g, &beta, &self.p);
        let c_tilde = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
            &[&self.x.h, &self.y.h, &self.x_tag.h, &self.y_tag.h, &a_tilde, &b_tilde, &s_tilde]
        ), &self.q);
        let w_tilde = BigInt::mod_floor(&(&alpha - &c_tilde), &self.q);
        let r_tilde = BigInt::mod_floor(&(&(&beta - &w_tilde) * BigInt::mod_inv(&self.h_v.sk.x, &self.q))
                                        , &self.q);
        DVRP_ProverOutput{
            c: c_tilde,
            w: w_tilde,
            r: r_tilde,
            u: u_tilde
        }
    }
}

// This function proves the there is some c_i in c_1,...,c_l that is an encryption of C
// Hirt, Sako: Efficient receipt-free voting based on homomorphic encryption
impl ReencPF_Input {
    pub fn reencpf(self, t: usize, r: BigInt) {
        let (u,v) = self.c;
        let mut list_d_i: [BigInt; L] = [BigInt::zero(); L];
        let mut list_r_i: [BigInt; L] = [BigInt::zero(); L];
        let mut list_a_i: [BigInt; L] = [BigInt::zero(); L];
        let mut list_b_i: [BigInt; L] = [BigInt::zero(); L];
        for i in 1..L {
            list_d_i[i] = BigInt::sample_below(&self.q);
            list_r_i[i] = BigInt::sample_below(&self.q);
        }
        for i in 1..L {
             list_a_i[i] = BigInt::div_floor(div_and_pow(&self.U[i], &u,&list_d_i[i], &p) *
                                                 BigInt::mod_pow(&self.g, &r, &p) , &p)
             list_b_i[i] = BigInt::div_floor(div_and_pow(&self.V[i], &u,&list_d_i[i], &p) *
                                                BigInt::mod_pow(&self.y, &r, &p) , &p)
            let E = [&u,&v,&U,&V];
            let c = BigInt::mod_floor(&hash_sha256::HSha256::create_hash(
                &[&E, &list_a_i, &list_b_i].iter().flatten().collect())
                                      , &self.q);
            let w = BigInt::mod_floor(&list_r_i[t] - &r * &list_d_i[t], &self.q);
            let D = BigInt::mod_floor(&c - (&list_d_i.iter().sum() - &list_d_i[t])
                                      , &self.q);

        }
    }
}