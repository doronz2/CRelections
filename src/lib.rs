
#[macro_use]
pub mod macros{
    macro_rules! sample_from{
        ($pp: expr) => {
        BigInt::sample_below($pp);
        };
    }
}

pub mod citivas;
pub use elgamal::{ElGamal,rfc7919_groups::SupportedGroups,ElGamalPP,
ElGamalKeyPair,ElGamalError,ElGamalCiphertext,
ElGamalPrivateKey,ElGamalPublicKey,ExponentElGamal};
use elgamal::BigInt;
use curv::arithmetic::traits::Modulo;


pub enum Error{
    FailedMixError,
    EncryptionError
}

pub fn encrypt_toy(m: &BigInt, pk: &ElGamalPublicKey) -> Result<ElGamalCiphertext, ElGamalError> {
    //test 0<m<p
    if m.ge(&pk.pp.q) || m.le(&BigInt::zero()) {
        return Err(ElGamalError::EncryptionError);
    }
    let y = BigInt::from(2);
    let c1 = BigInt::mod_pow(&pk.pp.g, &y, &pk.pp.p);
    let s = BigInt::mod_pow(&pk.h, &y, &pk.pp.p);
    let c2 = BigInt::mod_mul(&s, &m, &pk.pp.p);
    Ok(ElGamalCiphertext {
        c1,
        c2,
        pp: pk.pp.clone(),
    })
}

pub fn generate_keys_toy(pp: &ElGamalPP) -> ElGamalKeyPair {
    let x = BigInt::from(7);
    let h = BigInt::mod_pow(&pp.g, &x, &pp.p);
    let pk = ElGamalPublicKey { pp: pp.clone(), h };
    let sk = ElGamalPrivateKey { pp: pp.clone(), x };
    ElGamalKeyPair { pk, sk }
}


pub fn generate_pp_toy() -> ElGamalPP {
   ElGamalPP{
       g: BigInt::from(2),
       q: BigInt::from(509),// q is Sophie Germain prime
       p: BigInt::from(1019)//p is a safe prime
   }
}
