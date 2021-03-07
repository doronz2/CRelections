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



}

