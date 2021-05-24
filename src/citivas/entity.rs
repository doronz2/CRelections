use crate::ElGamalPublicKey;
use curv::BigInt;
use elgamal::ElGamalPP;

pub trait Entity {
    fn get_pp(&self) -> &ElGamalPP;
    fn get_pk(&self) -> &BigInt;
    fn get_p(&self) -> &BigInt;
    fn get_q(&self) -> &BigInt;
    fn get_tally_pk(&self) -> &ElGamalPublicKey;
    fn get_generator(&self) -> &BigInt;
}
