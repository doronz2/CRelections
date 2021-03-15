use curv::BigInt;
use elgamal::ElGamalPP;
use crate::ElGamalKeyPair;


pub trait Entity{
    fn get_pp(&self)-> &ElGamalPP;
    fn get_pk(&self)-> &BigInt;
    fn get_sk(&self)-> &BigInt;
    fn get_p(&self) -> &BigInt;
    fn get_q(&self) -> &BigInt;
    fn get_tally_pk(&self) -> &BigInt;
    fn get_generator(&self) -> &BigInt;
    fn get_key_pair(&self) -> &ElGamalKeyPair{
        &self.KTT
    }
 //   fn create(entity_index: usize, pp: ElGamalPP) -> Self;
 //   fn create_voter_from_given_sk(entity_index: usize, pp: ElGamalPP, sk: BigInt) -> Self;

}