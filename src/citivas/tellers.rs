use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalPublicKey};

use serde::{Deserialize, Serialize};

use crate::citivas::dist_el_gamal::{DistDecryptEGMsg, DistElGamal};
use crate::citivas::encryption_schemes::{reencrypt, ElGamalCipherTextAndPK};
use crate::citivas::supervisor::SystemParameters;
use crate::citivas::voter::Vote;
use crate::citivas::zkproofs::{ReencProofInput, VotepfPublicInput};
use elgamal::ElGamalPP;
use rand::seq::SliceRandom;
use rand::thread_rng;
use vice_city::utlities::ddh_proof::{DDHProof, DDHStatement, DDHWitness, NISigmaProof};
const OUT: bool = true;
const IN: bool = false;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Teller {
    share: DistElGamal,
    sp: SystemParameters,
    pub teller_index: i32,
}

#[derive(Clone, PartialEq, Debug)]
pub struct MixInput<'a> {
    pub(crate) ctx_list: Vec<ElGamalCipherTextAndPK<'a>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MixOutput {
    pub ctx_mix_list: Vec<ElGamalCiphertext>,
    pub comm_to_shuffle_list: Vec<BigInt>,
}

impl Teller {
    pub fn create_teller(sp: SystemParameters, teller_index: i32) -> Self {
        let share = DistElGamal::generate_share(&sp.pp, teller_index);
        Teller {
            share,
            sp,
            teller_index,
        }
    }
}

pub struct TellerMixingParams {
    r_list: Vec<BigInt>,  // the r parameter for reencryption of the ctx
    w_list: Vec<BigInt>,  // the w parameter for committing the ctx
    perm: Vec<usize>,     //representation of the random permutation of the ciphertexts (mixing)
    inv_perm: Vec<usize>, //representation of the inverse random permutation of the ciphertexts (mixing)
}

impl Teller {
    pub fn get_share(&self) -> &DistElGamal {
        &self.share
    }

    pub fn get_public_share(self) -> BigInt {
        self.share.get_public_share()
    }

    pub fn get_private_share(self) -> BigInt {
        self.share.get_private_share()
    }

    //not that some code is redundent as the lists (permuted and its inverse are computed twice for both directions
    pub fn mix(self, mix_input: MixInput, dir: bool) -> (MixOutput, TellerMixingParams) {
        let mut rng = thread_rng();
        let m = self.sp.num_of_voters;
        let mut permuted_indices: Vec<usize> = (0..m).collect();
        permuted_indices.shuffle(&mut rng);
        println!("permuted: {:?}", permuted_indices);
        // let inverse_permuted_indices: [usize;m] = [0;m];
        let inverse_permuted_indices: Vec<usize> = (0..m)
            .map(|i| permuted_indices.iter().position(|&e| e == i).unwrap())
            .collect();
        println!("permuted inverse: {:?}", inverse_permuted_indices);

        let permuted_ctx: Vec<&ElGamalCipherTextAndPK> = permuted_indices
            .iter()
            .map(|&i| mix_input.ctx_list.get(i).unwrap())
            .collect();

        let mut l_r = Vec::with_capacity(m);
        let mut l_c = Vec::with_capacity(m);
        let mut r_list: Vec<BigInt> = Vec::with_capacity(m);
        let mut w_list: Vec<BigInt> = Vec::with_capacity(m);

        for i in 0..m {
            let r_i = BigInt::sample_below(&self.sp.pp.q);
            r_list.push(r_i.clone());
            l_r.push(reencrypt(&permuted_ctx[i], &r_i));

            let w_i = BigInt::sample_below(&self.sp.o);
            w_list.push(w_i.clone());

            if dir == IN {
                l_c.push(hash_sha256::HSha256::create_hash(&[
                    &BigInt::from(permuted_indices[i] as i32),
                    &w_i,
                ]));
            } else {
                l_c.push(hash_sha256::HSha256::create_hash(&[
                    &BigInt::from(inverse_permuted_indices[i] as i32),
                    &w_i,
                ]));
            }
        }
        (
            MixOutput {
                ctx_mix_list: l_r,
                comm_to_shuffle_list: l_c,
            },
            TellerMixingParams {
                r_list,
                w_list,
                perm: Vec::from(permuted_indices),
                inv_perm: inverse_permuted_indices,
            },
        )
    }

    // Verify the proofs of votepf and reencryption
    // move function to tallies
    pub fn check_votes(vote: &Vote, params: &SystemParameters, pk: &ElGamalPublicKey) -> bool {
        let vote_pf_input = VotepfPublicInput {
            encrypted_credential: vote.es.clone(),
            encrypted_choice: vote.ev.clone(),
            eid: BigInt::from(params.eid),
        };
        let check_1 = vote.pf.votepf_verifier(&vote_pf_input, params);

        let reenc_proof_input = ReencProofInput {
            c_list: params.encrypted_candidate_list.clone().unwrap(),
            c: vote.ev.clone(),
        };

        let check_2 = reenc_proof_input.reenc_1_out_of_l_verifier(
            &params.pp,
            pk,
            &vote.pw,
            params.num_of_candidates,
        );

        check_1 && check_2
    }
}

// ── Plaintext Equivalence Test (PET) ──────────────────────────────────────
// Paper: Civitas appendix B.3, due to Jakobsson and Juels.
// Tests whether two ciphertexts encrypt the same plaintext under K_TT.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PetZShare {
    pub d_i: BigInt,
    pub e_i: BigInt,
    pub commitment: BigInt,
    pub eq_dlogs_proof: DDHProof,
    pub party_index: i32,
}

impl Teller {
    /// Step 1–2: compute and commit to the z_i multiplication share.
    pub fn pet_z_share(
        &self,
        c1: &ElGamalCiphertext,
        c2: &ElGamalCiphertext,
    ) -> PetZShare {
        let pp = &self.sp.pp;
        let z_i = BigInt::sample_below(&pp.q);

        // R = c1 / c2 = (a1/a2, b1/b2)
        let d = BigInt::mod_mul(
            &c1.c1,
            &BigInt::mod_inv(&c2.c1, &pp.p),
            &pp.p,
        );
        let e = BigInt::mod_mul(
            &c1.c2,
            &BigInt::mod_inv(&c2.c2, &pp.p),
            &pp.p,
        );

        let d_i = BigInt::mod_pow(&d, &z_i, &pp.p);
        let e_i = BigInt::mod_pow(&e, &z_i, &pp.p);
        let commitment = hash_sha256::HSha256::create_hash(&[&d_i, &e_i]);

        // EqDlogs: proves log_d(d_i) = log_e(e_i) = z_i  ≡  DDH tuple (d, d_i, e, e_i)
        let statement = DDHStatement {
            pp: pp.clone(),
            g1: d.clone(),
            h1: d_i.clone(),
            g2: e.clone(),
            h2: e_i.clone(),
        };
        let proof = DDHProof::prove(&DDHWitness { x: z_i }, &statement);

        PetZShare {
            d_i,
            e_i,
            commitment,
            eq_dlogs_proof: proof,
            party_index: self.teller_index,
        }
    }

    /// Full PET protocol: returns true iff c1 and c2 encrypt the same plaintext.
    /// `tellers` must be the complete set so distributed decryption can proceed.
    pub fn pet(
        c1: &ElGamalCiphertext,
        c2: &ElGamalCiphertext,
        tellers: &[Teller],
        pp: &ElGamalPP,
    ) -> bool {
        // Phase 1: each teller computes (d_i, e_i) = R^z_i and publishes commitment + proof
        let z_shares: Vec<PetZShare> = tellers
            .iter()
            .map(|t| t.pet_z_share(c1, c2))
            .collect();

        let d = BigInt::mod_mul(&c1.c1, &BigInt::mod_inv(&c2.c1, &pp.p), &pp.p);
        let e = BigInt::mod_mul(&c1.c2, &BigInt::mod_inv(&c2.c2, &pp.p), &pp.p);

        // Steps 3–5: verify commitments and EqDlogs proofs before accepting shares
        let valid_z: Vec<&PetZShare> = z_shares
            .iter()
            .filter(|s| {
                let comm = hash_sha256::HSha256::create_hash(&[&s.d_i, &s.e_i]);
                if comm != s.commitment {
                    return false;
                }
                let stmt = DDHStatement {
                    pp: pp.clone(),
                    g1: d.clone(),
                    h1: s.d_i.clone(),
                    g2: e.clone(),
                    h2: s.e_i.clone(),
                };
                s.eq_dlogs_proof.verify(&stmt).is_ok()
            })
            .collect();

        // All tellers must contribute a valid share — a single compromised teller
        // can bias the PET result, so we require n-of-n.
        if valid_z.len() != z_shares.len() {
            return false;
        }

        // Step 6: c' = (∏d_i, ∏e_i)
        let c_prime_c1 = valid_z
            .iter()
            .fold(BigInt::one(), |acc, s| BigInt::mod_mul(&acc, &s.d_i, &pp.p));
        let c_prime_c2 = valid_z
            .iter()
            .fold(BigInt::one(), |acc, s| BigInt::mod_mul(&acc, &s.e_i, &pp.p));
        let c_prime = ElGamalCiphertext {
            c1: c_prime_c1,
            c2: c_prime_c2,
            pp: pp.clone(),
        };

        // Step 7: DistDec(c') using K_TT shares
        let dec_msgs: Vec<DistDecryptEGMsg> = tellers
            .iter()
            .map(|t| t.share.publish_shares_and_proofs_for_decryption(&c_prime))
            .collect();

        let valid_dec: Vec<BigInt> = tellers
            .iter()
            .zip(dec_msgs.iter())
            .filter(|(t, msg)| {
                t.share
                    .verify_proof_for_decryption(&c_prime, msg, t.teller_index)
            })
            .map(|(_, msg)| msg.share.clone())
            .collect();

        let m_prime = DistElGamal::combine_shares_and_decrypt(&c_prime, valid_dec, pp);

        // Step 8: m' = 1  ⟺  m1 = m2
        m_prime == BigInt::one()
    }
}

// ── MixNet verification ───────────────────────────────────────────────────
// Paper: Civitas appendix B.3 ALGORITHM: Mix + PROTOCOL: MixNet
// Each teller produces two passes (out + in); a random challenge Q then
// selects which pass is opened for each position.

/// All data a teller needs to retain after mixing so it can respond to challenges.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TellerMixRecord {
    pub teller_index: i32,
    /// First-pass output (Mix with dir=out): permuted + reencrypted list
    pub mix_out: MixOutput,
    /// Second-pass output (Mix with dir=in): re-permuted + reencrypted list
    pub mix_in: MixOutput,
    /// Mixing parameters for both passes, kept secret until the challenge
    params_out: TellerMixingParamsOwned,
    params_in: TellerMixingParamsOwned,
    /// The teller's random contribution q_i to the challenge seed
    pub q_i: BigInt,
    pub commitment_q: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TellerMixingParamsOwned {
    r_list: Vec<BigInt>,
    w_list: Vec<BigInt>,
    perm: Vec<usize>,
    inv_perm: Vec<usize>,
}

impl From<TellerMixingParams> for TellerMixingParamsOwned {
    fn from(p: TellerMixingParams) -> Self {
        Self {
            r_list: p.r_list,
            w_list: p.w_list,
            perm: p.perm,
            inv_perm: p.inv_perm,
        }
    }
}

impl Teller {
    /// Perform both Mix passes and commit to the q_i challenge seed.
    pub fn mix_both_passes(
        &self,
        input_list: &[ElGamalCipherTextAndPK<'_>],
        pk: &ElGamalPublicKey,
    ) -> TellerMixRecord {
        let _m = input_list.len();
        let mut rng = thread_rng();

        // First pass: Mix(L, out)
        let (mix_out, params_out) = self.mix_pass(input_list, OUT, &mut rng);

        // Second pass: Mix(first-pass output, in)
        let l2: Vec<ElGamalCipherTextAndPK<'_>> = mix_out
            .ctx_mix_list
            .iter()
            .map(|c| ElGamalCipherTextAndPK { ctx: c.clone(), pk })
            .collect();
        let (mix_in, params_in) = self.mix_pass(&l2, IN, &mut rng);

        // q_i is a random commitment seed
        let q_i = BigInt::sample_below(&self.sp.o);
        let commitment_q = hash_sha256::HSha256::create_hash(&[&q_i]);

        TellerMixRecord {
            teller_index: self.teller_index,
            mix_out,
            mix_in,
            params_out: params_out.into(),
            params_in: params_in.into(),
            q_i,
            commitment_q,
        }
    }

    fn mix_pass(
        &self,
        input: &[ElGamalCipherTextAndPK<'_>],
        dir: bool,
        rng: &mut impl rand::Rng,
    ) -> (MixOutput, TellerMixingParams) {
        let m = input.len();
        let mut perm: Vec<usize> = (0..m).collect();
        perm.shuffle(rng);
        let inv_perm: Vec<usize> = (0..m)
            .map(|i| perm.iter().position(|&e| e == i).unwrap())
            .collect();

        let mut l_r = Vec::with_capacity(m);
        let mut l_c = Vec::with_capacity(m);
        let mut r_list = Vec::with_capacity(m);
        let mut w_list = Vec::with_capacity(m);

        for i in 0..m {
            let r_i = BigInt::sample_below(&self.sp.pp.q);
            r_list.push(r_i.clone());

            // p(i): source index used in both L_R and L_C so the verifier can check both.
            // IN:  output i comes from input π(i)   → p(i) = perm[i]
            // OUT: output i comes from input π⁻¹(i) → p(i) = inv_perm[i]
            let p_i = if dir == IN { perm[i] } else { inv_perm[i] };
            l_r.push(reencrypt(&input[p_i], &r_i));

            let w_i = BigInt::sample_below(&self.sp.o);
            w_list.push(w_i.clone());
            l_c.push(hash_sha256::HSha256::create_hash(&[
                &BigInt::from(p_i as i32),
                &w_i,
            ]));
        }

        (
            MixOutput { ctx_mix_list: l_r, comm_to_shuffle_list: l_c },
            TellerMixingParams { r_list, w_list, perm, inv_perm },
        )
    }
}

/// One teller's selective-disclosure response to the MixNet challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MixReveal {
    pub teller_index: i32,
    /// For each position j: (r_j, w_j, p(j)) from whichever pass Q_i[j] selects
    pub reveals: Vec<(BigInt, BigInt, usize)>,
}

impl TellerMixRecord {
    /// Build the reveal for position j given the challenge bit Q_i_j.
    /// Q_i_j = 0 → open the out pass; Q_i_j = 1 → open the in pass.
    pub fn build_reveal(&self, q_i_bits: &[u8]) -> MixReveal {
        let reveals = q_i_bits
            .iter()
            .enumerate()
            .map(|(j, &bit)| {
                let params = if bit == 0 { &self.params_out } else { &self.params_in };
                // Reveal p(j): for OUT (bit=0) p = π⁻¹ → reveal inv_perm[j]
                //              for IN  (bit=1) p = π   → reveal perm[j]
                let p_j = if bit == 0 { params.inv_perm[j] } else { params.perm[j] };
                (params.r_list[j].clone(), params.w_list[j].clone(), p_j)
            })
            .collect();
        MixReveal { teller_index: self.teller_index, reveals }
    }
}

/// Verify one teller's MixNet reveal against its published commitments.
/// `input_to_out_pass` is the input list to this teller's OUT pass.
pub fn verify_mix_reveal(
    record: &TellerMixRecord,
    reveal: &MixReveal,
    input_to_out_pass: &[ElGamalCiphertext],
    q_i_bits: &[u8],
    pk: &ElGamalPublicKey,
) -> bool {
    for (j, &bit) in q_i_bits.iter().enumerate() {
        let (ref r_j, ref w_j, p_j) = reveal.reveals[j];
        let mix = if bit == 0 { &record.mix_out } else { &record.mix_in };

        // Source list: OUT pass reads from the teller's input;
        //              IN  pass reads from the OUT pass output.
        let src_ctx = if bit == 0 {
            input_to_out_pass[p_j].clone()
        } else {
            record.mix_out.ctx_mix_list[p_j].clone()
        };

        // 1. Verify commitment: hash(p_j, w_j) = comm[j]
        let expected_comm = hash_sha256::HSha256::create_hash(&[&BigInt::from(p_j as i32), w_j]);
        if expected_comm != mix.comm_to_shuffle_list[j] {
            return false;
        }

        // 2. Verify reencryption: Reenc(src[p_j]; r_j) = mix.ctx_mix_list[j]
        let reenc = reencrypt(&ElGamalCipherTextAndPK { ctx: src_ctx, pk }, r_j);
        if reenc != mix.ctx_mix_list[j] {
            return false;
        }
    }
    true
}

/// Run the full MixNet protocol across all tellers and verify.
/// Returns the anonymised ciphertext list, or None if any teller fails verification.
pub fn run_mixnet<'a>(
    initial_list: Vec<ElGamalCiphertext>,
    tellers: &[Teller],
    pk: &'a ElGamalPublicKey,
) -> Option<Vec<ElGamalCiphertext>> {
    let n = tellers.len();
    let m = initial_list.len();

    // Step 1: tellers run in sequence — each mixes the previous teller's IN-pass output
    let mut records: Vec<TellerMixRecord> = Vec::with_capacity(tellers.len());
    for (idx, teller) in tellers.iter().enumerate() {
        let input: Vec<ElGamalCipherTextAndPK<'_>> = if idx == 0 {
            initial_list.iter().map(|c| ElGamalCipherTextAndPK { ctx: c.clone(), pk }).collect()
        } else {
            records[idx - 1].mix_in.ctx_mix_list.iter()
                .map(|c| ElGamalCipherTextAndPK { ctx: c.clone(), pk })
                .collect()
        };
        records.push(teller.mix_both_passes(&input, pk));
    }

    // Step 2: verify that every teller's q_i matches its earlier commitment
    for record in &records {
        let expected = hash_sha256::HSha256::create_hash(&[&record.q_i]);
        if expected != record.commitment_q {
            return None;
        }
    }

    // Step 3: Q = hash(q_1, ..., q_n)
    let q_inputs: Vec<&BigInt> = records.iter().map(|r| &r.q_i).collect();
    let big_q = hash_sha256::HSha256::create_hash(&q_inputs);

    // Step 4: for each teller i, Q_i = hash(Q, i); derive challenge bits
    let mut all_ok = true;
    for (idx, record) in records.iter().enumerate() {
        let _ = n; // n used for future threshold checks
        // Q_i[j] = hash(Q, teller_index, j) mod 2 — one independent bit per position
        let q_i_bits: Vec<u8> = (0..m)
            .map(|j| {
                let h = hash_sha256::HSha256::create_hash(&[
                    &big_q,
                    &BigInt::from(record.teller_index),
                    &BigInt::from(j as i32),
                ]);
                (h.mod_floor(&BigInt::from(2)) == BigInt::one()) as u8
            })
            .collect();

        let reveal = record.build_reveal(&q_i_bits);

        // The input to teller i's mix is either the initial list (i=0)
        // or the in-pass output of the previous teller
        let src_list: Vec<ElGamalCiphertext> = if idx == 0 {
            initial_list.clone()
        } else {
            records[idx - 1].mix_in.ctx_mix_list.clone()
        };

        if !verify_mix_reveal(record, &reveal, &src_list, &q_i_bits, pk) {
            all_ok = false;
        }
    }

    if !all_ok {
        return None;
    }

    Some(records.last().unwrap().mix_in.ctx_mix_list.clone())
}
