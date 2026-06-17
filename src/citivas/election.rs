//! High-level election infrastructure wrapping the Civitas cryptographic core.
//!
//! Lifecycle:
//!   1. `Election::setup`   — generate shared KTT key, create tellers & registrars
//!   2. `election.register` — issue credentials to each voter
//!   3. `election.submit_vote` — accept validated ballots
//!   4. `election.tabulate` — run the full pipeline and return the tally

use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalPP, ElGamalPublicKey};
use serde::{Deserialize, Serialize};

use crate::citivas::dist_el_gamal::{CommitmentKeyGen, DistElGamal, KeyProof};
use crate::citivas::entity::Entity;
use crate::citivas::encryption_schemes::{
    encoding_quadratic_residue, encrypt_from_predefined_randomness,
};
use crate::citivas::registrar::{CredetialShareOutput, Registrar};
use crate::citivas::supervisor::SystemParameters;
use crate::citivas::tellers::{run_mixnet, Teller};
use crate::citivas::voter::{Vote, Voter};
use crate::citivas::zkproofs::DvrpPublicInput;

// ── Result types ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElectionResult {
    /// Vote count for each candidate (index = candidate index).
    pub counts: Vec<usize>,
    /// Total ballots submitted.
    pub total_cast: usize,
    /// Ballots that passed VotePf + ReencPf validation.
    pub num_valid_proofs: usize,
    /// Duplicate ballots removed (same credential voted more than once).
    pub num_duplicates_removed: usize,
    /// Ballots removed because credential was not registered.
    pub num_invalid_credential: usize,
    /// Ballots that were decrypted and tallied.
    pub num_counted: usize,
}

impl ElectionResult {
    /// Index of the candidate with the most votes (None if no votes cast).
    pub fn winner(&self) -> Option<usize> {
        self.counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &c)| c)
            .filter(|(_, &c)| c > 0)
            .map(|(i, _)| i)
    }
}

// ── Election ──────────────────────────────────────────────────────────────

pub struct Election {
    /// System-wide parameters (group, candidate list, election id, …).
    pub params: SystemParameters,
    /// Shared KTT (tabulation-teller) public key.
    pub pk: ElGamalPublicKey,
    tellers: Vec<Teller>,
    registrars: Vec<Registrar>,
    /// One registered credential ciphertext per voter, stored after `register`.
    registered_credentials: Vec<ElGamalCiphertext>,
    /// Accepted ballots.
    pub ballot_box: Vec<Vote>,
}

impl Election {
    // ── Setup ────────────────────────────────────────────────────────────

    /// Create an election: build the shared KTT key from `num_tellers` tellers
    /// and set up `num_registrars` independent registrars.
    pub fn setup(pp: &ElGamalPP, num_tellers: usize, num_registrars: usize) -> Self {
        assert!(num_tellers > 0 && num_registrars > 0);

        let mut params = SystemParameters::create_supervisor(pp);

        let tellers: Vec<Teller> = (0..num_tellers as i32)
            .map(|i| Teller::create_teller(params.clone(), i))
            .collect();

        // Distributed key generation — commit, prove, combine
        let comms: Vec<CommitmentKeyGen> = tellers
            .iter()
            .map(|t| t.get_share().publish_commitment_key_gen())
            .collect();
        let proofs: Vec<KeyProof> = tellers
            .iter()
            .map(|t| t.get_share().publish_proof_for_key_share())
            .collect();
        let pk = tellers[0]
            .get_share()
            .construct_shared_public_key(comms, proofs);

        // Supervisor publishes the encrypted candidate list under K_TT
        params.set_encrypted_list(pk.clone());

        let registrars: Vec<Registrar> = (0..num_registrars)
            .map(|i| Registrar::create(i, params.clone(), pk.clone()))
            .collect();

        Self {
            params,
            pk,
            tellers,
            registrars,
            registered_credentials: Vec::new(),
            ballot_box: Vec::new(),
        }
    }

    // ── Registration ─────────────────────────────────────────────────────

    /// Issue credentials to `voter` from all registrars.
    ///
    /// Each registrar produces a share, sends it to the voter with a DVRP proof,
    /// and the voter verifies and combines the shares into a single private
    /// credential. The election stores `Enc(s_v; K_TT)` for later credential
    /// validation during tabulation.
    ///
    /// Returns `Some(private_credential)` on success, `None` if all shares failed
    /// verification (should never happen in honest execution).
    pub fn register(&mut self, voter: &mut Voter) -> Option<BigInt> {
        let shares: Vec<_> = self
            .registrars
            .iter()
            .map(|r| r.create_credential_share())
            .collect();

        let cred_outputs: Vec<CredetialShareOutput> = self
            .registrars
            .iter()
            .zip(shares.iter())
            .map(|(reg, share)| {
                let dvrp_input = DvrpPublicInput::create_input(
                    &voter.designation_key_pair.pk.h,
                    reg.get_pk(),
                    &share.public_credential_i_tag,
                    &share.public_credential_i,
                );
                reg.publish_credential_with_proof(share, dvrp_input)
            })
            .collect();

        let public_creds: Vec<ElGamalCiphertext> = shares
            .iter()
            .map(|s| s.public_credential_i.clone())
            .collect();

        let private_cred =
            voter.construct_private_credential_from_shares(cred_outputs, public_creds)?;
        voter.set_private_credential(private_cred.clone());

        // Post Enc(s_v; K_TT) to the "bulletin board" for credential validation
        let r_reg = BigInt::sample_below(&self.params.pp.q);
        let reg_enc =
            encrypt_from_predefined_randomness(&private_cred, &self.pk, &r_reg).unwrap();
        self.registered_credentials.push(reg_enc);

        Some(private_cred)
    }

    // ── Voting ────────────────────────────────────────────────────────────

    /// Accept a ballot after verifying its VotePf and ReencPf.
    /// Returns `true` if accepted, `false` if either proof is invalid.
    pub fn submit_vote(&mut self, vote: Vote) -> bool {
        if Teller::check_votes(&vote, &self.params, &self.pk) {
            self.ballot_box.push(vote);
            true
        } else {
            false
        }
    }

    // ── Tabulation ────────────────────────────────────────────────────────

    /// Run the full Civitas tabulation pipeline:
    ///
    ///  1. **Validate** — keep only ballots with valid VotePf + ReencPf
    ///  2. **Deduplicate** — PET on credentials; keep the most recent ballot per voter
    ///  3. **Credential check** — PET each ballot's credential against the registered list;
    ///     eliminate unregistered credentials
    ///  4. **MixNet** — anonymise the encrypted vote choices
    ///  5. **Distributed decrypt** — tellers jointly decrypt each anonymised choice
    ///  6. **Tally** — count votes per candidate
    pub fn tabulate(&mut self) -> ElectionResult {
        let tellers = self.tellers.clone();
        let pp = self.params.pp.clone();
        let pk = self.pk.clone();
        let registered = self.registered_credentials.clone();
        let num_candidates = self.params.num_of_candidates;

        let total_cast = self.ballot_box.len();

        // ── Step 1: validate proofs ────────────────────────────────────────
        let validated: Vec<Vote> = self
            .ballot_box
            .iter()
            .filter(|v| Teller::check_votes(v, &self.params, &pk))
            .cloned()
            .collect();
        let num_valid_proofs = validated.len();

        // ── Step 2: deduplicate by credential (PET) ────────────────────────
        // Revoting policy: if a voter cast multiple ballots, keep the most recent.
        let (deduped, num_duplicates_removed) =
            Self::deduplicate(validated, &tellers, &pp);

        // ── Step 3: eliminate unregistered credentials (PET) ──────────────
        let (credentialed, num_invalid_credential) =
            Self::check_credentials(deduped, &registered, &tellers, &pp);

        if credentialed.is_empty() {
            return ElectionResult {
                counts: vec![0; num_candidates],
                total_cast,
                num_valid_proofs,
                num_duplicates_removed,
                num_invalid_credential,
                num_counted: 0,
            };
        }

        // ── Step 4: MixNet on vote choices ─────────────────────────────────
        let ev_list: Vec<ElGamalCiphertext> =
            credentialed.iter().map(|v| v.ev.clone()).collect();
        let mixed = run_mixnet(ev_list, &tellers, &pk).expect("MixNet failed");

        // ── Step 5: distributed decryption ─────────────────────────────────
        // Collect decryption shares, verify each teller's DDH proof, then combine.
        // Ciphertexts that cannot be decrypted by all tellers are skipped.
        let decrypted: Vec<BigInt> = mixed
            .iter()
            .filter_map(|c| {
                let msgs: Vec<_> = tellers
                    .iter()
                    .map(|t| t.get_share().publish_shares_and_proofs_for_decryption(c))
                    .collect();
                let valid_shares: Vec<BigInt> = tellers
                    .iter()
                    .zip(msgs.iter())
                    .filter(|(t, msg)| {
                        t.get_share()
                            .verify_proof_for_decryption(c, msg, t.teller_index)
                    })
                    .map(|(_, msg)| msg.share.clone())
                    .collect();
                if valid_shares.len() == tellers.len() {
                    Some(DistElGamal::combine_shares_and_decrypt(c, valid_shares, &pp))
                } else {
                    None
                }
            })
            .collect();

        // ── Step 6: tally ─────────────────────────────────────────────────
        // Each valid vote decrypts to encoding_quadratic_residue(candidate_index, pp).
        let candidate_encodings: Vec<BigInt> = (0..num_candidates)
            .map(|k| encoding_quadratic_residue(BigInt::from(k as i32), &pp))
            .collect();

        let mut counts = vec![0usize; num_candidates];
        let mut num_counted = 0;
        for d in &decrypted {
            if let Some(k) = candidate_encodings.iter().position(|enc| enc == d) {
                counts[k] += 1;
                num_counted += 1;
            }
        }

        ElectionResult {
            counts,
            total_cast,
            num_valid_proofs,
            num_duplicates_removed,
            num_invalid_credential,
            num_counted,
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────

    /// Duplicate elimination: if the same credential appears more than once,
    /// remove all earlier occurrences and keep the last one (revoting policy).
    fn deduplicate(
        votes: Vec<Vote>,
        tellers: &[Teller],
        pp: &ElGamalPP,
    ) -> (Vec<Vote>, usize) {
        let n = votes.len();
        let mut to_remove = vec![false; n];

        for i in 0..n {
            if to_remove[i] {
                continue;
            }
            for j in (i + 1)..n {
                if to_remove[j] {
                    continue;
                }
                // Same credential → drop the earlier vote
                if Teller::pet(&votes[i].es, &votes[j].es, tellers, pp) {
                    to_remove[i] = true;
                    break;
                }
            }
        }

        let n_removed = to_remove.iter().filter(|&&r| r).count();
        let deduped = votes
            .into_iter()
            .zip(to_remove)
            .filter_map(|(v, rm)| if rm { None } else { Some(v) })
            .collect();
        (deduped, n_removed)
    }

    /// Credential check: remove any ballot whose encrypted credential does not
    /// match any entry in the registered-credential list (PET).
    fn check_credentials(
        votes: Vec<Vote>,
        registered: &[ElGamalCiphertext],
        tellers: &[Teller],
        pp: &ElGamalPP,
    ) -> (Vec<Vote>, usize) {
        let mut valid = Vec::new();
        let mut n_invalid = 0;
        for vote in votes {
            let is_registered = registered
                .iter()
                .any(|reg| Teller::pet(&vote.es, reg, tellers, pp));
            if is_registered {
                valid.push(vote);
            } else {
                n_invalid += 1;
            }
        }
        (valid, n_invalid)
    }
}
