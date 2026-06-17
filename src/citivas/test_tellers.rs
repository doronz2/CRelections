#[cfg(test)]
pub mod test_tellers {
    use crate::citivas::dist_el_gamal::{CommitmentKeyGen, DistElGamal, KeyProof};
    use crate::citivas::encryption_schemes::{
        encoding_quadratic_residue, encrypt_from_predefined_randomness, ElGamalCipherTextAndPK,
    };
    use crate::citivas::supervisor::SystemParameters;
    use crate::citivas::tellers::{run_mixnet, MixInput, Teller};
    use crate::citivas::voter::Voter;
    use crate::{ElGamal, ElGamalKeyPair, ElGamalPP, SupportedGroups};
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use rand::Rng;

    // ── shared setup ──────────────────────────────────────────────────────

    fn setup_tellers(pp: &ElGamalPP) -> (SystemParameters, elgamal::ElGamalPublicKey, Vec<Teller>) {
        let mut params = SystemParameters::create_supervisor(pp);
        let t1 = Teller::create_teller(params.clone(), 0);
        let t2 = Teller::create_teller(params.clone(), 1);
        let t3 = Teller::create_teller(params.clone(), 2);

        let comms: Vec<CommitmentKeyGen> = [&t1, &t2, &t3]
            .iter()
            .map(|t| t.get_share().publish_commitment_key_gen())
            .collect();
        let proofs: Vec<KeyProof> = [&t1, &t2, &t3]
            .iter()
            .map(|t| t.get_share().publish_proof_for_key_share())
            .collect();
        let pk = t1.get_share().construct_shared_public_key(comms, proofs);
        params.set_encrypted_list(pk.clone());
        (params, pk, vec![t1, t2, t3])
    }

    // ── Test 1: Teller::check_votes (ev/es swap fix) ──────────────────────

    #[test]
    pub fn test_teller_check_votes() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let mut params = SystemParameters::create_supervisor(&pp);
        let key_pair = ElGamalKeyPair::generate(&pp);
        let pk = key_pair.pk.clone();
        params.set_encrypted_list(pk.clone());

        let mut rng = rand::thread_rng();

        // 30 valid votes — all must be accepted
        for _ in 0..30 {
            let mut voter = Voter::create(0, &params, &pk);
            let cred = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
            voter.set_private_credential(cred);
            let candidate = rng.gen_range(0, params.num_of_candidates);
            let vote = voter.vote(candidate, &params);
            assert!(
                Teller::check_votes(&vote, &params, &pk),
                "valid vote must be accepted"
            );
        }

        // One tampered vote (ev replaced) — must be rejected
        let mut voter = Voter::create(0, &params, &pk);
        let cred = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
        voter.set_private_credential(cred);
        let mut vote = voter.vote(0, &params);
        vote.ev = ElGamal::encrypt(&BigInt::sample_below(&pp.q), &pk).unwrap();
        assert!(
            !Teller::check_votes(&vote, &params, &pk),
            "tampered vote must be rejected"
        );
    }

    // ── Test 2: PET ───────────────────────────────────────────────────────

    #[test]
    pub fn test_pet() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let (_, pk, tellers) = setup_tellers(&pp);

        // 30 pairs with equal plaintexts — PET must return true
        for _ in 0..30 {
            // QR-encoded messages live in Z_p (can be > q); use the project's
            // encrypt_from_predefined_randomness which accepts m < p.
            let m = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
            let r1 = BigInt::sample_below(&pp.q);
            let r2 = BigInt::sample_below(&pp.q);
            let c1 = encrypt_from_predefined_randomness(&m, &pk, &r1).unwrap();
            let c2 = encrypt_from_predefined_randomness(&m, &pk, &r2).unwrap();
            assert!(
                Teller::pet(&c1, &c2, &tellers, &pp),
                "PET must return true for equal plaintexts"
            );
        }

        // 30 pairs with distinct plaintexts — PET must return false
        let mut count = 0;
        while count < 30 {
            let m1 = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
            let m2 = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
            if m1 == m2 {
                continue;
            }
            let r1 = BigInt::sample_below(&pp.q);
            let r2 = BigInt::sample_below(&pp.q);
            let c1 = encrypt_from_predefined_randomness(&m1, &pk, &r1).unwrap();
            let c2 = encrypt_from_predefined_randomness(&m2, &pk, &r2).unwrap();
            assert!(
                !Teller::pet(&c1, &c2, &tellers, &pp),
                "PET must return false for unequal plaintexts"
            );
            count += 1;
        }
    }

    // ── Test 3: Mix permutation fix ───────────────────────────────────────

    #[test]
    pub fn test_mix_permutation() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let (params, pk, tellers) = setup_tellers(&pp);

        let m_count = params.num_of_voters;
        let ctxs: Vec<elgamal::ElGamalCiphertext> = (1..=m_count as i32)
            .map(|i| ElGamal::encrypt(&BigInt::from(i), &pk).unwrap())
            .collect();

        // Run mix 30 times — each must produce outputs of the correct length.
        // Before the fix, permuted_indices was empty so this would panic (index
        // out of bounds).  Completing 30 runs without panic proves the fix.
        for _ in 0..30 {
            let mix_input = MixInput {
                ctx_list: ctxs
                    .iter()
                    .map(|c| ElGamalCipherTextAndPK { ctx: c.clone(), pk: &pk })
                    .collect(),
            };
            let (mix_output, _) = tellers[0].clone().mix(mix_input, true);
            assert_eq!(
                mix_output.ctx_mix_list.len(),
                m_count,
                "mix output must have same length as input"
            );
            assert_eq!(
                mix_output.comm_to_shuffle_list.len(),
                m_count,
                "commitment list must have same length as input"
            );
        }
    }

    // ── Test 4: run_mixnet end-to-end ─────────────────────────────────────

    #[test]
    pub fn test_run_mixnet() {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let (params, pk, tellers) = setup_tellers(&pp);

        // Encrypt distinct messages 1, 2, 3 under the shared KTT key
        let messages: Vec<BigInt> = (1..=params.num_of_voters as i32)
            .map(BigInt::from)
            .collect();
        let ciphertexts: Vec<elgamal::ElGamalCiphertext> = messages
            .iter()
            .map(|m| ElGamal::encrypt(m, &pk).unwrap())
            .collect();

        // Verification must succeed
        let output = run_mixnet(ciphertexts, &tellers, &pk);
        assert!(output.is_some(), "run_mixnet must succeed with valid tellers");
        let output = output.unwrap();
        assert_eq!(output.len(), messages.len(), "output length must equal input length");

        // Decrypt every output ciphertext via threshold decryption and verify
        // that the resulting multiset equals the original plaintext multiset.
        let mut decrypted: Vec<BigInt> = output
            .iter()
            .map(|c| {
                let shares: Vec<BigInt> = tellers
                    .iter()
                    .map(|t| t.get_share().publish_shares_and_proofs_for_decryption(c).share)
                    .collect();
                DistElGamal::combine_shares_and_decrypt(c, shares, &pp)
            })
            .collect();

        let mut expected = messages.clone();
        decrypted.sort();
        expected.sort();
        assert_eq!(
            decrypted, expected,
            "decrypted outputs must be a permutation of the original plaintexts"
        );
    }
}
