#[cfg(test)]
mod test_election {
    use crate::citivas::election::{Election, ElectionResult};
    use crate::citivas::voter::Voter;
    use crate::{ElGamalPP, SupportedGroups};

    fn setup_election() -> (ElGamalPP, Election) {
        let group_id = SupportedGroups::FFDHE4096;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let election = Election::setup(&pp, 3, 2);
        (pp, election)
    }

    // ── Test 1: honest election ────────────────────────────────────────────
    // 3 voters each vote for a different candidate. Every vote should be
    // counted. Result: 1 vote per candidate.
    #[test]
    fn test_honest_election() {
        let (pp, mut election) = setup_election();

        let mut voter_0 = Voter::create(0, &election.params, &election.pk);
        let mut voter_1 = Voter::create(1, &election.params, &election.pk);
        let mut voter_2 = Voter::create(2, &election.params, &election.pk);

        election.register(&mut voter_0).expect("registration failed");
        election.register(&mut voter_1).expect("registration failed");
        election.register(&mut voter_2).expect("registration failed");

        assert!(election.submit_vote(voter_0.vote(0, &election.params)));
        assert!(election.submit_vote(voter_1.vote(1, &election.params)));
        assert!(election.submit_vote(voter_2.vote(2, &election.params)));

        let result = election.tabulate();

        assert_eq!(result.total_cast, 3);
        assert_eq!(result.num_duplicates_removed, 0);
        assert_eq!(result.num_invalid_credential, 0);
        assert_eq!(result.num_counted, 3);
        assert_eq!(result.counts, vec![1, 1, 1]);
    }

    // ── Test 2: revoting (duplicate elimination) ───────────────────────────
    // Voter 0 votes twice: first for candidate 0, then for candidate 2.
    // The first vote must be removed; only the second vote counts.
    #[test]
    fn test_revoting_keeps_last_ballot() {
        let (pp, mut election) = setup_election();

        let mut voter_0 = Voter::create(0, &election.params, &election.pk);
        let mut voter_1 = Voter::create(1, &election.params, &election.pk);

        election.register(&mut voter_0).expect("registration failed");
        election.register(&mut voter_1).expect("registration failed");

        // voter_0 votes twice
        let first_vote = voter_0.vote(0, &election.params);
        let second_vote = voter_0.vote(2, &election.params);
        assert!(election.submit_vote(first_vote));
        assert!(election.submit_vote(second_vote));
        assert!(election.submit_vote(voter_1.vote(1, &election.params)));

        let result = election.tabulate();

        assert_eq!(result.total_cast, 3);
        assert_eq!(result.num_duplicates_removed, 1, "first vote must be deduplicated");
        assert_eq!(result.num_counted, 2);
        // voter_0's effective vote = candidate 2, voter_1 = candidate 1
        assert_eq!(result.counts[0], 0, "candidate 0 must have 0 votes");
        assert_eq!(result.counts[1], 1, "candidate 1 must have 1 vote");
        assert_eq!(result.counts[2], 1, "candidate 2 must have 1 vote");
    }

    // ── Test 3: invalid credential rejection ──────────────────────────────
    // Voter 1 is NOT registered. Their ballot must be rejected during the
    // credential check phase, and must not appear in the final count.
    #[test]
    fn test_unregistered_credential_rejected() {
        use crate::citivas::encryption_schemes::encoding_quadratic_residue;
        use crate::citivas::voter::Voter;
        use curv::arithmetic::traits::Samplable;
        use curv::BigInt;

        let (pp, mut election) = setup_election();

        let mut voter_0 = Voter::create(0, &election.params, &election.pk);
        election.register(&mut voter_0).expect("registration failed");

        // voter_1 is created but never registered
        let mut voter_1 = Voter::create(1, &election.params, &election.pk);
        let fake_cred = encoding_quadratic_residue(BigInt::sample_below(&pp.p), &pp);
        voter_1.set_private_credential(fake_cred);

        assert!(election.submit_vote(voter_0.vote(0, &election.params)));
        assert!(election.submit_vote(voter_1.vote(1, &election.params)));

        let result = election.tabulate();

        assert_eq!(result.total_cast, 2);
        assert_eq!(result.num_invalid_credential, 1, "unregistered ballot must be eliminated");
        assert_eq!(result.num_counted, 1, "only the registered voter's vote counts");
        assert_eq!(result.counts[0], 1, "candidate 0 has 1 valid vote");
        assert_eq!(result.counts[1], 0, "candidate 1 has 0 valid votes");
    }

    // ── Test 4: invalid proof rejected ────────────────────────────────────
    // A ballot with a tampered ev (random ciphertext) must be rejected by
    // the proof-validation step and never enter the pipeline.
    #[test]
    fn test_invalid_proof_rejected() {
        use crate::{ElGamal, ElGamalKeyPair};
        use curv::arithmetic::traits::Samplable;
        use curv::BigInt;

        let (pp, mut election) = setup_election();

        let mut voter_0 = Voter::create(0, &election.params, &election.pk);
        election.register(&mut voter_0).expect("registration failed");

        let mut tampered = voter_0.vote(0, &election.params);
        // Replace ev with a random ciphertext — VotePf/ReencPf will fail
        tampered.ev = ElGamal::encrypt(&BigInt::sample_below(&pp.q), &election.pk).unwrap();

        let accepted = election.submit_vote(tampered);
        assert!(!accepted, "tampered ballot must be rejected at submission");
        assert_eq!(election.ballot_box.len(), 0);
    }
}
