use cr_elections::citivas::election::Election;
use cr_elections::citivas::voter::Voter;
use cr_elections::{ElGamalPP, SupportedGroups};
use std::io::{self, Write};

// ── helpers ───────────────────────────────────────────────────────────────

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

fn read_usize(msg: &str, lo: usize, hi: usize) -> usize {
    loop {
        let s = prompt(msg);
        match s.parse::<usize>() {
            Ok(n) if n >= lo && n <= hi => return n,
            _ => println!("  Please enter a number between {} and {}.", lo, hi),
        }
    }
}

fn banner(title: &str) {
    let line = "─".repeat(60);
    println!("\n{}", line);
    println!("  {}", title);
    println!("{}\n", line);
}

// ── main ──────────────────────────────────────────────────────────────────

fn main() {
    banner("CRelections — Coercion-Resistant E-Voting Demo");

    println!("This demo runs a Civitas-style election end-to-end.");
    println!("Candidates: 0 = Alice   1 = Bob   2 = Carol\n");

    let candidate_names = ["Alice", "Bob", "Carol"];

    // ── Setup ─────────────────────────────────────────────────────────────
    println!("Setting up election (3 tellers, 2 registrars)...");
    println!("  Generating shared KTT key — this takes a few seconds.");
    let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE4096);
    let mut election = Election::setup(&pp, 3, 2);
    println!("  ✓ Shared KTT key established.");
    println!("  ✓ Candidate list encrypted and published.\n");

    // ── Registration ──────────────────────────────────────────────────────
    banner("Voter Registration");

    let num_voters = read_usize("How many voters to register? [1-9]: ", 1, 9);
    println!();

    let mut voters: Vec<Voter> = Vec::new();
    for i in 0..num_voters {
        print!("  Registering voter {}... ", i + 1);
        io::stdout().flush().unwrap();
        let mut v = Voter::create(i, &election.params, &election.pk);
        election.register(&mut v).expect("registration failed");
        voters.push(v);
        println!("✓");
    }
    println!("\n  {} voter(s) registered.", num_voters);

    // ── Voting ────────────────────────────────────────────────────────────
    banner("Voting Phase");

    println!("Each voter casts their ballot. Voters may vote more than once");
    println!("(the last ballot counts — coercion resistance in action).\n");

    loop {
        println!("Registered voters: {}", num_voters);
        let voter_id = read_usize(
            &format!("Which voter casts now? [1-{}]  (0 = close polls): ", num_voters),
            0,
            num_voters,
        );
        if voter_id == 0 {
            break;
        }

        println!("  Candidates:");
        for (k, name) in candidate_names.iter().enumerate() {
            println!("    {} — {}", k, name);
        }
        let choice = read_usize("  Vote for candidate [0-2]: ", 0, 2);

        print!("  Casting ballot... ");
        io::stdout().flush().unwrap();
        let vote = voters[voter_id - 1].vote(choice, &election.params);
        if election.submit_vote(vote) {
            println!(
                "✓  Voter {}'s ballot for {} accepted.",
                voter_id, candidate_names[choice]
            );
        } else {
            println!("✗  Ballot rejected (invalid proof).");
        }
    }

    let total = election.ballot_box.len();
    if total == 0 {
        println!("\nNo ballots cast. Exiting.");
        return;
    }
    println!("\n  {} ballot(s) in the box.", total);

    // ── Tabulation ────────────────────────────────────────────────────────
    banner("Tabulation");

    println!("Running Civitas pipeline:");
    println!("  1. Validating proofs (VotePf + ReencPf)...");
    println!("  2. Duplicate elimination (PET on credentials)...");
    println!("  3. Credential check (PET vs. registered list)...");
    println!("  4. MixNet anonymisation (RPC two-pass shuffle)...");
    println!("  5. Distributed decryption (threshold ElGamal)...");
    println!("  6. Tallying...\n");
    println!("  This may take up to a minute. Please wait.\n");

    let result = election.tabulate();

    // ── Results ───────────────────────────────────────────────────────────
    banner("Election Results");

    println!("  Ballots cast:               {}", result.total_cast);
    println!("  Valid proofs:               {}", result.num_valid_proofs);
    println!("  Duplicates removed:         {}", result.num_duplicates_removed);
    println!("  Invalid credentials:        {}", result.num_invalid_credential);
    println!("  Ballots counted:            {}", result.num_counted);

    println!();
    let winner_idx = result.winner();
    for (k, name) in candidate_names.iter().enumerate() {
        let bar = "█".repeat(result.counts[k]);
        let marker = if winner_idx == Some(k) { " ← winner" } else { "" };
        println!("  {} {:>6}  {}  {}{}", k, name, result.counts[k], bar, marker);
    }

    println!();
    match winner_idx {
        Some(k) => println!("  {} wins with {} vote(s).", candidate_names[k], result.counts[k]),
        None    => println!("  No votes counted."),
    }
    println!();
}
