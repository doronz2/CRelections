# CRelections

A Rust implementation of **coercion-resistant e-voting**, based on the JCJ protocol (Juels, Catalano, Jakobsson 2010) and the Civitas system design (Clarkson, Chong, Myers 2008).

---

## What is coercion resistance?

Most e-voting schemes provide *secrecy*: no one learns how you voted. Coercion resistance is a strictly stronger property. It means a voter can be physically forced to reveal their credential and cast a specific vote — and still silently override it later, with no trace.

The key mechanism: every voter holds a *private credential* issued jointly by independent registrars. When you vote, you encrypt both your credential and your choice. If coerced, you can generate a *fake credential* (from scratch, without any registrar) and cast whatever vote the coercer demands. Both the real and fake credential produce valid-looking ballots. The tabulation tellers filter out ballots with unregistered credentials; your real ballot always wins.

---

## Running the interactive demo

**Prerequisites:** Rust stable, GMP library.

```bash
# macOS (Apple Silicon)
brew install gmp
git clone https://github.com/doronz2/CRelections
cd CRelections
LIBRARY_PATH=/opt/homebrew/lib cargo run
```

```bash
# macOS (Intel)
LIBRARY_PATH=/usr/local/lib cargo run
```

```bash
# Linux (Debian/Ubuntu)
sudo apt-get install libgmp-dev
cargo run
```

The CLI walks through a complete election:

```
=== CRelections — Coercion-Resistant E-Voting Demo ===
Candidates: 0 = Alice   1 = Bob   2 = Carol

Setting up election (3 tellers, 2 registrars)...
  ✓ Shared KTT key established.
  ✓ Candidate list encrypted and published.

How many voters to register? [1-9]: 3
  Registering voter 1... ✓
  Registering voter 2... ✓
  Registering voter 3... ✓

Which voter casts now? (0 = close polls): 1
  Vote for candidate [0-2]: 0
  ✓  Voter 1's ballot for Alice accepted.

Which voter casts now? (0 = close polls): 1
  Vote for candidate [0-2]: 2
  ✓  Voter 1's ballot for Carol accepted.    ← revote

...

  Ballots cast:         4
  Duplicates removed:   1    ← Voter 1's first ballot replaced
  Ballots counted:      3

  0  Alice   1  █
  1    Bob   0
  2  Carol   2  ██ ← winner
```

Voter 1 cast two ballots; the first was eliminated by the PET duplicate check and only the second counted. This is the coercion-resistance revoting mechanism in action.

---

## Protocol overview

Four roles interact via a public bulletin board:

| Role | Responsibility |
|---|---|
| **Supervisor** | Publishes system parameters and the encrypted candidate list |
| **Registrars** | Issue credential shares to voters with DVRP proofs |
| **Voters** | Combine shares into a private credential; cast a ballot |
| **Tabulation tellers** | Hold shares of the joint decryption key; mix, verify, and tally |

### Tabulation pipeline

```
Submitted ballots
      │
      ▼
 [1] Validate          VotePf + ReencPf checked per ballot
      │
      ▼
 [2] Deduplicate       PET on credentials — one ballot per voter (last wins)
      │
      ▼
 [3] Credential check  PET each credential against the registered list
      │
      ▼
 [4] MixNet            RPC two-pass shuffle — anonymises vote order
      │
      ▼
 [5] Distributed decrypt  Threshold ElGamal — no teller learns anything alone
      │
      ▼
 [6] Tally             Match decrypted plaintexts to candidate encodings
```

---

## Cryptographic primitives

| Primitive | Source | File |
|---|---|---|
| **DVRP** — Designated-Verifier Reencryption Proof | Hirt & Sako (EUROCRYPT 2000) | `zkproofs.rs` |
| **FakeDVRP** — simulated DVRP for coercion resistance | Hirt & Sako | `zkproofs.rs` |
| **ReencPf** — 1-of-L reencryption proof | Hirt & Sako | `zkproofs.rs` |
| **VotePf** — proof of knowledge of vote and credential randomness | Camenisch & Stadler | `zkproofs.rs` |
| **PET** — Plaintext Equivalence Test | Jakobsson & Juels | `tellers.rs` |
| **RPC MixNet** — randomized partial checking, two-pass | Jakobsson, Juels & Rivest (USENIX Sec. 2002) | `tellers.rs` |
| **Distributed ElGamal** — key generation + threshold decryption | Standard | `dist_el_gamal.rs` |
| **Non-malleable ElGamal** — Schnorr-signed ciphertext | — | `encryption_schemes.rs` |

All arithmetic uses the FFDHE4096 group (RFC 7919). BigInt is GMP-backed via the ZenGo-X `curv` crate.

---

## Library usage

```rust
use cr_elections::citivas::election::Election;
use cr_elections::citivas::voter::Voter;
use cr_elections::{ElGamalPP, SupportedGroups};

let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE4096);

// Setup: 3 tellers, 2 registrars
let mut election = Election::setup(&pp, 3, 2);

// Register a voter
let mut voter = Voter::create(0, &election.params, &election.pk);
election.register(&mut voter).unwrap();

// Cast a ballot
let ballot = voter.vote(/*candidate_index=*/ 1, &election.params);
election.submit_vote(ballot);

// Tabulate
let result = election.tabulate();
println!("{:?}", result.counts);   // [0, 1, 0]
println!("{:?}", result.winner()); // Some(1)
```

---

## Tests

```bash
LIBRARY_PATH=/opt/homebrew/lib cargo test -- --nocapture
```

25 tests, all passing:

| File | What is tested |
|---|---|
| `test_zkproofs` | DVRP, FakeDVRP, VotePf, ReencPf (both variants) |
| `test_voter` | Credential share verification, construction, vote casting |
| `test_encryption_schemes` | ElGamal, reencryption, QR encoding, credential encryption |
| `dist_el_gamal` | Distributed key generation, distributed decryption |
| `registrar` | DVRP proof on credential share |
| `test_tellers` | `check_votes` (30 samples), PET (60 pairs), mix permutation (30 runs), `run_mixnet` end-to-end |
| `test_election` | Honest election, revoting/dedup, unregistered credential rejection, invalid proof rejection |
| `integration_test` | Full end-to-end: 3 voters, 2 registrars, 3 tellers, distributed decrypt |

---

## Code structure

```
src/
├── main.rs                     interactive CLI
├── lib.rs                      crate root
└── citivas/
    ├── supervisor.rs           SystemParameters, candidate list encryption
    ├── entity.rs               Entity trait (shared group-element accessors)
    ├── dist_el_gamal.rs        Threshold ElGamal: key gen, DistDec, DDH proofs
    ├── encryption_schemes.rs   NonMalleable ElGamal, reencrypt, QR encoding
    ├── zkproofs.rs             DVRP, FakeDVRP, ReencPf, VotePf
    ├── registrar.rs            Credential share issuance
    ├── voter.rs                Credential construction, vote casting
    ├── tellers.rs              Mix, PET, MixNet verification, check_votes
    └── election.rs             Full election lifecycle + tabulation pipeline
```

---

## Known limitations

This is a research prototype. The following aspects of the full Civitas design are simplified:

**Registration trust model.** `Election::register` reconstructs the voter's private credential in a single process. In a real deployment, each registrar would communicate with the voter directly over an authenticated channel; the credential would be assembled client-side and never exposed to any third party.

**No threshold dropout.** Key generation and decryption currently require all `n` tellers. A `t-of-n` threshold scheme is a natural extension.

**No bulletin board signatures.** The bulletin board is in-memory; posted messages are not signed.

**Credential mixing omitted.** The full Civitas tabulation runs a separate MixNet over the registered-credential list before the invalid-credential PET. The current implementation does the credential check before anonymisation, which is functionally correct but slightly weaker against a compromised-teller adversary.

---

## References

- A. Juels, D. Catalano, M. Jakobsson. *Coercion-Resistant Electronic Elections.* WPES 2005 / extended version 2010. [PDF](http://www.arijuels.com/wp-content/uploads/2013/09/JCJ10.pdf)
- M. R. Clarkson, S. Chong, A. C. Myers. *Civitas: Toward a Secure Voting System.* IEEE S&P 2008. [Technical report](http://hdl.handle.net/1813/7875)
- M. Jakobsson, A. Juels, R. Rivest. *Making Mix Nets Robust for Electronic Voting by Randomized Partial Checking.* USENIX Security 2002.
- M. Hirt, K. Sako. *Efficient Receipt-Free Voting Based on Homomorphic Encryption.* EUROCRYPT 2000.
