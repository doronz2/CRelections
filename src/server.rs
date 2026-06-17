use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::task;
use tower_http::cors::CorsLayer;

use cr_elections::citivas::election::Election;
use cr_elections::citivas::voter::Voter;
use cr_elections::{ElGamalPP, SupportedGroups};
use curv::arithmetic::traits::Samplable;
use curv::BigInt;

// ── State ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    election: Mutex<Option<Election>>,
    voters:   Mutex<Vec<VoterRecord>>,
    log:      Mutex<Vec<LogEntry>>,
    result:   Mutex<Option<ResultData>>,
}

struct VoterRecord {
    voter:      Voter,
    name:       String,
    registered: bool,
    real_votes: usize,
    fake_votes: usize,
}

#[derive(Clone, Serialize)]
struct LogEntry {
    level:   String,
    message: String,
}

#[derive(Clone, Serialize)]
struct ResultData {
    counts:                 Vec<usize>,
    winner:                 Option<usize>,
    total_cast:             usize,
    num_valid_proofs:       usize,
    num_duplicates_removed: usize,
    num_invalid_credential: usize,
    num_counted:            usize,
}

impl AppState {
    fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                election: Mutex::new(None),
                voters:   Mutex::new(Vec::new()),
                log:      Mutex::new(Vec::new()),
                result:   Mutex::new(None),
            }),
        }
    }
    fn log(&self, level: &str, msg: &str) {
        self.inner.log.lock().unwrap().push(LogEntry {
            level:   level.to_string(),
            message: msg.to_string(),
        });
    }
}

// ── Request / response ─────────────────────────────────────────────────────

#[derive(Deserialize)] struct SetupReq   { num_voters: usize }
#[derive(Deserialize)] struct RegisterReq{ voter_id:   usize }
#[derive(Deserialize)] struct VoteReq    { voter_id: usize, candidate: usize, fake: bool }

#[derive(Serialize)]
struct ApiResult { success: bool, message: String }

fn ok(msg: &str)  -> Json<ApiResult> { Json(ApiResult { success: true,  message: msg.into() }) }
fn err(msg: &str) -> Json<ApiResult> { Json(ApiResult { success: false, message: msg.into() }) }

// ── State snapshot ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StateSnap {
    setup:          bool,
    voter_count:    usize,
    voters:         Vec<VoterSnap>,
    ballots_in_box: usize,
    tabulated:      bool,
    result:         Option<ResultData>,
    log:            Vec<LogEntry>,
}
#[derive(Serialize)]
struct VoterSnap { id: usize, name: String, registered: bool, real_votes: usize, fake_votes: usize }

// ── Handlers ───────────────────────────────────────────────────────────────

async fn root() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

async fn get_state(State(s): State<AppState>) -> Json<StateSnap> {
    let el  = s.inner.election.lock().unwrap();
    let vv  = s.inner.voters.lock().unwrap();
    let lg  = s.inner.log.lock().unwrap();
    let res = s.inner.result.lock().unwrap();
    Json(StateSnap {
        setup:          el.is_some(),
        voter_count:    vv.len(),
        voters:         vv.iter().enumerate().map(|(i,v)| VoterSnap {
            id: i, name: v.name.clone(),
            registered: v.registered, real_votes: v.real_votes, fake_votes: v.fake_votes,
        }).collect(),
        ballots_in_box: el.as_ref().map(|e| e.ballot_box.len()).unwrap_or(0),
        tabulated:      res.is_some(),
        result:         res.clone(),
        log:            lg.clone(),
    })
}

async fn setup(State(s): State<AppState>, Json(req): Json<SetupReq>) -> impl IntoResponse {
    if s.inner.election.lock().unwrap().is_some() {
        return err("Election already set up. Reset first.");
    }
    let n = req.num_voters.clamp(1, 9);
    s.log("info", &format!("Initialising election — {} voter slot(s), 3 tellers, 2 registrars…", n));
    let state = s.clone();
    task::spawn_blocking(move || {
        let pp       = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE4096);
        let election = Election::setup(&pp, 3, 2);
        let voters   = (0..n).map(|i| VoterRecord {
            voter:      Voter::create(i, &election.params, &election.pk),
            name:       format!("Voter {}", i + 1),
            registered: false, real_votes: 0, fake_votes: 0,
        }).collect::<Vec<_>>();
        *state.inner.election.lock().unwrap() = Some(election);
        *state.inner.voters.lock().unwrap()   = voters;
        state.log("success", "Election ready. Shared KTT key established.");
        state.log("info",    "Candidates:  0 = Alice   |   1 = Bob   |   2 = Carol");
    }).await.unwrap();
    ok(&format!("Election initialised with {} voter slot(s).", n))
}

async fn register(State(s): State<AppState>, Json(req): Json<RegisterReq>) -> impl IntoResponse {
    {
        let el = s.inner.election.lock().unwrap();
        if el.is_none() { return err("Set up the election first."); }
        let vv = s.inner.voters.lock().unwrap();
        if req.voter_id >= vv.len() { return err("Voter ID out of range."); }
        if vv[req.voter_id].registered { return err("Already registered."); }
    }
    let vid  = req.voter_id;
    let name = s.inner.voters.lock().unwrap()[vid].name.clone();
    s.log("info", &format!("Registering {}…", name));
    let state = s.clone();
    let ok_flag = task::spawn_blocking(move || -> bool {
        let mut el = state.inner.election.lock().unwrap();
        let mut vv = state.inner.voters.lock().unwrap();
        let rec = &mut vv[vid];
        match el.as_mut().unwrap().register(&mut rec.voter) {
            Some(_) => { rec.registered = true;
                state.log("success", &format!("{} registered. Private credential issued.", rec.name));
                true }
            None    => { state.log("error", "All credential shares invalid."); false }
        }
    }).await.unwrap_or(false);
    if ok_flag { ok(&format!("{} registered.", name)) } else { err("Registration failed.") }
}

async fn vote(State(s): State<AppState>, Json(req): Json<VoteReq>) -> impl IntoResponse {
    {
        let el = s.inner.election.lock().unwrap();
        if el.is_none() { return err("Set up the election first."); }
        let vv = s.inner.voters.lock().unwrap();
        if req.voter_id >= vv.len() { return err("Voter ID out of range."); }
        if !req.fake && !vv[req.voter_id].registered { return err("Voter not registered."); }
    }
    if req.candidate >= 3 { return err("Invalid candidate (0–2)."); }

    let vid   = req.voter_id;
    let cname = ["Alice","Bob","Carol"][req.candidate];
    let vname = s.inner.voters.lock().unwrap()[vid].name.clone();
    let fake  = req.fake;

    if fake {
        s.log("warning", &format!(
            "{} is casting a COERCED ballot for {} using a fake credential…", vname, cname));
    } else {
        s.log("info", &format!("{} is casting a real ballot for {}…", vname, cname));
    }

    let state = s.clone();
    let accepted = task::spawn_blocking(move || -> bool {
        let mut el = state.inner.election.lock().unwrap();
        let election = el.as_mut().unwrap();
        let mut vv = state.inner.voters.lock().unwrap();

        if fake {
            // Unregistered voter with a random credential — simulates coerced ballot
            let pp         = election.params.pp.clone();
            let pk         = election.pk.clone();
            let fake_cred  = BigInt::sample_below(&pp.q) + BigInt::one();
            let mut impost = Voter::create(9999, &election.params, &pk);
            impost.set_private_credential(fake_cred);
            let ballot = impost.vote(req.candidate, &election.params);
            let ok     = election.submit_vote(ballot);
            if ok {
                vv[vid].fake_votes += 1;
                state.log("warning",
                    "Coerced ballot accepted. It looks valid — but uses an unregistered \
                     credential and will be eliminated at tabulation. The real ballot wins.");
            }
            ok
        } else {
            let ballot = vv[vid].voter.vote(req.candidate, &election.params);
            let ok     = election.submit_vote(ballot);
            if ok {
                vv[vid].real_votes += 1;
                state.log("success",
                    &format!("{}'s real ballot for {} accepted and sealed.", vname, cname));
            }
            ok
        }
    }).await.unwrap_or(false);

    if accepted { ok("Ballot accepted.") } else { err("Ballot rejected: proof invalid.") }
}

async fn tabulate(State(s): State<AppState>) -> impl IntoResponse {
    {
        let el = s.inner.election.lock().unwrap();
        if el.is_none() { return err("Set up the election first."); }
        if el.as_ref().unwrap().ballot_box.is_empty() { return err("No ballots in the box."); }
    }
    if s.inner.result.lock().unwrap().is_some() {
        return err("Already tabulated. Reset to run a new election.");
    }
    s.log("info", "Starting tabulation pipeline…");
    s.log("info", "1 · Validating VotePf + ReencPf proofs");
    s.log("info", "2 · PET duplicate elimination");
    s.log("info", "3 · PET credential check vs registered list");
    s.log("info", "4 · RPC MixNet — two-pass shuffle");
    s.log("info", "5 · Threshold ElGamal distributed decryption");
    s.log("info", "6 · Tallying  (may take ~30 seconds)");

    let state = s.clone();
    task::spawn_blocking(move || {
        let mut el = state.inner.election.lock().unwrap();
        let r      = el.as_mut().unwrap().tabulate();
        let cands  = ["Alice","Bob","Carol"];
        state.log("success", &format!(
            "Done. Cast:{} | Dupes removed:{} | Invalid creds:{} | Counted:{}",
            r.total_cast, r.num_duplicates_removed, r.num_invalid_credential, r.num_counted));
        for (k,&n) in r.counts.iter().enumerate() {
            let mark = if r.winner() == Some(k) { " ← winner" } else { "" };
            state.log("info", &format!("  {} : {}{}", cands.get(k).unwrap_or(&"?"), n, mark));
        }
        *state.inner.result.lock().unwrap() = Some(ResultData {
            counts:                 r.counts.clone(),
            winner:                 r.winner(),
            total_cast:             r.total_cast,
            num_valid_proofs:       r.num_valid_proofs,
            num_duplicates_removed: r.num_duplicates_removed,
            num_invalid_credential: r.num_invalid_credential,
            num_counted:            r.num_counted,
        });
    }).await.unwrap();
    ok("Tabulation complete.")
}

async fn reset(State(s): State<AppState>) -> Json<ApiResult> {
    *s.inner.election.lock().unwrap() = None;
    *s.inner.voters.lock().unwrap()   = Vec::new();
    *s.inner.result.lock().unwrap()   = None;
    s.inner.log.lock().unwrap().clear();
    s.log("info", "Election reset.");
    ok("Reset complete.")
}

// ── Router ─────────────────────────────────────────────────────────────────

pub async fn run(port: u16) {
    let state = AppState::new();
    state.log("info", &format!("CRelections server — http://localhost:{}", port));
    let app = Router::new()
        .route("/",             get(root))
        .route("/api/state",    get(get_state))
        .route("/api/setup",    post(setup))
        .route("/api/register", post(register))
        .route("/api/vote",     post(vote))
        .route("/api/tabulate", post(tabulate))
        .route("/api/reset",    post(reset))
        .layer(CorsLayer::permissive())
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    println!("Listening on http://localhost:{}", port);
    axum::serve(listener, app).await.unwrap();
}
