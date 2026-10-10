//! The approval record: the state machine between "a module asked for a signature" and "a person
//! approved it, and the account's signer signed". Ported from keystore_module, whose API it keeps;
//! the difference is who signs. The manager reads, renders and commits to the request, computes
//! each digest, hands them to the account's signer, and checks every signature before settling.
//!
//! Two invariants, asserted by the tests:
//!
//! 1. **One parse.** The intent is parsed once into typed legs; the render and the digests come
//!    from that same value, and `approve` re-derives the commitment before anything is signed.
//! 2. **At most one record is `Rendered`.** Acknowledging a second record demotes the first, so a
//!    UI update between reading A and clicking Approve cannot submit B.

use std::time::{Duration, Instant};

use alloy::primitives::U256;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, Psbt};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use logos_signer_interface::{verify, HashItem, JobState, Payload, RequestKind, Scheme, Secret, SignRequest, Signature};

use crate::btc::AccountPublic;
use crate::error::{bad, ManagerError, Result};
use crate::evm::{self, check_displayable, parse_u128, ParsedTx, UnsignedTx};
use crate::psbt::{self as btcpsbt, Checked};
use crate::registry::{Found, Registry};

/// Garbage collection for an offer whose requester will never come back; the requester cancels
/// promptly when its own path closes, so this only covers its death.
pub const ABANDONED_OFFER_TTL: Duration = Duration::from_secs(60);
pub const MAX_PENDING_PER_REQUESTER: usize = 4;
pub const MAX_PENDING_TOTAL: usize = 16;
/// Largest intent parsed, before parsing it.
pub const MAX_INTENT_BYTES: usize = 64 * 1024;
/// A settled record is kept so the requester reads a real outcome rather than "no such handle".
pub const SETTLED_RETENTION: Duration = Duration::from_secs(120);

// ── the intent ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "snake_case")]
pub enum Leg {
    Tx { chain_id: u64, tx: UnsignedTx },
    /// EIP-191 `personal_sign` over printable text.
    Message { text: String },
    /// An opaque 32-byte digest: only the requester's `purpose` can be shown, as its claim.
    Digest { digest: String, purpose: String },
    /// EIP-712 typed data; every field is shown, and the hash is computed here.
    TypedData { typed_data: serde_json::Value },
    /// A Bitcoin PSBT, base64, for the intent's `group`, read by the manager itself.
    Psbt { network: String, psbt: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// The EVM account. An intent names this or `group`, never both.
    #[serde(default)]
    pub address: String,
    /// The Bitcoin wallet.
    #[serde(default)]
    pub group: String,
    /// A short requester-supplied label, shown as its claim.
    #[serde(default)]
    pub purpose: String,
    pub legs: Vec<Leg>,
}

// ── the record ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Offered,
    Rendered,
    /// Approved, and the account's signer is working: a device waiting for its person.
    Signing,
    Settled(Outcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Rejected,
    ExpiredNoAck,
    Cancelled,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Rejected => "rejected",
            Outcome::ExpiredNoAck => "expired_no_ack",
            Outcome::Cancelled => "cancelled",
        }
    }
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Offered => "offered",
            State::Rendered => "rendered",
            State::Signing => "signing",
            State::Settled(_) => "settled",
        }
    }
}

struct Record {
    handle: String,
    receipt_hash: [u8; 32],
    requester: String,
    intent: Intent,
    bundle_id: [u8; 32],
    claim_lines: Vec<String>,
    render_lines: Vec<String>,
    signer: String,
    /// The account's id at its signer, for the unlock that may cover it.
    account: String,
    state: State,
    offered_at: Instant,
    settled_at: Option<Instant>,
    claimed: bool,
    /// The signer's job while `Signing`.
    job: Option<String>,
    /// Why the last approval didn't sign, for the approver.
    last_error: Option<String>,
    results: Option<Vec<String>>,
}

#[derive(Default)]
pub struct Approvals {
    records: Vec<Record>,
    seq: u64,
    abandoned_offer_ttl: Option<Duration>,
    moves: Vec<Move>,
}

/// What a signer's answer moved since the glue last asked: a device ends its job in its own time,
/// and the glue announces it.
#[derive(Debug, PartialEq, Eq)]
pub enum Move {
    Settled(String, Outcome),
    /// Back on screen, saying why.
    Rendered(String),
}

/// What `acknowledge` hands an approver, in two groups it must not merge.
pub struct Rendered {
    pub handle: String,
    pub bundle_id: String,
    /// Who asked: the caller's own identity.
    pub requester: String,
    /// What the requester says this is for.
    pub claim_lines: Vec<String>,
    /// What is signed, and the commitment over it, in the manager's own words.
    pub render_lines: Vec<String>,
    /// The module that will sign, and what `approve` must carry for it.
    pub signer: String,
    pub collects: logos_signer_interface::Collects,
    /// The account at its signer: an address, or a Bitcoin wallet's id. What an unlock names.
    pub account: String,
}

pub struct Summary {
    pub handle: String,
    pub requester: String,
    pub state: &'static str,
    pub purpose: String,
    pub leg_count: usize,
    pub age_ms: u128,
    pub error: Option<String>,
}

/// What `approve` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Approved {
    /// Signed and settled: this many results.
    Settled(usize),
    /// The signer is working; the record settles when it answers.
    Signing,
}

impl Approvals {
    pub fn new() -> Self {
        Self::default()
    }

    fn ttl(&self) -> Duration {
        self.abandoned_offer_ttl.unwrap_or(ABANDONED_OFFER_TTL)
    }

    /// Shortening it only ever fails closed sooner, which the expiry test relies on.
    pub fn set_abandoned_offer_ttl(&mut self, d: Duration) {
        self.abandoned_offer_ttl = Some(d);
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl();
        for r in &mut self.records {
            if r.state == State::Offered && !r.claimed && now.duration_since(r.offered_at) > ttl {
                r.state = State::Settled(Outcome::ExpiredNoAck);
            }
            if matches!(r.state, State::Settled(_)) && r.settled_at.is_none() {
                r.settled_at = Some(now);
            }
        }
        self.records.retain(|r| {
            let Some(at) = r.settled_at else { return true };
            r.results.is_some() || now.duration_since(at) < SETTLED_RETENTION
        });
    }

    fn find(&mut self, handle: &str) -> Option<&mut Record> {
        self.records.iter_mut().find(|r| r.handle == handle)
    }

    fn by_receipt(&mut self, handle: &str, receipt: &str) -> Result<&mut Record> {
        let want = sha256(receipt.as_bytes());
        self.records
            .iter_mut()
            .find(|r| r.handle == handle && ct_eq(&r.receipt_hash, &want))
            .ok_or_else(|| ManagerError::NotFound(handle.to_string()))
    }

    /// Open a request: `(handle, receipt)`. The receipt is returned once and never stored in the clear.
    pub fn request(&mut self, signers: &mut Registry, requester: &str, intent_json: &str) -> Result<(String, String)> {
        self.sweep();
        if intent_json.len() > MAX_INTENT_BYTES {
            return Err(bad(format!("intent: {} bytes exceeds the {MAX_INTENT_BYTES}-byte limit", intent_json.len())));
        }
        let live = |r: &&Record| !matches!(r.state, State::Settled(_));
        if self.records.iter().filter(live).count() >= MAX_PENDING_TOTAL {
            return Err(bad("too many pending approvals"));
        }
        if self.records.iter().filter(live).filter(|r| r.requester == requester).count() >= MAX_PENDING_PER_REQUESTER {
            return Err(bad("too many pending approvals for this requester"));
        }
        let intent: Intent = serde_json::from_str(intent_json).map_err(|e| bad(format!("intent: {e}")))?;
        if intent.legs.is_empty() {
            return Err(bad("intent: no legs"));
        }
        check_displayable(&intent.purpose, "purpose")?;

        let prepared = prepare(signers, &intent)?;
        let bundle_id = commitment(&intent, &prepared)?;
        let (claim_lines, render_lines) = render(&intent, &prepared, &bundle_id)?;

        self.seq += 1;
        let handle = format!("smh_{}", token_hex(self.seq));
        let receipt = format!("smc_{}", token_hex(self.seq));
        self.records.push(Record {
            handle: handle.clone(),
            receipt_hash: sha256(receipt.as_bytes()),
            requester: requester.to_string(),
            intent,
            bundle_id,
            claim_lines,
            render_lines,
            signer: prepared.found().name.clone(),
            account: prepared.found().account.id.clone(),
            state: State::Offered,
            offered_at: Instant::now(),
            settled_at: None,
            claimed: false,
            job: None,
            last_error: None,
            results: None,
        });
        Ok((handle, receipt))
    }

    pub fn pending(&mut self, signers: &mut Registry) -> Vec<Summary> {
        self.progress(signers);
        let now = Instant::now();
        self.records
            .iter()
            .filter(|r| !matches!(r.state, State::Settled(_)))
            .map(|r| Summary {
                handle: r.handle.clone(),
                requester: r.requester.clone(),
                state: r.state.as_str(),
                purpose: r.intent.purpose.clone(),
                leg_count: r.intent.legs.len(),
                age_ms: now.duration_since(r.offered_at).as_millis(),
                error: r.last_error.clone(),
            })
            .collect()
    }

    /// Claim a record for display, demoting any other rendered one.
    pub fn acknowledge(&mut self, signers: &mut Registry, handle: &str) -> Result<Rendered> {
        self.progress(signers);
        if !self.records.iter().any(|r| r.handle == handle) {
            return Err(ManagerError::NotFound(handle.to_string()));
        }
        for r in &mut self.records {
            if r.state == State::Rendered && r.handle != handle {
                r.state = State::Offered;
            }
        }
        let r = self.find(handle).expect("checked above");
        match r.state {
            State::Settled(o) => return Err(bad(format!("already settled: {}", o.as_str()))),
            State::Signing => return Err(bad("already approved; its signer is working")),
            _ => {
                r.state = State::Rendered;
                r.claimed = true;
            }
        }
        let (handle, bundle_id, requester, claim_lines, render_lines, signer, account) = (
            r.handle.clone(),
            hex::encode(r.bundle_id),
            r.requester.clone(),
            r.claim_lines.clone(),
            r.render_lines.clone(),
            r.signer.clone(),
            r.account.clone(),
        );
        let collects = signers
            .infos()
            .into_iter()
            .find(|(n, _)| *n == signer)
            .and_then(|(_, i)| i)
            .map_or(logos_signer_interface::Collects::Nothing, |i| i.collects);
        Ok(Rendered { handle, bundle_id, requester, claim_lines, render_lines, signer, collects, account })
    }

    /// Who asked, and for which account: what an unlock's scope is checked against.
    pub fn requester_and_account(&self, handle: &str) -> Option<(String, String)> {
        self.records.iter().find(|r| r.handle == handle).map(|r| (r.requester.clone(), r.account.clone()))
    }

    /// The person said yes. Re-derives the commitment, checks the approver echoed what it showed,
    /// and has the account's signer sign. A wrong secret leaves the record on screen. With no
    /// secret, a signer that collects one signs only inside an unlock that covers the requester.
    pub fn approve(
        &mut self,
        signers: &mut Registry,
        handle: &str,
        bundle_id_echo: &str,
        secret: &str,
        unlocked: bool,
    ) -> Result<Approved> {
        self.sweep();
        let r = self.find(handle).ok_or_else(|| ManagerError::NotFound(handle.to_string()))?;
        if r.state != State::Rendered {
            return Err(bad("approve: this handle was not the one being rendered"));
        }
        self.sign(signers, handle, Some(bundle_id_echo), secret, unlocked)
    }

    /// Sign as the request arrives, inside an unlock the person granted without confirmation.
    pub fn sign_unattended(&mut self, signers: &mut Registry, handle: &str) -> Result<Approved> {
        let r = self.find(handle).ok_or_else(|| ManagerError::NotFound(handle.to_string()))?;
        if r.state != State::Offered {
            return Err(bad("sign_unattended: this request was already shown"));
        }
        self.sign(signers, handle, None, "", true)
    }

    fn sign(&mut self, signers: &mut Registry, handle: &str, echo: Option<&str>, secret: &str, unlocked: bool) -> Result<Approved> {
        let r = self.find(handle).ok_or_else(|| ManagerError::NotFound(handle.to_string()))?;
        let prepared = prepare(signers, &r.intent)?;
        let fresh = commitment(&r.intent, &prepared)?;
        if fresh != r.bundle_id {
            return Err(bad("approve: commitment drift"));
        }
        if echo.is_some_and(|e| e.trim().trim_start_matches("0x") != hex::encode(fresh)) {
            return Err(bad("approve: bundle_id does not match the rendered request"));
        }
        let found = prepared.found().clone();
        if secret.is_empty() && !unlocked && found.info.collects != logos_signer_interface::Collects::Nothing {
            let e = logos_signer_interface::SignerError::new(
                logos_signer_interface::ErrorCode::Locked,
                format!("{} is not unlocked for {}: approve with its password", found.account.id, r.requester),
            );
            r.last_error = Some(e.message.clone());
            return Err(e.into());
        }
        if !found.info.request_kinds.contains(&RequestKind::Hash) {
            return Err(ManagerError::Refused(format!("{} signs whole requests; this manager hands it hashes only", found.name)));
        }
        let items = items_for(&r.intent, &prepared)?;
        let request = SignRequest {
            account: found.account.id.clone(),
            payload: Payload::Hash { items },
            secret: (!secret.is_empty()).then(|| Secret::new(secret)),
        };
        let signer = signers.signer(found.signer);
        let job = match signer.sign(request) {
            Ok(job) => job,
            Err(e) => {
                r.last_error = Some(e.message.clone());
                return Err(e.into());
            }
        };
        r.job = Some(job);
        r.state = State::Signing;
        r.last_error = None;
        let handle = r.handle.clone();
        self.advance(signers, &handle);
        let r = self.find(&handle).expect("advanced, not removed");
        match r.state {
            State::Settled(Outcome::Approved) => Ok(Approved::Settled(r.results.as_ref().map_or(0, Vec::len))),
            State::Signing => Ok(Approved::Signing),
            State::Settled(o) => Err(bad(format!("the signer settled this as {}", o.as_str()))),
            _ => Err(ManagerError::Signing(r.last_error.clone().unwrap_or_else(|| "the signer did not sign".into()))),
        }
    }

    /// Move every record whose signer is working, once.
    pub fn progress(&mut self, signers: &mut Registry) {
        self.sweep();
        let working: Vec<String> =
            self.records.iter().filter(|r| r.state == State::Signing).map(|r| r.handle.clone()).collect();
        for h in working {
            self.advance(signers, &h);
        }
    }

    /// Ask the signer how a record's job stands, and settle it if it has an answer.
    fn advance(&mut self, signers: &mut Registry, handle: &str) {
        let Some(r) = self.find(handle) else { return };
        let Some(job) = r.job.clone() else { return };
        let outcome = (|| -> Result<Option<Vec<String>>> {
            let prepared = prepare(signers, &r.intent)?;
            let found = prepared.found().clone();
            let signer = signers.signer(found.signer);
            let status = signer.status(&job)?;
            match status.state {
                JobState::Done => {
                    let sigs = signer.result(&job)?;
                    Ok(Some(results(&r.intent, prepared, &sigs)?))
                }
                JobState::Refused => Err(ManagerError::Refused("declined on the device".into())),
                JobState::Failed | JobState::Cancelled => Err(status
                    .error
                    .map(ManagerError::from)
                    .unwrap_or_else(|| ManagerError::Signing(format!("the signer's job ended {}", status.state.as_str())))),
                JobState::Working | JobState::ConfirmOnDevice => Ok(None),
            }
        })();
        let moved = match outcome {
            Ok(Some(out)) => {
                r.results = Some(out);
                r.state = State::Settled(Outcome::Approved);
                r.job = None;
                Move::Settled(handle.to_string(), Outcome::Approved)
            }
            Ok(None) => return,
            Err(ManagerError::Refused(_)) => {
                r.state = State::Settled(Outcome::Rejected);
                r.job = None;
                Move::Settled(handle.to_string(), Outcome::Rejected)
            }
            Err(e) => {
                // Back on screen, saying why, so the person can try again.
                r.last_error = Some(e.to_string());
                r.state = State::Rendered;
                r.job = None;
                Move::Rendered(handle.to_string())
            }
        };
        self.moves.push(moved);
    }

    /// What moved since the last call, for the glue to announce.
    pub fn drain_moves(&mut self) -> Vec<Move> {
        std::mem::take(&mut self.moves)
    }

    pub fn reject(&mut self, signers: &mut Registry, handle: &str) -> Result<()> {
        self.sweep();
        let r = self.find(handle).ok_or_else(|| ManagerError::NotFound(handle.to_string()))?;
        if let State::Settled(o) = r.state {
            return Err(bad(format!("already settled: {}", o.as_str())));
        }
        cancel_job(signers, r);
        r.state = State::Settled(Outcome::Rejected);
        Ok(())
    }

    /// Bare state for the requester: never the intent, never the results.
    pub fn status(&mut self, signers: &mut Registry, handle: &str, receipt: &str) -> Result<(&'static str, Option<&'static str>)> {
        self.progress(signers);
        let r = self.by_receipt(handle, receipt)?;
        Ok(match r.state {
            State::Settled(o) => ("settled", Some(o.as_str())),
            s => (s.as_str(), None),
        })
    }

    /// Collect the results. Idempotent until `ack_result`: a dropped reply must not cost a second approval.
    pub fn fetch_result(&mut self, signers: &mut Registry, handle: &str, receipt: &str) -> Result<Vec<String>> {
        self.progress(signers);
        let r = self.by_receipt(handle, receipt)?;
        r.results.clone().ok_or_else(|| bad("no result for this handle"))
    }

    pub fn ack_result(&mut self, handle: &str, receipt: &str) -> Result<()> {
        self.by_receipt(handle, receipt)?.results = None;
        self.sweep();
        Ok(())
    }

    /// The requester gave up; a signer still working is told to stop.
    pub fn cancel(&mut self, signers: &mut Registry, handle: &str, receipt: &str) -> Result<()> {
        let r = self.by_receipt(handle, receipt)?;
        if !matches!(r.state, State::Settled(_)) {
            cancel_job(signers, r);
            r.state = State::Settled(Outcome::Cancelled);
        }
        r.results = None;
        self.sweep();
        Ok(())
    }
}

fn cancel_job(signers: &mut Registry, r: &mut Record) {
    if let Some(job) = r.job.take() {
        if let Ok(found) = prepare(signers, &r.intent).map(|p| p.found().clone()) {
            let _ = signers.signer(found.signer).cancel(&job);
        }
    }
}

// ── reading a request ───────────────────────────────────────────────────────

enum Prepared {
    Evm { found: Found },
    /// A Bitcoin request: the manager's reading of its PSBT.
    Psbt { found: Found, acct: AccountPublic, psbt: Box<Psbt>, checked: Checked, name: String },
}

impl Prepared {
    fn found(&self) -> &Found {
        match self {
            Prepared::Evm { found } | Prepared::Psbt { found, .. } => found,
        }
    }
}

fn evm_only() -> ManagerError {
    bad("intent: a psbt leg needs a Bitcoin group, not an address")
}

/// Check the intent's shape, find the account's signer, and read a Bitcoin request's PSBT.
fn prepare(signers: &mut Registry, intent: &Intent) -> Result<Prepared> {
    let bitcoin = !intent.group.trim().is_empty();
    if bitcoin == !intent.address.trim().is_empty() {
        return Err(bad("intent: name exactly one of address (EVM) or group (Bitcoin)"));
    }
    if !bitcoin {
        if intent.legs.iter().any(|l| matches!(l, Leg::Psbt { .. })) {
            return Err(evm_only());
        }
        let addr = evm::parse_address(&intent.address)?;
        let found = signers.find(&format!("{addr}"))?;
        if found.account.family != logos_signer_interface::Family::Evm {
            return Err(bad(format!("{} is not an EVM account", intent.address.trim())));
        }
        return Ok(Prepared::Evm { found });
    }
    let [Leg::Psbt { network, psbt }] = intent.legs.as_slice() else {
        return Err(bad("intent: a Bitcoin request carries exactly one psbt leg"));
    };
    let found = signers.find(intent.group.trim())?;
    let acct = AccountPublic::from_account(&found.account)?;
    let net: Network = acct.chain.network(network)?;
    let parsed = btcpsbt::parse(psbt)?;
    let name = found
        .account
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty() && check_displayable(l, "label").is_ok())
        .map_or_else(|| found.account.id.clone(), |l| format!("\"{l}\""));
    let checked = btcpsbt::check(&Secp256k1::verification_only(), &acct, net, &name, &parsed)?;
    Ok(Prepared::Psbt { found, acct, psbt: Box::new(parsed), checked, name })
}

/// The digest each leg signs, from the same parsed value the person was shown.
fn items_for(intent: &Intent, prepared: &Prepared) -> Result<Vec<HashItem>> {
    if let Prepared::Psbt { acct, psbt, checked, .. } = prepared {
        return btcpsbt::hash_items(acct, psbt, checked);
    }
    intent
        .legs
        .iter()
        .map(|leg| {
            let digest = match leg {
                Leg::Tx { chain_id, tx } => ParsedTx::parse(tx, *chain_id)?.signing_hash(),
                Leg::Message { text } => evm::message_hash(text)?,
                Leg::Digest { digest, .. } => evm::parse_b256(digest)?,
                Leg::TypedData { typed_data } => evm::typed_data_signing_hash(typed_data)?,
                Leg::Psbt { .. } => return Err(evm_only()),
            };
            Ok(HashItem { path: None, scheme: Scheme::Evm, digest: hex::encode(digest) })
        })
        .collect()
}

/// The results from the signer's answer: each signature checked against the account's public
/// material over the digest computed here, then built into what the requester collects.
fn results(intent: &Intent, prepared: Prepared, sigs: &[Signature]) -> Result<Vec<String>> {
    let items = items_for(intent, &prepared)?;
    match prepared {
        Prepared::Psbt { acct, mut psbt, checked, .. } => {
            btcpsbt::insert_signatures(&Secp256k1::verification_only(), &acct, &mut psbt, &checked, &items, sigs)?;
            Ok(vec![psbt.to_string()])
        }
        Prepared::Evm { found } => {
            let mut out = Vec::with_capacity(items.len());
            for (i, (leg, item)) in intent.legs.iter().zip(&items).enumerate() {
                let mut mine = sigs.iter().filter(|s| s.item == i);
                let (Some(sig), None) = (mine.next(), mine.next()) else {
                    return Err(ManagerError::Signing(format!("item {i}: expected exactly one signature")));
                };
                verify::check(&found.account, item, sig).map_err(|e| ManagerError::Signing(format!("item {i}: {e}")))?;
                let s = evm::signature(&sig.signature, sig.recovery_id)?;
                out.push(match leg {
                    Leg::Tx { chain_id, tx } => ParsedTx::parse(tx, *chain_id)?.signed_hex(s),
                    _ => evm::signature_hex(&s),
                });
            }
            if sigs.len() != items.len() {
                return Err(ManagerError::Signing("more signatures than items".into()));
            }
            Ok(out)
        }
    }
}

// ── commitment and render ───────────────────────────────────────────────────

/// SHA-256 over the manager's own re-encoding of the parsed intent, never the requester's bytes.
fn commitment(intent: &Intent, prepared: &Prepared) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"logos-signer-manager-approval-v1\n");
    if let Prepared::Psbt { checked, .. } = prepared {
        h.update(b"group\n");
        h.update(intent.group.trim().as_bytes());
        h.update(b"\n");
        h.update(&checked.canonical);
        return Ok(h.finalize().into());
    }
    h.update(intent.address.trim().to_lowercase().as_bytes());
    h.update(b"\n");
    for leg in &intent.legs {
        match leg {
            Leg::Tx { chain_id, tx } => {
                h.update(b"tx\n");
                h.update(chain_id.to_string().as_bytes());
                h.update(b"\n");
                for field in [
                    tx.to.clone().unwrap_or_default(),
                    tx.create.to_string(),
                    tx.value.clone(),
                    tx.nonce.clone(),
                    tx.gas_limit.clone(),
                    tx.data.clone(),
                    tx.fee_mode.clone(),
                    tx.max_fee_per_gas.clone(),
                    tx.max_priority_fee_per_gas.clone(),
                    tx.gas_price.clone(),
                ] {
                    h.update(field.trim().to_lowercase().as_bytes());
                    h.update(b"\x1f");
                }
            }
            Leg::Message { text } => {
                h.update(b"message\n");
                h.update(text.as_bytes());
            }
            Leg::Digest { digest, purpose } => {
                h.update(b"digest\n");
                h.update(digest.trim().trim_start_matches("0x").to_lowercase().as_bytes());
                h.update(b"\x1f");
                h.update(purpose.as_bytes());
            }
            Leg::TypedData { typed_data } => {
                h.update(b"typed_data\n");
                h.update(evm::typed_data_signing_hash(typed_data)?.as_slice());
            }
            Leg::Psbt { .. } => return Err(evm_only()),
        }
        h.update(b"\n");
    }
    Ok(h.finalize().into())
}

/// The lines an approver shows, verbatim: the claim apart from what is signed.
fn render(intent: &Intent, prepared: &Prepared, bundle_id: &[u8; 32]) -> Result<(Vec<String>, Vec<String>)> {
    let mut claim = Vec::new();
    if !intent.purpose.trim().is_empty() {
        claim.push(format!("Purpose (claimed by the requester): {}", intent.purpose.trim()));
    }
    let mut out = Vec::new();
    if let Prepared::Psbt { checked, name, .. } = prepared {
        out.push(format!("Wallet: {name}"));
        out.push(format!("Commitment: {}", hex::encode(bundle_id)));
        out.push("1 item(s) to sign:".into());
        for (k, line) in checked.lines.iter().enumerate() {
            out.push(if k == 0 { format!("  [1] {line}") } else { format!("      {line}") });
        }
        return Ok((claim, out));
    }
    out.push(format!("Account: {}", intent.address.trim()));
    out.push(format!("Commitment: {}", hex::encode(bundle_id)));
    out.push(format!("{} item(s) to sign:", intent.legs.len()));
    for (i, leg) in intent.legs.iter().enumerate() {
        let n = i + 1;
        match leg {
            Leg::Tx { chain_id, tx } => {
                out.push(format!("  [{n}] Transaction on chain {chain_id}"));
                match tx.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    Some(to) => out.push(format!("      To: {to}")),
                    None => out.push("      ** CONTRACT CREATION — no recipient **".into()),
                }
                out.push(format!("      Value: {}", norm_num(&tx.value)));
                out.push(format!("      Nonce: {}", norm_num(&tx.nonce)));
                out.push(format!("      Gas limit: {}", norm_num(&tx.gas_limit)));
                fee_lines(tx, &mut out);
                let data = tx.data.trim();
                if data.is_empty() || data == "0x" {
                    out.push("      Data: (none)".into());
                } else {
                    let d = data.trim_start_matches("0x");
                    if d.len() >= 8 {
                        out.push(format!("      Selector: 0x{}", &d[..8]));
                    }
                    out.push(format!("      Data: 0x{d}"));
                }
            }
            Leg::Message { text } => {
                check_displayable(text, "message")?;
                out.push(format!("  [{n}] Sign text message"));
                out.push(format!("      Text: {text}"));
                out.push(format!("      Bytes: 0x{}", hex::encode(text.as_bytes())));
            }
            Leg::Digest { digest, purpose } => {
                check_displayable(purpose, "purpose")?;
                out.push(format!("  [{n}] Sign an OPAQUE 32-byte digest"));
                out.push(format!("      Purpose (claimed by the requester): {purpose}"));
                out.push(format!("      Digest: {}", digest.trim()));
                out.push("      This signer cannot show you what this authorises.".into());
            }
            Leg::TypedData { typed_data } => {
                out.push(format!("  [{n}] Sign EIP-712 typed data"));
                render_typed_data(typed_data, &mut out)?;
                out.push(format!("      Signing hash: 0x{}", hex::encode(evm::typed_data_signing_hash(typed_data)?)));
            }
            Leg::Psbt { .. } => return Err(evm_only()),
        }
    }
    Ok((claim, out))
}

/// The domain, the type, and every field of the message, nested fields indented.
fn render_typed_data(v: &serde_json::Value, out: &mut Vec<String>) -> Result<()> {
    let domain = v.get("domain").cloned().unwrap_or(serde_json::Value::Null);
    let mut bits = Vec::new();
    for key in ["name", "version", "chainId", "verifyingContract", "salt"] {
        if let Some(x) = domain.get(key) {
            bits.push(format!("{key}={}", json_scalar(x)?));
        }
    }
    out.push(format!("      Domain: {}", if bits.is_empty() { "(none)".to_string() } else { bits.join(", ") }));
    let primary = v.get("primaryType").and_then(|p| p.as_str()).unwrap_or("?");
    check_displayable(primary, "primaryType")?;
    out.push(format!("      Type: {primary}"));
    out.push("      Message:".into());
    match v.get("message") {
        Some(serde_json::Value::Object(m)) => render_json_fields(m, 8, out)?,
        _ => out.push("        (none)".into()),
    }
    Ok(())
}

fn json_scalar(x: &serde_json::Value) -> Result<String> {
    Ok(match x {
        serde_json::Value::String(s) => {
            check_displayable(s, "typed data field")?;
            s.clone()
        }
        serde_json::Value::Null => "null".into(),
        other => other.to_string(),
    })
}

fn render_json_fields(m: &serde_json::Map<String, serde_json::Value>, indent: usize, out: &mut Vec<String>) -> Result<()> {
    let pad = " ".repeat(indent);
    for (k, x) in m {
        check_displayable(k, "typed data field name")?;
        match x {
            serde_json::Value::Object(inner) => {
                out.push(format!("{pad}{k}:"));
                render_json_fields(inner, indent + 2, out)?;
            }
            serde_json::Value::Array(items) => {
                out.push(format!("{pad}{k}: {} item(s)", items.len()));
                for (i, item) in items.iter().enumerate() {
                    match item {
                        serde_json::Value::Object(inner) => {
                            out.push(format!("{pad}  [{i}]"));
                            render_json_fields(inner, indent + 4, out)?;
                        }
                        other => out.push(format!("{pad}  [{i}] {}", json_scalar(other)?)),
                    }
                }
            }
            other => out.push(format!("{pad}{k}: {}", json_scalar(other)?)),
        }
    }
    Ok(())
}

/// Hex and decimal both, so nobody converts in their head.
fn norm_num(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return "0".into();
    }
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => match u128::from_str_radix(h, 16) {
            Ok(v) => format!("{t} ({v})"),
            Err(_) => t.to_string(),
        },
        None => t.to_string(),
    }
}

/// The fee a transaction leg signs and the most its gas can cost; a zero tip is flagged.
fn fee_lines(tx: &UnsignedTx, out: &mut Vec<String>) {
    let per_gas = match tx.fee_mode.trim() {
        "" | "eip1559" => {
            out.push(format!("      Max fee per gas: {}", wei_per_gas(&tx.max_fee_per_gas)));
            out.push(format!("      Max priority fee per gas: {}", wei_per_gas(&tx.max_priority_fee_per_gas)));
            if parse_u128(&tx.max_priority_fee_per_gas, "").ok() == Some(0) {
                out.push("      ** ZERO PRIORITY FEE — this may never be included **".into());
            }
            parse_u128(&tx.max_fee_per_gas, "").ok()
        }
        "legacy" => {
            out.push(format!("      Gas price: {}", wei_per_gas(&tx.gas_price)));
            parse_u128(&tx.gas_price, "").ok()
        }
        other => {
            out.push(format!("      ** UNSUPPORTED FEE MODE {other:?} — this cannot be signed **"));
            None
        }
    };
    if let (Some(gas), Some(price)) = (parse_u128(&tx.gas_limit, "").ok(), per_gas) {
        let most = U256::from(gas) * U256::from(price);
        out.push(format!("      Fee at most: {most} wei ({} of the native coin)", decimal(most, 18)));
    }
}

fn wei_per_gas(s: &str) -> String {
    match parse_u128(s, "") {
        Ok(v) => format!("{v} wei ({} gwei)", decimal(U256::from(v), 9)),
        Err(_) => format!("{} (unreadable: this cannot be signed)", s.trim()),
    }
}

/// `v` scaled down by `places` decimal digits, exactly, without trailing zeros.
fn decimal(v: U256, places: usize) -> String {
    let digits = v.to_string();
    let (int, frac) = if digits.len() > places { digits.split_at(digits.len() - places) } else { ("0", digits.as_str()) };
    let frac = format!("{frac:0>places$}");
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// 128 random bits, folded with a counter so two mints in one instant cannot collide.
fn token_hex(seq: u64) -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{}{:x}", hex::encode(b), seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Collects, ErrorCode, JobStatus, Signer, SignerInfo};

    const ACCT0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    /// The manager with one signer: software keys that ask for the password "pw", like the keystore.
    fn fixture() -> (Registry, Approvals) {
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions { collects: Collects::Password, secret: "pw".into(), ..Default::default() })));
        (r, Approvals::new())
    }

    fn tx_intent(nonce: &str) -> String {
        format!(
            r#"{{"address":"{ACCT0}","purpose":"send","legs":[
                {{"kind":"tx","chain_id":1,"tx":{{
                    "to":"{ACCT0}","value":"0x0","nonce":"{nonce}","gas_limit":"0x5208",
                    "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}}}]}}"#
        )
    }

    fn approve(ap: &mut Approvals, s: &mut Registry, h: &str, bundle: &str, pw: &str) -> Result<usize> {
        match ap.approve(s, h, bundle, pw, false)? {
            Approved::Settled(n) => Ok(n),
            Approved::Signing => Err(bad("still signing")),
        }
    }

    #[test]
    fn approve_refuses_a_handle_that_is_not_the_one_being_rendered() {
        let (mut s, mut ap) = fixture();
        let (h1, _) = ap.request(&mut s, "wallet_backend", &tx_intent("0x1")).unwrap();
        let (h2, _) = ap.request(&mut s, "wallet_backend", &tx_intent("0x2")).unwrap();
        let v1 = ap.acknowledge(&mut s, &h1).unwrap();
        let _ = ap.acknowledge(&mut s, &h2).unwrap();
        let err = approve(&mut ap, &mut s, &h1, &v1.bundle_id, "pw").unwrap_err();
        assert!(err.to_string().contains("not the one being rendered"), "{err}");
        let v2 = ap.acknowledge(&mut s, &h2).unwrap();
        assert_eq!(approve(&mut ap, &mut s, &h2, &v2.bundle_id, "pw").unwrap(), 1);
    }

    #[test]
    fn approve_requires_the_bundle_id_that_was_displayed() {
        let (mut s, mut ap) = fixture();
        let (h, _) = ap.request(&mut s, "wallet_backend", &tx_intent("0x1")).unwrap();
        ap.acknowledge(&mut s, &h).unwrap();
        assert!(approve(&mut ap, &mut s, &h, &"00".repeat(32), "pw").is_err());
    }

    #[test]
    fn a_wrong_password_neither_signs_nor_settles_the_record() {
        let (mut s, mut ap) = fixture();
        let (h, r) = ap.request(&mut s, "wallet_backend", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        assert_eq!(v.signer, "keystore_module");
        assert_eq!(v.collects, Collects::Password);
        assert_eq!(v.account.to_lowercase(), ACCT0.to_lowercase(), "what an unlock of it names");
        let e = ap.approve(&mut s, &h, &v.bundle_id, "wrong", false).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::WrongSecret), "the approver can ask again: {e}");
        assert_eq!(ap.status(&mut s, &h, &r).unwrap().0, "rendered");
        let e = ap.approve(&mut s, &h, &v.bundle_id, "", false).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::Locked));
        assert_eq!(approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap(), 1);
    }

    #[test]
    fn results_are_idempotent_until_acked_then_erased() {
        let (mut s, mut ap) = fixture();
        let (h, r) = ap.request(&mut s, "wallet_backend", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap();
        let a = ap.fetch_result(&mut s, &h, &r).unwrap();
        assert_eq!(a, ap.fetch_result(&mut s, &h, &r).unwrap());
        assert!(a[0].starts_with("0x"));
        ap.ack_result(&h, &r).unwrap();
        assert!(ap.fetch_result(&mut s, &h, &r).is_err());
    }

    #[test]
    fn the_receipt_not_the_handle_is_what_authorises_collection() {
        let (mut s, mut ap) = fixture();
        let (h, r) = ap.request(&mut s, "wallet_backend", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap();
        assert!(ap.fetch_result(&mut s, &h, "smc_not_the_receipt").is_err());
        assert!(ap.fetch_result(&mut s, &h, &r).is_ok());
    }

    #[test]
    fn the_commitment_covers_the_parsed_value_not_the_requesters_bytes() {
        let (mut s, mut ap) = fixture();
        let pretty = tx_intent("0x1");
        let compact: String = pretty.split_whitespace().collect::<Vec<_>>().join(" ");
        let (h1, _) = ap.request(&mut s, "a", &pretty).unwrap();
        let (h2, _) = ap.request(&mut s, "b", &compact).unwrap();
        let v1 = ap.acknowledge(&mut s, &h1).unwrap();
        let v2 = ap.acknowledge(&mut s, &h2).unwrap();
        assert_eq!(v1.bundle_id, v2.bundle_id);
        let (h3, _) = ap.request(&mut s, "c", &tx_intent("0x2")).unwrap();
        assert_ne!(v1.bundle_id, ap.acknowledge(&mut s, &h3).unwrap().bundle_id);
    }

    #[test]
    fn the_requesters_account_of_the_request_is_kept_out_of_what_is_signed() {
        let (mut s, mut ap) = fixture();
        let intent = tx_intent("0x1").replace(r#""purpose":"send""#, r#""purpose":"Send 1 ETH to Alice""#);
        let (h, _) = ap.request(&mut s, "wallet_backend", &intent).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        let (claim, signed) = (v.claim_lines.join("\n"), v.render_lines.join("\n"));
        assert!(claim.contains("Send 1 ETH to Alice") && claim.contains("claimed by the requester"), "{claim}");
        assert!(!signed.contains("Send 1 ETH to Alice"), "{signed}");
        assert!(signed.contains("Commitment:") && signed.contains("Account:"), "{signed}");
    }

    #[test]
    fn the_render_shows_full_calldata_and_flags_contract_creation() {
        let (mut s, mut ap) = fixture();
        let intent = format!(
            r#"{{"address":"{ACCT0}","legs":[{{"kind":"tx","chain_id":1,"tx":{{
                "create":true,"value":"0x0","nonce":"0x1","gas_limit":"0x5208","data":"0xdeadbeefcafe",
                "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}}}]}}"#
        );
        let (h, _) = ap.request(&mut s, "wallet_backend", &intent).unwrap();
        let all = ap.acknowledge(&mut s, &h).unwrap().render_lines.join("\n");
        assert!(all.contains("CONTRACT CREATION") && all.contains("0xdeadbeefcafe") && all.contains("Selector: 0xdeadbeef"), "{all}");
    }

    fn fee_render(fee: &str) -> String {
        let (mut s, mut ap) = fixture();
        let intent = format!(
            r#"{{"address":"{ACCT0}","legs":[{{"kind":"tx","chain_id":1,"tx":{{
                "to":"{ACCT0}","value":"0x0","nonce":"0x1","gas_limit":"0x5208","data":"0x",{fee}}}}}]}}"#
        );
        let (h, _) = ap.request(&mut s, "wallet_backend", &intent).unwrap();
        ap.acknowledge(&mut s, &h).unwrap().render_lines.join("\n")
    }

    #[test]
    fn the_render_shows_the_fee_it_signs_and_its_ceiling() {
        let all = fee_render(r#""fee_mode":"eip1559","max_fee_per_gas":"0xbd0b858e","max_priority_fee_per_gas":"169400000""#);
        assert!(all.contains("Max fee per gas: 3171648910 wei (3.17164891 gwei)"), "{all}");
        assert!(all.contains("Max priority fee per gas: 169400000 wei (0.1694 gwei)"), "{all}");
        assert!(all.contains("Fee at most: 66604627110000 wei (0.00006660462711 of the native coin)"), "{all}");
        let all = fee_render(r#""max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0""#);
        assert!(all.contains("** ZERO PRIORITY FEE — this may never be included **"), "{all}");
        let all = fee_render(r#""fee_mode":"legacy","gas_price":"7""#);
        assert!(all.contains("Gas price: 7 wei (0.000000007 gwei)") && !all.contains("Max fee per gas"), "{all}");
        let all = fee_render(r#""fee_mode":"eip4844","max_fee_per_gas":"0x1""#);
        assert!(all.contains("UNSUPPORTED FEE MODE") && !all.contains("Fee at most"), "{all}");
    }

    /// What the keystore produced when it signed itself, for the same key: the results must not change.
    fn as_the_keystore_signed(digest: alloy::primitives::B256) -> alloy::primitives::Signature {
        use alloy::signers::SignerSync;
        let key: alloy::signers::local::PrivateKeySigner = PK.parse().unwrap();
        key.sign_hash_sync(&digest).unwrap()
    }

    #[test]
    fn a_signed_transaction_is_byte_for_byte_the_one_the_keystore_returned() {
        use alloy::consensus::{Transaction as _, TxEnvelope};
        use alloy::eips::eip2718::Decodable2718;
        let (mut s, mut ap) = fixture();
        let intent = format!(
            r#"{{"address":"{ACCT0}","legs":[{{"kind":"tx","chain_id":1,"tx":{{
                "to":"{ACCT0}","value":"0x0","nonce":"0x1","gas_limit":"0x5208","data":"0x",
                "max_fee_per_gas":"0xbd0b858e","max_priority_fee_per_gas":"169400000"}}}}]}}"#
        );
        let (h, r) = ap.request(&mut s, "wallet_backend", &intent).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        assert_eq!(approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap(), 1);
        let got = ap.fetch_result(&mut s, &h, &r).unwrap().remove(0);
        let parsed: Intent = serde_json::from_str(&intent).unwrap();
        let Leg::Tx { chain_id, tx } = &parsed.legs[0] else { unreachable!() };
        let expected = ParsedTx::parse(tx, *chain_id).unwrap();
        let sig = as_the_keystore_signed(expected.signing_hash());
        assert_eq!(got, expected.signed_hex(sig));
        let raw = hex::decode(got.trim_start_matches("0x")).unwrap();
        let env = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(env.max_fee_per_gas(), 3171648910);
    }

    fn mail_typed_data() -> &'static str {
        r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCCCCCCCCcCCCCCCCcccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#
    }
    // EIP-712's own published signing hash for its Mail example.
    const MAIL_SIGNING_HASH: &str = "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";

    #[test]
    fn typed_data_is_hashed_here_shown_field_by_field_and_signed_as_the_keystore_did() {
        let (mut s, mut ap) = fixture();
        let td: serde_json::Value = serde_json::from_str(mail_typed_data()).unwrap();
        assert_eq!(hex::encode(evm::typed_data_signing_hash(&td).unwrap()), MAIL_SIGNING_HASH);
        let intent = format!(r#"{{"address":"{ACCT0}","legs":[{{"kind":"typed_data","typed_data":{}}}]}}"#, mail_typed_data());
        let (h, r) = ap.request(&mut s, "some_dapp", &intent).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        let all = v.render_lines.join("\n");
        assert!(all.contains("Type: Mail") && all.contains("        contents: Hello, Bob!"), "{all}");
        assert!(all.contains(&format!("Signing hash: 0x{MAIL_SIGNING_HASH}")), "{all}");
        approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap();
        let got = ap.fetch_result(&mut s, &h, &r).unwrap().remove(0);
        let hash = alloy::primitives::B256::from_slice(&hex::decode(MAIL_SIGNING_HASH).unwrap());
        assert_eq!(got, evm::signature_hex(&as_the_keystore_signed(hash)));
    }

    #[test]
    fn a_message_signature_is_the_one_the_keystore_returned() {
        let (mut s, mut ap) = fixture();
        let intent = format!(r#"{{"address":"{ACCT0}","legs":[{{"kind":"message","text":"hello-logos"}}]}}"#);
        let (h, r) = ap.request(&mut s, "wallet_backend", &intent).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap();
        let got = ap.fetch_result(&mut s, &h, &r).unwrap().remove(0);
        assert_eq!(got, evm::signature_hex(&as_the_keystore_signed(evm::message_hash("hello-logos").unwrap())));
    }

    #[test]
    fn a_bundle_is_one_decision_over_several_legs() {
        let (mut s, mut ap) = fixture();
        let leg = |n: u8| format!(r#"{{"kind":"tx","chain_id":1,"tx":{{"to":"{ACCT0}","value":"0x0","nonce":"0x{n}","gas_limit":"0x5208","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}}}"#);
        let intent = format!(r#"{{"address":"{ACCT0}","legs":[{},{},{{"kind":"message","text":"and this"}}]}}"#, leg(1), leg(2));
        let (h, r) = ap.request(&mut s, "wallet_backend", &intent).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        assert_eq!(approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap(), 3);
        assert_eq!(ap.fetch_result(&mut s, &h, &r).unwrap().len(), 3);
    }

    #[test]
    fn an_unacknowledged_request_expires_and_says_why() {
        let (mut s, mut ap) = fixture();
        ap.set_abandoned_offer_ttl(Duration::from_millis(0));
        let (h, r) = ap.request(&mut s, "wallet_backend", &tx_intent("0x1")).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(ap.status(&mut s, &h, &r).unwrap(), ("settled", Some("expired_no_ack")));
        assert!(ap.acknowledge(&mut s, &h).is_err());
    }

    #[test]
    fn a_requester_cannot_flood_the_queue() {
        let (mut s, mut ap) = fixture();
        for i in 0..MAX_PENDING_PER_REQUESTER {
            ap.request(&mut s, "noisy", &tx_intent(&format!("0x{i}"))).unwrap();
        }
        assert!(ap.request(&mut s, "noisy", &tx_intent("0xff")).is_err());
        assert!(ap.request(&mut s, "quiet", &tx_intent("0x1")).is_ok());
    }

    #[test]
    fn an_oversize_or_empty_intent_or_an_account_no_signer_offers_is_refused() {
        let (mut s, mut ap) = fixture();
        let huge = format!(r#"{{"address":"{ACCT0}","purpose":"{}","legs":[]}}"#, "a".repeat(MAX_INTENT_BYTES));
        assert!(ap.request(&mut s, "x", &huge).is_err());
        assert!(ap.request(&mut s, "x", &format!(r#"{{"address":"{ACCT0}","legs":[]}}"#)).is_err());
        let stranger = tx_intent("0x1").replace(r#""address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266""#, r#""address":"0x0000000000000000000000000000000000000001""#);
        assert!(matches!(ap.request(&mut s, "x", &stranger), Err(ManagerError::NotFound(_))));
    }

    // ── Bitcoin requests ────────────────────────────────────────────────

    fn psbt_intent(group: &str, psbt: &Psbt) -> String {
        format!(r#"{{"group":"{group}","purpose":"pay","legs":[{{"kind":"psbt","network":"regtest","psbt":"{psbt}"}}]}}"#)
    }

    #[test]
    fn a_bitcoin_request_is_read_shown_and_signed_through_its_signer() {
        for family in [crate::btc::Family::Segwit, crate::btc::Family::Taproot] {
            let (mut s, mut ap) = fixture();
            let (_, listed, acct) = crate::psbt::tests::ours(family);
            let psbt = crate::psbt::tests::sample(&acct);
            let (h, r) = ap.request(&mut s, "bitcoin_wallet_core_module", &psbt_intent(&listed.id, &psbt)).unwrap();
            let v = ap.acknowledge(&mut s, &h).unwrap();
            let all = v.render_lines.join("\n");
            assert!(all.starts_with("Wallet: \"Mock "), "{all}");
            assert!(all.contains("Fee 1,190 sats"), "{all}");
            assert_eq!(approve(&mut ap, &mut s, &h, &v.bundle_id, "pw").unwrap(), 1);
            let signed: Psbt = ap.fetch_result(&mut s, &h, &r).unwrap().remove(0).parse().unwrap();
            assert_eq!(signed.unsigned_tx, psbt.unsigned_tx, "signing changed the transaction");
            for input in &signed.inputs {
                assert!(!input.partial_sigs.is_empty() || input.tap_key_sig.is_some(), "{family:?}");
            }
        }
    }

    #[test]
    fn a_bitcoin_request_names_its_wallet_and_carries_one_psbt() {
        let (mut s, mut ap) = fixture();
        let (_, listed, acct) = crate::psbt::tests::ours(crate::btc::Family::Segwit);
        let psbt = crate::psbt::tests::sample(&acct);
        let both = psbt_intent(&listed.id, &psbt).replacen("{", &format!(r#"{{"address":"{ACCT0}","#), 1);
        assert!(ap.request(&mut s, "x", &both).is_err());
        let two = psbt_intent(&listed.id, &psbt).replace("}]}", r#"},{"kind":"message","text":"x"}]}"#);
        assert!(ap.request(&mut s, "x", &two).is_err());
        assert!(ap.request(&mut s, "x", &psbt_intent(ACCT0, &psbt)).is_err(), "an EVM account is no wallet");
    }

    /// A signer that answers with signatures over something else.
    struct Liar(MockSigner);

    impl Signer for Liar {
        fn info(&self) -> SignerInfo {
            self.0.info()
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<logos_signer_interface::Account>> {
            self.0.accounts()
        }
        fn sign(&mut self, mut request: SignRequest) -> logos_signer_interface::Result<String> {
            if let Payload::Hash { items } = &mut request.payload {
                for item in items {
                    item.digest = "11".repeat(32);
                }
            }
            self.0.sign(request)
        }
        fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.0.status(job)
        }
        fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            self.0.result(job)
        }
        fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.0.cancel(job)
        }
    }

    #[test]
    fn a_signature_over_something_else_settles_nothing() {
        let mut s = Registry::new();
        s.add("liar", Box::new(Liar(MockSigner::new(MockOptions::default()))));
        let mut ap = Approvals::new();
        let (_, listed, acct) = crate::psbt::tests::ours(crate::btc::Family::Taproot);
        for intent in [tx_intent("0x1"), psbt_intent(&listed.id, &crate::psbt::tests::sample(&acct))] {
            let (h, r) = ap.request(&mut s, "x", &intent).unwrap();
            let v = ap.acknowledge(&mut s, &h).unwrap();
            assert!(ap.approve(&mut s, &h, &v.bundle_id, "", false).is_err());
            assert_eq!(ap.status(&mut s, &h, &r).unwrap().0, "rendered", "back on screen");
            assert!(ap.fetch_result(&mut s, &h, &r).is_err());
            assert!(ap.pending(&mut s).iter().any(|p| p.handle == h && p.error.is_some()), "the approver is told why");
            ap.cancel(&mut s, &h, &r).unwrap();
        }
    }

    /// A device the test can press, shared with the registry.
    #[derive(Clone)]
    struct Device(std::sync::Arc<std::sync::Mutex<MockSigner>>);

    impl Device {
        fn new() -> Self {
            Device(std::sync::Arc::new(std::sync::Mutex::new(MockSigner::new(MockOptions {
                needs_confirmation: true,
                ..Default::default()
            }))))
        }
        fn press(&self, job: &str, yes: bool) {
            let mut d = self.0.lock().unwrap();
            if yes { d.confirm(job).unwrap() } else { d.refuse(job).unwrap() }
        }
    }

    impl Signer for Device {
        fn info(&self) -> SignerInfo {
            self.0.lock().unwrap().info()
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<logos_signer_interface::Account>> {
            self.0.lock().unwrap().accounts()
        }
        fn sign(&mut self, request: SignRequest) -> logos_signer_interface::Result<String> {
            self.0.lock().unwrap().sign(request)
        }
        fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.0.lock().unwrap().status(job)
        }
        fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            self.0.lock().unwrap().result(job)
        }
        fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.0.lock().unwrap().cancel(job)
        }
    }

    #[test]
    fn a_device_signer_settles_when_the_person_confirms_on_it() {
        let device = Device::new();
        let mut s = Registry::new();
        s.add("device", Box::new(device.clone()));
        let mut ap = Approvals::new();
        let (h, r) = ap.request(&mut s, "x", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        assert_eq!(ap.approve(&mut s, &h, &v.bundle_id, "", false).unwrap(), Approved::Signing);
        assert_eq!(ap.status(&mut s, &h, &r).unwrap().0, "signing");
        assert!(ap.acknowledge(&mut s, &h).is_err(), "nothing else can be approved over it");
        let job = ap.find(&h).unwrap().job.clone().unwrap();
        // The person confirms on the device; the next look settles the record.
        assert!(ap.drain_moves().is_empty(), "approving moved nothing yet");
        device.press(&job, true);
        assert_eq!(ap.status(&mut s, &h, &r).unwrap(), ("settled", Some("approved")));
        assert_eq!(ap.drain_moves(), vec![Move::Settled(h.clone(), Outcome::Approved)], "to announce");
        assert!(ap.drain_moves().is_empty(), "announced once");
        assert_eq!(ap.fetch_result(&mut s, &h, &r).unwrap().len(), 1);
    }

    #[test]
    fn a_refusal_on_the_device_settles_as_rejected() {
        let device = Device::new();
        let mut s = Registry::new();
        s.add("device", Box::new(device.clone()));
        let mut ap = Approvals::new();
        let (h, r) = ap.request(&mut s, "x", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        ap.approve(&mut s, &h, &v.bundle_id, "", false).unwrap();
        let job = ap.find(&h).unwrap().job.clone().unwrap();
        device.press(&job, false);
        assert_eq!(ap.status(&mut s, &h, &r).unwrap(), ("settled", Some("rejected")));
        assert_eq!(ap.drain_moves(), vec![Move::Settled(h, Outcome::Rejected)]);
    }

    /// A device that signs something else, once the person confirms.
    struct LyingDevice(Device);

    impl Signer for LyingDevice {
        fn info(&self) -> SignerInfo {
            self.0.info()
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<logos_signer_interface::Account>> {
            self.0.accounts()
        }
        fn sign(&mut self, mut request: SignRequest) -> logos_signer_interface::Result<String> {
            if let Payload::Hash { items } = &mut request.payload {
                for item in items {
                    item.digest = "11".repeat(32);
                }
            }
            self.0.sign(request)
        }
        fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.0.status(job)
        }
        fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            self.0.result(job)
        }
        fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.0.cancel(job)
        }
    }

    #[test]
    fn a_device_that_signs_something_else_puts_the_request_back_and_says_so() {
        let device = Device::new();
        let mut s = Registry::new();
        s.add("device", Box::new(LyingDevice(device.clone())));
        let mut ap = Approvals::new();
        let (h, r) = ap.request(&mut s, "x", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        assert_eq!(ap.approve(&mut s, &h, &v.bundle_id, "", false).unwrap(), Approved::Signing);
        let job = ap.find(&h).unwrap().job.clone().unwrap();
        device.press(&job, true);
        assert_eq!(ap.status(&mut s, &h, &r).unwrap().0, "rendered", "back on screen");
        assert_eq!(ap.drain_moves(), vec![Move::Rendered(h.clone())], "to announce");
        assert!(ap.pending(&mut s).iter().any(|p| p.handle == h && p.error.is_some()), "saying why");
        assert!(ap.fetch_result(&mut s, &h, &r).is_err());
    }

    #[test]
    fn cancelling_stops_the_signer_too() {
        let mut s = Registry::new();
        s.add("device", Box::new(MockSigner::new(MockOptions { needs_confirmation: true, ..Default::default() })));
        let mut ap = Approvals::new();
        let (h, r) = ap.request(&mut s, "x", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        ap.approve(&mut s, &h, &v.bundle_id, "", false).unwrap();
        let job = ap.find(&h).unwrap().job.clone().unwrap();
        ap.cancel(&mut s, &h, &r).unwrap();
        assert_eq!(s.signer(0).status(&job).unwrap().state, JobState::Cancelled);
    }
}

#[cfg(test)]
mod unlock_tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Collects, ErrorCode};

    const ACCT0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn intent() -> String {
        format!(r#"{{"address":"{ACCT0}","legs":[{{"kind":"message","text":"inside an unlock"}}]}}"#)
    }

    /// A signer that asks for "pw" unless its account is unlocked, as the keystore does.
    fn unlocked_keystore() -> Registry {
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions { collects: Collects::Password, secret: "pw".into(), ..Default::default() })));
        r
    }

    #[test]
    fn without_a_password_only_a_covering_unlock_signs() {
        let mut s = unlocked_keystore();
        let mut ap = Approvals::new();
        let (h, _) = ap.request(&mut s, "wallet", &intent()).unwrap();
        let v = ap.acknowledge(&mut s, &h).unwrap();
        let e = ap.approve(&mut s, &h, &v.bundle_id, "", false).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::Locked));
        assert!(e.to_string().contains("is not unlocked for wallet"), "{e}");
        let (who, account) = ap.requester_and_account(&h).unwrap();
        assert_eq!(who, "wallet");
        assert!(account.eq_ignore_ascii_case(ACCT0), "{account}");
    }

    #[test]
    fn signing_unattended_happens_only_before_anything_is_shown() {
        let mut s = Registry::new();
        s.add("keystore_module", Box::new(MockSigner::new(MockOptions::default())));
        let mut ap = Approvals::new();
        let (h, r) = ap.request(&mut s, "game", &intent()).unwrap();
        assert_eq!(ap.sign_unattended(&mut s, &h).unwrap(), Approved::Settled(1));
        assert_eq!(ap.fetch_result(&mut s, &h, &r).unwrap().len(), 1);
        let (h2, _) = ap.request(&mut s, "game", &intent()).unwrap();
        ap.acknowledge(&mut s, &h2).unwrap();
        assert!(ap.sign_unattended(&mut s, &h2).is_err(), "a request on screen waits for the person");
    }
}
