//! Logos module glue for `signer_manager_module`. The builder derives the `.lidl` from the
//! `SignerManagerModule` trait and injects the generated scaffold at the `include!` point.
//!
//! Every structured value crosses IPC as a JSON string: `{ "ok": true, ... }` or
//! `{ "ok": false, "error": "...", "code"? }`. The approval API keeps keystore_module's names and
//! shapes, so a requester or an approver changes only the module it calls.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use zeroize::Zeroizing;

use logos_signer_interface::{json as signer_json, Account, ErrorCode, JobStatus, SignRequest, Signature, Signer, SignerError, SignerInfo};

use crate::approval::{Approvals, Approved};
use crate::gate;
use crate::registry::Registry;
use crate::ManagerError;

/// The signer manager's IPC contract.
pub trait SignerManagerModule: Send + 'static {
    /// Name the roles and the signer modules consulted: `{ approvers?, custodians?, signers? }` →
    /// `{ ok, approvers, custodians, signers }`. TOTAL — what the document doesn't name is held by
    /// nobody — and effective at once. UNGATED for now, as keystore_module's: see docs/specs.md.
    fn configure(&mut self, config_json: String) -> String;

    // ── Tier B: any NAMED module may ask ────────────────────────────────
    /// Ask a person to approve signing; returns at once with `{ ok, handle, receipt, state }`.
    /// The handle is announced on the event plane; the receipt, returned once, authorises collecting.
    fn request_approval(&mut self, intent_json: String) -> String;
    /// `{ ok, state, reason? }`: offered, rendered, signing or settled. Never the intent or results.
    fn approval_status(&mut self, handle: String, receipt: String) -> String;
    /// `{ ok, signed: [...] }`, idempotent until `ack_result`.
    fn fetch_result(&mut self, handle: String, receipt: String) -> String;
    /// The requester has the results; erase them.
    fn ack_result(&mut self, handle: String, receipt: String) -> bool;
    /// The requester gave up; a signer still working is told to stop.
    fn cancel_approval(&mut self, handle: String, receipt: String) -> bool;

    // ── Tier A: the configured approver only ────────────────────────────
    /// Queue summaries, never leg detail: `{ ok, pending: [{ handle, requester, state, purpose,
    /// legs, ageMs, error? }] }`.
    fn pending(&mut self) -> String;
    /// Claim a request for display: `{ ok, handle, bundle_id, requester, claim_lines,
    /// render_lines, signer, collects }`. `collects` says what `approve` must carry.
    fn acknowledge(&mut self, handle: String) -> String;
    /// The person said yes: `{ ok, signed }` once signed, or `{ ok, state: "signing" }` while a
    /// device works. A wrong password answers `{ ok: false, code: "wrong_secret" }` and the request
    /// stays on screen. `password` is the vault password or a card's PIN, or empty.
    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String;
    /// The person said no.
    fn reject(&mut self, handle: String) -> bool;

    // ── Tier C: ungated reads ───────────────────────────────────────────
    /// Every signer's accounts, each under the first signer that offers it: `{ ok, accounts: [{
    /// id, family, chain?, address?, label?, signer, available }] }`. No xpub: it would show a
    /// Bitcoin wallet's whole history to anyone who asked.
    fn accounts(&mut self) -> String;
    /// The signer modules consulted, with what each says it is: `{ ok, signers: [{ name, info? }] }`.
    fn signers(&mut self) -> String;
    /// What this module sees as its caller.
    fn caller_identity(&mut self) -> String;
    /// Framework hook — defaulted, so not part of the IPC contract.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

/// Typed events. Payloads carry handles only: the event plane is unauthenticated.
pub trait SignerManagerModuleEvents {
    /// A new request is waiting.
    fn approval_offered(&self, handle: String);
    /// A request reached a terminal state.
    fn approval_settled(&self, handle: String, state: String);
    /// A request moved without settling, such as to `signing`.
    fn approval_progress(&self, handle: String, state: String);
    /// A signer's accounts changed; re-read `accounts`. `count` is advisory.
    fn accounts_changed(&self, count: i64);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

/// How long the manager waits on a signer module before calling it unavailable.
const SIGNER_TIMEOUT: Duration = Duration::from_secs(20);
const INFO_TIMEOUT: Duration = Duration::from_secs(3);

/// A signer module over IPC, through the `signer` interface bound to its name.
struct IpcSigner {
    name: String,
}

fn unavailable(name: &str, e: impl std::fmt::Display) -> SignerError {
    SignerError::new(ErrorCode::Unavailable, format!("{name}: {e}"))
}

impl Signer for IpcSigner {
    fn info(&self) -> SignerInfo {
        signer::SignerClient::bind(&self.name)
            .signer_info_with_timeout(INFO_TIMEOUT)
            .ok()
            .and_then(|reply| signer_json::read_info(&reply).ok())
            .unwrap_or(SignerInfo {
                interface: String::new(),
                kind: String::new(),
                model: String::new(),
                families: Vec::new(),
                request_kinds: Vec::new(),
                shows_request: false,
                collects: logos_signer_interface::Collects::Nothing,
            })
    }

    fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
        let reply = signer::SignerClient::bind(&self.name)
            .signer_accounts_with_timeout(SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_accounts(&reply)
    }

    fn sign(&mut self, request: SignRequest) -> logos_signer_interface::Result<String> {
        let body = Zeroizing::new(serde_json::to_string(&request).map_err(|e| unavailable(&self.name, e))?);
        drop(request);
        let reply = signer::SignerClient::bind(&self.name)
            .sign_with_timeout(&body, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_job(&reply)
    }

    fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        let reply = signer::SignerClient::bind(&self.name)
            .sign_status_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_status(&reply)
    }

    fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
        let reply = signer::SignerClient::bind(&self.name)
            .sign_result_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_signatures(&reply)
    }

    fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        let reply = signer::SignerClient::bind(&self.name)
            .cancel_sign_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_job(&reply).map(drop)
    }
}

#[derive(Default)]
struct SignerManagerModuleImpl {
    approvals: Approvals,
    roles: gate::Roles,
    signers: Registry,
    /// Set by a listener when any signer's accounts change.
    stale: Arc<AtomicBool>,
    started: bool,
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

/// A refusal carries the signer's code, so the approver can tell "try the password again".
fn manager_err(e: &ManagerError) -> String {
    match e.code() {
        Some(code) => json!({ "ok": false, "code": code, "error": e.to_string() }).to_string(),
        None => err(e),
    }
}

/// Identical whether the handle is unknown or not yours: no oracle for "does this exist?".
fn not_authorized() -> String {
    json!({ "ok": false, "error": "not authorized" }).to_string()
}

impl SignerManagerModuleImpl {
    fn caller() -> gate::Caller {
        match logos_rust_sdk::current_caller() {
            logos_rust_sdk::LogosCaller::Unknown => gate::Caller::Unknown,
            logos_rust_sdk::LogosCaller::HostAnchor => gate::Caller::HostAnchor,
            logos_rust_sdk::LogosCaller::Module { name, .. } => gate::Caller::Module(name),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => gate::Caller::Derived { parent, leaf },
            logos_rust_sdk::LogosCaller::Operator { name } => gate::Caller::Operator(name),
        }
    }

    fn is_approver(&self) -> bool {
        gate::holds_any_role(&self.roles.approvers, &Self::caller())
    }

    fn named_caller(&self) -> Option<String> {
        Self::caller().named().map(str::to_string)
    }

    /// The configured signer modules, bound by name, each listened to for account changes.
    fn bind_signers(&mut self) {
        let mut r = Registry::new();
        for name in &self.roles.signers {
            r.add(name.clone(), Box::new(IpcSigner { name: name.clone() }));
            let stale = self.stale.clone();
            if let Ok(sub) = signer::SignerClient::bind(name).on_signer_accounts_changed() {
                std::thread::spawn(move || {
                    for _ in sub {
                        stale.store(true, Ordering::SeqCst);
                    }
                });
            }
        }
        self.signers = r;
        self.started = true;
    }

    /// Before each call: bind the signers once, and re-read their accounts after a change.
    fn refresh(&mut self) {
        if !self.started {
            self.bind_signers();
        }
        if self.stale.swap(false, Ordering::SeqCst) {
            self.signers.forget();
            emit_accounts_changed(self.signers.accounts().len() as i64);
        }
    }
}

impl SignerManagerModule for SignerManagerModuleImpl {
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {
        self.bind_signers();
    }

    fn configure(&mut self, config_json: String) -> String {
        match self.roles.configure(&config_json) {
            Ok(()) => {
                self.bind_signers();
                json!({ "ok": true, "approvers": self.roles.approvers, "custodians": self.roles.custodians,
                        "signers": self.roles.signers })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn request_approval(&mut self, intent_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.approvals.request(&mut self.signers, &requester, &intent_json) {
            Ok((handle, receipt)) => {
                emit_approval_offered(&handle);
                json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn approval_status(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        self.refresh();
        match self.approvals.status(&mut self.signers, &handle, &receipt) {
            Ok((state, reason)) => json!({ "ok": true, "state": state, "reason": reason }).to_string(),
            Err(_) => not_authorized(),
        }
    }

    fn fetch_result(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        self.refresh();
        match self.approvals.fetch_result(&mut self.signers, &handle, &receipt) {
            Ok(signed) => json!({ "ok": true, "signed": signed }).to_string(),
            Err(ManagerError::NotFound(_)) => not_authorized(),
            Err(e) => err(e),
        }
    }

    fn ack_result(&mut self, handle: String, receipt: String) -> bool {
        self.named_caller().is_some() && self.approvals.ack_result(&handle, &receipt).is_ok()
    }

    fn cancel_approval(&mut self, handle: String, receipt: String) -> bool {
        if self.named_caller().is_none() {
            return false;
        }
        self.refresh();
        let ok = self.approvals.cancel(&mut self.signers, &handle, &receipt).is_ok();
        if ok {
            emit_approval_settled(&handle, "cancelled");
        }
        ok
    }

    fn pending(&mut self) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        let list: Vec<_> = self
            .approvals
            .pending(&mut self.signers)
            .into_iter()
            .map(|p| {
                json!({ "handle": p.handle, "requester": p.requester, "state": p.state, "purpose": p.purpose,
                        "legs": p.leg_count, "ageMs": p.age_ms as u64, "error": p.error })
            })
            .collect();
        json!({ "ok": true, "pending": list }).to_string()
    }

    fn acknowledge(&mut self, handle: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        match self.approvals.acknowledge(&mut self.signers, &handle) {
            Ok(v) => json!({ "ok": true, "handle": v.handle, "bundle_id": v.bundle_id, "requester": v.requester,
                             "claim_lines": v.claim_lines, "render_lines": v.render_lines,
                             "signer": v.signer, "collects": v.collects })
            .to_string(),
            Err(e) => err(e),
        }
    }

    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String {
        let password = Zeroizing::new(password);
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        match self.approvals.approve(&mut self.signers, &handle, &bundle_id, &password) {
            Ok(Approved::Settled(n)) => {
                emit_approval_settled(&handle, "approved");
                json!({ "ok": true, "signed": n }).to_string()
            }
            Ok(Approved::Signing) => {
                emit_approval_progress(&handle, "signing");
                json!({ "ok": true, "state": "signing" }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn reject(&mut self, handle: String) -> bool {
        if !self.is_approver() {
            return false;
        }
        self.refresh();
        let ok = self.approvals.reject(&mut self.signers, &handle).is_ok();
        if ok {
            emit_approval_settled(&handle, "rejected");
        }
        ok
    }

    fn accounts(&mut self) -> String {
        self.refresh();
        let list: Vec<_> = self
            .signers
            .accounts()
            .into_iter()
            .map(|(signer, a)| {
                json!({ "id": a.id, "family": a.family, "chain": a.chain, "address": a.address, "label": a.label,
                        "signer": signer, "available": a.available })
            })
            .collect();
        json!({ "ok": true, "accounts": list }).to_string()
    }

    fn signers(&mut self) -> String {
        self.refresh();
        let list: Vec<_> =
            self.signers.infos().into_iter().map(|(name, info)| json!({ "name": name, "info": info })).collect();
        json!({ "ok": true, "signers": list }).to_string()
    }

    fn caller_identity(&mut self) -> String {
        let c = logos_rust_sdk::current_caller();
        let (kind, name) = match &c {
            logos_rust_sdk::LogosCaller::Unknown => ("unknown", String::new()),
            logos_rust_sdk::LogosCaller::HostAnchor => ("host", String::new()),
            logos_rust_sdk::LogosCaller::Module { name, .. } => ("module", name.clone()),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => ("derived", format!("{parent}.{leaf}")),
            logos_rust_sdk::LogosCaller::Operator { name } => ("operator", name.clone()),
        };
        json!({ "ok": true, "kind": kind, "identity": name,
                "approvers": self.roles.approvers, "custodians": self.roles.custodians })
        .to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<SignerManagerModuleImpl>();
}
