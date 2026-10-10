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

use crate::access::{Access, Cover, Decision, KeyHolder, Terms, Unlocked};
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
    /// render_lines, signer, collects, unlocked }`. `collects` says what `approve` must carry,
    /// unless `unlocked`, when an unlock covers the request and no password is needed.
    fn acknowledge(&mut self, handle: String) -> String;
    /// The person said yes: `{ ok, signed_count }` once signed, or `{ ok, state: "signing" }` while a
    /// device works. A wrong password answers `{ ok: false, code: "wrong_secret" }` and the request
    /// stays on screen. `password` is the vault password or a card's PIN, or empty.
    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String;
    /// The person said no.
    fn reject(&mut self, handle: String) -> bool;

    // ── Opening and unlocking: asked by any named module, decided by the custodian ──
    /// Ask a person to open a Bitcoin wallet for the caller: `{ group, network? }` to reopen one, or
    /// `{ family, network }` to let the person pick, create or restore one, with optional `unlock`
    /// terms and a `reason` → `{ ok, handle, receipt, state }`. `fetch_result` then returns `{ group,
    /// family, chain, network, external, internal, fingerprint, databaseKey, unlocked }`. Tier B.
    fn request_open(&mut self, params_json: String) -> String;
    /// Ask for an account to stay unlocked: `{ account, ttlMs?, count?, apps?, confirm?, reason? }`
    /// → `{ ok, handle, receipt, state }`. The person decides the terms. Tier B.
    fn request_unlock(&mut self, params_json: String) -> String;
    /// The custodian's queue: `{ ok, requests: [{ handle, requester, kind, state, ageMs }] }`. Tier D.
    fn access_requests(&mut self) -> String;
    /// Claim one for display: `{ ok, handle, requester, kind, bundle_id, lines, asked }`. `asked` is
    /// `{ group, family, network, unlock }` for an open and `{ account, terms }` for an unlock. Tier D.
    fn acknowledge_access(&mut self, handle: String) -> String;
    /// The person decided: `{ handle, bundle_id, group?, password, unlock? }` → `{ ok }`, or
    /// `{ ok: false, code: "wrong_secret" }` with the request left on screen. Tier D.
    fn approve_access(&mut self, params_json: String) -> String;
    /// The person said no. Tier D.
    fn reject_access(&mut self, handle: String) -> bool;
    /// An open wallet's descriptors again: `{ ok, group, external, internal }`, only for a module
    /// the wallet is open for.
    fn account_descriptors(&mut self, group: String) -> String;
    /// Close a wallet: `{ group }` for the caller's own, or as the custodian `{ group, module }` →
    /// `{ ok, closed }`. An unlock scoped to that module alone ends with it.
    fn close_account(&mut self, params_json: String) -> String;
    /// Every open wallet and its module: `{ ok, open: [{ module, group }] }`. Tier D.
    fn open_accounts(&mut self) -> String;
    /// The person's own unlock, from the keys app: `{ account, password, ttlMs?, count?, apps,
    /// confirm? }` → `{ ok, account, expiresInMs, countLeft }`. Tier D.
    fn unlock(&mut self, params_json: String) -> String;
    /// `{ account? }`, every account for `{}` → `{ ok, locked }`. Tier D.
    fn lock(&mut self, params_json: String) -> String;
    /// `{ ok, unlocked: [{ account, expiresInMs, countLeft, apps, confirm }] }`. Approver and custodian.
    fn unlocked(&mut self) -> String;
    /// Requests signed without being shown: `{ ok, signed: [{ handle, requester, account, ageMs }] }`.
    /// Approver and custodian.
    fn unattended_signatures(&mut self) -> String;

    // ── Tier C: ungated reads ───────────────────────────────────────────
    /// Every signer's accounts, each under the first signer that offers it: `{ ok, accounts: [{
    /// id, family, chain?, address?, label?, signer, available }] }`. No xpub: it would show a
    /// Bitcoin wallet's whole history to anyone who asked.
    fn accounts(&mut self) -> String;
    /// The signer modules consulted, with what each says it is: `{ ok, signers: [{ name, info? }] }`.
    fn signers(&mut self) -> String;
    /// What this module sees as its caller, with the roles and signers in force:
    /// `{ ok, kind, identity, approvers, custodians, signers }`.
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
    /// An open or unlock request is waiting for the custodian.
    fn access_requested(&self, handle: String);
    /// An open or unlock request reached a terminal state.
    fn access_settled(&self, handle: String, state: String);
    /// An account was unlocked or locked.
    fn unlock_changed(&self, account: String);
    /// A request was signed without being shown, inside an unlock that allows it.
    fn signed_without_asking(&self, handle: String);
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

/// The keystore's extras beyond the signer interface: database keys and unlocks.
struct KeystoreKeys;

fn keystore_reply(reply: Result<String, logos_rust_sdk::LogosError>) -> crate::Result<serde_json::Value> {
    let reply = reply.map_err(|e| ManagerError::Signer(unavailable("keystore_module", e)))?;
    Ok(logos_signer_interface::wire::parse_reply(&reply)?)
}

impl KeyHolder for KeystoreKeys {
    fn database_key(&mut self, group: &str, password: Option<&str>) -> crate::Result<Zeroizing<String>> {
        let body = Zeroizing::new(json!({ "group": group, "password": password }).to_string());
        let v = keystore_reply(modules().keystore_module.database_key(&body))?;
        let key = v.get("databaseKey").and_then(|k| k.as_str()).unwrap_or_default();
        Ok(Zeroizing::new(key.to_string()))
    }

    fn unlock(&mut self, account: &str, password: &str, ttl_ms: Option<u64>, count: Option<u32>) -> crate::Result<Unlocked> {
        let body = Zeroizing::new(
            json!({ "account": account, "password": password, "ttlMs": ttl_ms, "count": count }).to_string(),
        );
        let v = keystore_reply(modules().keystore_module.unlock(&body))?;
        serde_json::from_value(v).map_err(|e| ManagerError::Signing(format!("keystore unlock reply: {e}")))
    }

    fn lock(&mut self, account: Option<&str>) -> crate::Result<usize> {
        let v = keystore_reply(modules().keystore_module.lock(&json!({ "account": account }).to_string()))?;
        Ok(v.get("locked").and_then(|n| n.as_u64()).unwrap_or(0) as usize)
    }

    fn unlocked(&mut self) -> crate::Result<Vec<Unlocked>> {
        let v = keystore_reply(modules().keystore_module.unlocked())?;
        serde_json::from_value(v.get("unlocked").cloned().unwrap_or_default())
            .map_err(|e| ManagerError::Signing(format!("keystore unlocked reply: {e}")))
    }
}

/// A request signed without being shown, for the keys app and the signer to list.
struct Unattended {
    handle: String,
    requester: String,
    account: String,
    at: std::time::Instant,
}

#[derive(Default)]
struct SignerManagerModuleImpl {
    approvals: Approvals,
    access: Access,
    unattended: Vec<Unattended>,
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

    fn is_custodian(&self) -> bool {
        gate::holds_any_role(&self.roles.custodians, &Self::caller())
    }

    /// Does an unlock cover this approval's requester for its account?
    fn cover(&mut self, handle: &str) -> Cover {
        let Some((requester, account)) = self.approvals.requester_and_account(handle) else { return Cover::No };
        if self.access.covers(&account, &requester) == Cover::No {
            return Cover::No;
        }
        // The keystore keeps the time and the count: one it has dropped covers nothing here either.
        let _ = self.access.unlocked(&mut KeystoreKeys);
        self.access.covers(&account, &requester)
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
        // The terms of any unlock were kept here and are gone: nothing stays unlocked past a restart.
        let _ = KeystoreKeys.lock(None);
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
        let (handle, receipt) = match self.approvals.request(&mut self.signers, &requester, &intent_json) {
            Ok(hr) => hr,
            Err(e) => return manager_err(&e),
        };
        // Inside an unlock the person granted without confirmation, it is signed as it arrives.
        if self.cover(&handle) == Cover::WithoutAsking {
            match self.approvals.sign_unattended(&mut self.signers, &handle) {
                Ok(Approved::Settled(_)) => {
                    let account = self.approvals.requester_and_account(&handle).map(|(_, a)| a).unwrap_or_default();
                    self.unattended.push(Unattended { handle: handle.clone(), requester, account, at: std::time::Instant::now() });
                    emit_signed_without_asking(&handle);
                    emit_approval_settled(&handle, "approved");
                    return json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "settled" }).to_string();
                }
                Ok(Approved::Signing) => {}
                Err(e) if e.code() == Some(ErrorCode::Locked) => {
                    if let Some((_, account)) = self.approvals.requester_and_account(&handle) {
                        self.access.expired(&account);
                    }
                }
                Err(_) => {}
            }
        }
        emit_approval_offered(&handle);
        json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
    }

    fn approval_status(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        self.refresh();
        if self.access.owns(&handle) {
            return match self.access.status(&handle, &receipt) {
                Ok((state, reason)) => json!({ "ok": true, "state": state, "reason": reason }).to_string(),
                Err(_) => not_authorized(),
            };
        }
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
        if self.access.owns(&handle) {
            return match self.access.fetch(&handle, &receipt) {
                Ok(v) => json!({ "ok": true, "result": v }).to_string(),
                Err(ManagerError::NotFound(_)) => not_authorized(),
                Err(e) => err(e),
            };
        }
        match self.approvals.fetch_result(&mut self.signers, &handle, &receipt) {
            Ok(signed) => json!({ "ok": true, "signed": signed }).to_string(),
            Err(ManagerError::NotFound(_)) => not_authorized(),
            Err(e) => err(e),
        }
    }

    fn ack_result(&mut self, handle: String, receipt: String) -> bool {
        if self.named_caller().is_none() {
            return false;
        }
        if self.access.owns(&handle) {
            return self.access.ack(&handle, &receipt).is_ok();
        }
        self.approvals.ack_result(&handle, &receipt).is_ok()
    }

    fn cancel_approval(&mut self, handle: String, receipt: String) -> bool {
        if self.named_caller().is_none() {
            return false;
        }
        self.refresh();
        if self.access.owns(&handle) {
            let ok = self.access.cancel(&handle, &receipt).is_ok();
            if ok {
                emit_access_settled(&handle, "cancelled");
            }
            return ok;
        }
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
            // `unlocked`: an unlock covers this request, so `approve` needs no password.
            Ok(v) => json!({ "ok": true, "handle": v.handle, "bundle_id": v.bundle_id, "requester": v.requester,
                             "claim_lines": v.claim_lines, "render_lines": v.render_lines,
                             "signer": v.signer, "collects": v.collects, "unlocked": self.cover(&handle) != Cover::No })
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
        let cover = self.cover(&handle);
        let unlocked = cover != Cover::No;
        match self.approvals.approve(&mut self.signers, &handle, &bundle_id, &password, unlocked) {
            Ok(Approved::Settled(n)) => {
                emit_approval_settled(&handle, "approved");
                json!({ "ok": true, "signed_count": n }).to_string()
            }
            Ok(Approved::Signing) => {
                emit_approval_progress(&handle, "signing");
                json!({ "ok": true, "state": "signing" }).to_string()
            }
            Err(e) => {
                // Unlocked here but locked at the keystore: its time or count ran out.
                if unlocked && password.is_empty() && e.code() == Some(ErrorCode::Locked) {
                    if let Some((_, account)) = self.approvals.requester_and_account(&handle) {
                        self.access.expired(&account);
                    }
                }
                manager_err(&e)
            }
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

    fn request_open(&mut self, params_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.access.request_open(&mut self.signers, &requester, &params_json) {
            Ok((handle, receipt)) => {
                emit_access_requested(&handle);
                json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn request_unlock(&mut self, params_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.access.request_unlock(&mut self.signers, &requester, &params_json) {
            Ok((handle, receipt)) => {
                emit_access_requested(&handle);
                json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn access_requests(&mut self) -> String {
        if !self.is_custodian() {
            return not_authorized();
        }
        let list: Vec<_> = self
            .access
            .queue()
            .into_iter()
            .map(|q| json!({ "handle": q.handle, "requester": q.requester, "kind": q.kind, "state": q.state,
                             "ageMs": q.age_ms as u64 }))
            .collect();
        json!({ "ok": true, "requests": list }).to_string()
    }

    fn acknowledge_access(&mut self, handle: String) -> String {
        if !self.is_custodian() {
            return not_authorized();
        }
        match self.access.acknowledge(&handle) {
            Ok(v) => json!({ "ok": true, "handle": v.handle, "requester": v.requester, "kind": v.kind,
                             "bundle_id": v.bundle_id, "lines": v.lines, "asked": v.asked })
            .to_string(),
            Err(e) => err(e),
        }
    }

    fn approve_access(&mut self, params_json: String) -> String {
        let params_json = Zeroizing::new(params_json);
        if !self.is_custodian() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            handle: String,
            bundle_id: String,
            #[serde(default)]
            group: Option<String>,
            password: String,
            #[serde(default)]
            unlock: Option<Terms>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("approve_access: {e}")),
        };
        let decision = Decision { group: w.group, password: w.password, unlock: w.unlock };
        self.refresh();
        match self.access.approve(&mut self.signers, &mut KeystoreKeys, &w.handle, &w.bundle_id, decision) {
            Ok(()) => {
                emit_access_settled(&w.handle, "approved");
                json!({ "ok": true }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn reject_access(&mut self, handle: String) -> bool {
        if !self.is_custodian() {
            return false;
        }
        let ok = self.access.reject(&handle).is_ok();
        if ok {
            emit_access_settled(&handle, "rejected");
        }
        ok
    }

    fn account_descriptors(&mut self, group: String) -> String {
        let Some(module) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.access.descriptors(&mut self.signers, &module, &group) {
            Ok((external, internal)) => json!({ "ok": true, "group": group, "external": external, "internal": internal }).to_string(),
            Err(_) => not_authorized(),
        }
    }

    fn close_account(&mut self, params_json: String) -> String {
        #[derive(serde::Deserialize)]
        struct Wire {
            group: String,
            #[serde(default)]
            module: Option<String>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("close_account: {e}")),
        };
        let module = match (&w.module, self.named_caller()) {
            (Some(m), _) if self.is_custodian() => m.clone(),
            (None, Some(me)) => me,
            _ => return not_authorized(),
        };
        match self.access.close(&mut KeystoreKeys, &module, &w.group) {
            Ok(closed) => json!({ "ok": true, "closed": closed }).to_string(),
            Err(e) => manager_err(&e),
        }
    }

    fn open_accounts(&mut self) -> String {
        if !self.is_custodian() {
            return not_authorized();
        }
        let list: Vec<_> =
            self.access.open_accounts().into_iter().map(|(m, g)| json!({ "module": m, "group": g })).collect();
        json!({ "ok": true, "open": list }).to_string()
    }

    fn unlock(&mut self, params_json: String) -> String {
        let params_json = Zeroizing::new(params_json);
        if !self.is_custodian() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            account: String,
            password: String,
            #[serde(default)]
            ttl_ms: Option<u64>,
            #[serde(default)]
            count: Option<u32>,
            #[serde(default)]
            apps: Vec<String>,
            #[serde(default = "confirm_by_default")]
            confirm: bool,
        }
        fn confirm_by_default() -> bool {
            true
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("unlock: {e}")),
        };
        let password = Zeroizing::new(w.password);
        let terms = Terms { ttl_ms: w.ttl_ms, count: w.count, apps: w.apps, confirm: w.confirm };
        self.refresh();
        match self.access.unlock(&mut self.signers, &mut KeystoreKeys, &w.account, &password, &terms) {
            Ok(u) => {
                emit_unlock_changed(&u.account);
                json!({ "ok": true, "account": u.account, "expiresInMs": u.expires_in_ms, "countLeft": u.count_left })
                    .to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn lock(&mut self, params_json: String) -> String {
        if !self.is_custodian() {
            return not_authorized();
        }
        let account: Option<String> = serde_json::from_str::<serde_json::Value>(&params_json)
            .ok()
            .and_then(|v| v.get("account").and_then(|a| a.as_str()).map(str::to_string));
        match self.access.lock(&mut KeystoreKeys, account.as_deref()) {
            Ok(n) => {
                emit_unlock_changed(account.as_deref().unwrap_or("*"));
                json!({ "ok": true, "locked": n }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn unlocked(&mut self) -> String {
        if !self.is_custodian() && !self.is_approver() {
            return not_authorized();
        }
        match self.access.unlocked(&mut KeystoreKeys) {
            Ok(list) => {
                let list: Vec<_> = list
                    .into_iter()
                    .map(|(u, apps, confirm)| {
                        json!({ "account": u.account, "expiresInMs": u.expires_in_ms, "countLeft": u.count_left,
                                "apps": apps, "confirm": confirm })
                    })
                    .collect();
                json!({ "ok": true, "unlocked": list }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn unattended_signatures(&mut self) -> String {
        if !self.is_custodian() && !self.is_approver() {
            return not_authorized();
        }
        let now = std::time::Instant::now();
        let list: Vec<_> = self
            .unattended
            .iter()
            .map(|u| json!({ "handle": u.handle, "requester": u.requester, "account": u.account,
                             "ageMs": now.duration_since(u.at).as_millis() as u64 }))
            .collect();
        json!({ "ok": true, "signed": list }).to_string()
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
        // The whole configuration, so an approver can build a `configure` that keeps it: it is total.
        json!({ "ok": true, "kind": kind, "identity": name, "approvers": self.roles.approvers,
                "custodians": self.roles.custodians, "signers": self.roles.signers })
        .to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<SignerManagerModuleImpl>();
}
