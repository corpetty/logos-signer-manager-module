//! Opening and unlocking accounts: requests a person decides in the keys app (the custodian), the
//! grants they leave, and the scope of each unlock.
//!
//! An open request connects one Bitcoin wallet to one module for this session: once a person
//! approves it, the module collects the wallet's descriptors and its database key with its receipt,
//! and may read the descriptors again until it closes the wallet. An unlock request asks for an
//! account's key to stay unlocked on terms; the person decides the terms. The keystore holds the key
//! and enforces the time and the count; this module enforces which apps an unlock covers and
//! whether each signature is still confirmed. Nothing here is written down.

use std::time::{Duration, Instant};

use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use logos_signer_interface::{walletkey, Account, Family, JobState, Secret, WalletKey, WalletKeyRequest};

use crate::btc::AccountPublic;
use crate::error::{bad, ManagerError, Result};
use crate::evm::check_displayable;
use crate::registry::{Found, Registry};

pub const MAX_PENDING_PER_REQUESTER: usize = 2;
pub const SETTLED_RETENTION: Duration = Duration::from_secs(120);
pub const ABANDONED_OFFER_TTL: Duration = Duration::from_secs(300);

/// What the keystore hands over when a wallet opens: its database key, and where its history can start.
pub struct OpenedWallet {
    pub database_key: Zeroizing<String>,
    /// `created` or `restored`.
    pub origin: String,
    /// The wallet's first possible day, `YYYY-MM-DD`, when known.
    pub birthday: Option<String>,
}

// The signer whose Bitcoin wallets keep their database key in their own vault; any other is a device.
use crate::roster::KEYSTORE;

/// What the keystore does for an open or an unlock, beyond the signer interface.
pub trait KeyHolder {
    fn database_key(&mut self, group: &str, password: Option<&str>) -> Result<OpenedWallet>;
    /// A device account's database key, made at its first open under the password the person set.
    fn device_database_key(&mut self, signer: &str, account: &str, password: &str, birthday: Option<&str>)
        -> Result<OpenedWallet>;
    /// The device wallets that have a database key, as `(signer, account)`.
    fn device_wallets(&mut self) -> Result<Vec<(String, String)>>;
    fn unlock(&mut self, account: &str, password: &str, ttl_ms: Option<u64>, count: Option<u32>) -> Result<Unlocked>;
    fn lock(&mut self, account: Option<&str>) -> Result<usize>;
    fn unlocked(&mut self) -> Result<Vec<Unlocked>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unlocked {
    pub account: String,
    #[serde(default)]
    pub expires_in_ms: Option<u64>,
    #[serde(default)]
    pub count_left: Option<u32>,
}

/// An unlock's terms. `apps` empty means the module that asked; `confirm` false means its requests
/// are signed without being shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Terms {
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub apps: Vec<String>,
    /// Each signature is still confirmed in the signer. True unless the person chooses otherwise.
    #[serde(default = "yes")]
    pub confirm: bool,
}

fn yes() -> bool {
    true
}

impl Terms {
    fn describe(&self, requester: &str) -> String {
        let time = self.ttl_ms.map_or("until locked".to_string(), |ms| format!("for {}", duration(ms)));
        let count = self.count.map_or(String::new(), |n| format!(", up to {n} signature request(s)"));
        let apps = if self.apps.is_empty() { requester.to_string() } else { self.apps.join(", ") };
        let how = if self.confirm { "each one confirmed in the signer" } else { "WITHOUT showing them to you" };
        format!("{time}{count}, for {apps}, {how}")
    }

    /// "Any app" is offered only with confirmation: without it every module could sign.
    fn check(&self) -> Result<()> {
        if !self.confirm && self.apps.iter().any(|a| a == "*") {
            return Err(bad("unlock: signing without asking must name the apps it covers"));
        }
        for a in &self.apps {
            check_displayable(a, "app")?;
        }
        if self.count == Some(0) || self.ttl_ms == Some(0) {
            return Err(bad("unlock: terms that allow nothing"));
        }
        Ok(())
    }
}

fn duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=119 => format!("{s} seconds"),
        120..=7199 => format!("{} minutes", s / 60),
        _ => format!("{} hours", s / 3600),
    }
}

/// How an unlock covers a request from one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    No,
    /// Approved with a confirmation, no password.
    Confirmed,
    /// Signed as it arrives, unseen.
    WithoutAsking,
}

/// What the manager keeps of an unlock: whose it is and which apps it covers. The key and the time
/// and count are the keystore's.
#[derive(Debug, Clone)]
struct Scope {
    account: String,
    apps: Vec<String>,
    confirm: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenParams {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub family: Option<Family>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub unlock: Option<Terms>,
    #[serde(default)]
    pub reason: String,
}

/// `{ account, ttlMs?, count?, apps?, confirm?, reason? }`: an account and the terms asked for.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockParams {
    pub account: String,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default = "yes")]
    pub confirm: bool,
    #[serde(default)]
    pub reason: String,
}

impl UnlockParams {
    pub fn terms(&self) -> Terms {
        Terms { ttl_ms: self.ttl_ms, count: self.count, apps: self.apps.clone(), confirm: self.confirm }
    }
}

#[derive(Debug)]
enum Kind {
    Open(OpenParams),
    Unlock(UnlockParams),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Offered,
    Rendered,
    /// Approved, and the chosen holder is working out the account's open key.
    Opening,
    Settled(&'static str),
}

/// An open whose holder is working: a card waiting for its PIN session, a Shell for its button, a
/// QR wallet for its answer.
struct Opening {
    found: Found,
    group: String,
    network: Option<String>,
    job: String,
    /// The job's last state, for the app to show: `working` or `confirm_on_device`.
    step: &'static str,
    /// The keystore's password, kept for the unlock asked with the open; wiped with the record.
    password: Zeroizing<String>,
    terms: Option<Terms>,
}

struct Record {
    handle: String,
    receipt_hash: [u8; 32],
    requester: String,
    kind: Kind,
    bundle_id: [u8; 32],
    lines: Vec<String>,
    state: State,
    offered_at: Instant,
    settled_at: Option<Instant>,
    result: Option<serde_json::Value>,
    /// The app showing it: an open is one holder app's once it claims it.
    opener: Option<String>,
    opening: Option<Opening>,
    /// Why the last approval didn't open it, as `(code, message)`, for the app to show.
    last_error: Option<(Option<String>, String)>,
}

/// What the person decided: the wallet picked, the holder that opens it and its secret, and the
/// terms granted.
#[derive(Debug)]
pub struct Decision {
    pub group: Option<String>,
    pub password: String,
    pub unlock: Option<Terms>,
    /// A device wallet's first day of use, given at its first open (the old device vault's path).
    pub birthday: Option<String>,
    /// The holder whose `wallet_key` opens it. None: the keystore's own path, as before.
    pub signer: Option<String>,
}

/// Who may show and decide a request: the custodian, and the apps that open a holder's accounts.
pub struct Gate<'a> {
    pub caller: &'a str,
    pub custodian: bool,
    pub opens: &'a dyn Fn(&str) -> bool,
}

pub struct Shown {
    pub handle: String,
    pub requester: String,
    pub kind: &'static str,
    pub bundle_id: String,
    pub lines: Vec<String>,
    /// What was asked, for the app to offer: the wallet or the family and network to pick from,
    /// and the terms an app wants. Never the reason, which is in `lines` as a claim.
    pub asked: serde_json::Value,
    /// The wallet's holders this app may open it with, ranked.
    pub holders: Vec<serde_json::Value>,
}

/// What `approve` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Approved {
    Settled,
    /// The holder is working; `progress` settles it.
    Opening,
}

/// What a holder's answer moved, for the glue to announce.
#[derive(Debug, PartialEq, Eq)]
pub enum Move {
    Settled(String, &'static str),
    /// Back on screen, saying why.
    Rendered(String),
}

pub struct Summary {
    pub handle: String,
    pub requester: String,
    pub kind: &'static str,
    pub state: &'static str,
    pub age_ms: u128,
}

#[derive(Default)]
pub struct Access {
    records: Vec<Record>,
    /// (module, group): a wallet open for a module.
    grants: Vec<(String, String)>,
    scopes: Vec<Scope>,
    seq: u64,
    moves: Vec<Move>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn token(seq: u64) -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{}{:x}", hex::encode(b), seq)
}

fn lower(id: &str) -> String {
    id.trim().to_ascii_lowercase()
}

impl Access {
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        for r in &mut self.records {
            if r.state == State::Offered && now.duration_since(r.offered_at) > ABANDONED_OFFER_TTL {
                r.state = State::Settled("expired_no_ack");
            }
            if matches!(r.state, State::Settled(_)) && r.settled_at.is_none() {
                r.settled_at = Some(now);
            }
        }
        self.records.retain(|r| {
            let Some(at) = r.settled_at else { return true };
            r.result.is_some() || now.duration_since(at) < SETTLED_RETENTION
        });
    }

    pub fn owns(&self, handle: &str) -> bool {
        self.records.iter().any(|r| r.handle == handle)
    }

    fn by_receipt(&mut self, handle: &str, receipt: &str) -> Result<&mut Record> {
        let want = sha256(receipt.as_bytes());
        self.records
            .iter_mut()
            .find(|r| r.handle == handle && r.receipt_hash == want)
            .ok_or_else(|| ManagerError::NotFound(handle.to_string()))
    }

    fn admit(&mut self, requester: &str) -> Result<()> {
        self.sweep();
        let live = self.records.iter().filter(|r| !matches!(r.state, State::Settled(_)) && r.requester == requester).count();
        if live >= MAX_PENDING_PER_REQUESTER {
            return Err(bad("too many pending open or unlock requests for this requester"));
        }
        Ok(())
    }

    fn push(&mut self, requester: &str, kind: Kind, lines: Vec<String>) -> (String, String) {
        self.seq += 1;
        let handle = format!("sma_{}", token(self.seq));
        let receipt = format!("smr_{}", token(self.seq));
        let mut h = Sha256::new();
        h.update(b"logos-signer-manager-access-v1\n");
        h.update(requester.as_bytes());
        for l in &lines {
            h.update(b"\n");
            h.update(l.as_bytes());
        }
        self.records.push(Record {
            handle: handle.clone(),
            receipt_hash: sha256(receipt.as_bytes()),
            requester: requester.to_string(),
            kind,
            bundle_id: h.finalize().into(),
            lines,
            state: State::Offered,
            offered_at: Instant::now(),
            settled_at: None,
            result: None,
            opener: None,
            opening: None,
            last_error: None,
        });
        (handle, receipt)
    }

    /// May this caller show and decide the record? The custodian always; another app only for an
    /// open naming a wallet one of whose holders it opens, and once it claims it, only that app.
    fn may(&self, signers: &mut Registry, r: &Record, gate: &Gate) -> Result<bool> {
        if r.opener.as_deref().is_some_and(|o| o != gate.caller) {
            return Ok(false);
        }
        if gate.custodian {
            return Ok(true);
        }
        let Kind::Open(OpenParams { group: Some(group), .. }) = &r.kind else { return Ok(false) };
        Ok(signers.holders(group)?.iter().any(|f| (gate.opens)(&f.name)))
    }

    /// A module asks for a Bitcoin wallet: one it names, or any of a family and network the person
    /// picks, creates or restores in the keys app.
    pub fn request_open(&mut self, signers: &mut Registry, requester: &str, params_json: &str) -> Result<(String, String)> {
        self.admit(requester)?;
        let p: OpenParams = serde_json::from_str(params_json).map_err(|e| bad(format!("open: {e}")))?;
        check_displayable(&p.reason, "reason")?;
        if let Some(t) = &p.unlock {
            t.check()?;
        }
        let mut lines = vec![format!("{requester} asks to open a Bitcoin wallet")];
        match (&p.group, &p.family, &p.network) {
            (Some(g), None, n) => {
                let found = signers.find(g)?;
                let (family, chain) = AccountPublic::kind_of(&found.account)?;
                let name = found.account.label.clone().unwrap_or_else(|| found.account.id.clone());
                let on = match n {
                    Some(n) => {
                        check_displayable(n, "network")?;
                        chain.network(n)?;
                        format!(" on {n}")
                    }
                    None => String::new(),
                };
                lines.push(format!("Wallet: {name} ({}, {} chain){on}", family.describe(), chain.as_str()));
            }
            (None, Some(f), Some(n)) if f.is_bitcoin() => {
                let family = if *f == Family::Bitcoin { "native segwit" } else { "taproot" };
                check_displayable(n, "network")?;
                lines.push(format!("Any {family} wallet on {n}: pick one, create one or restore one"));
            }
            _ => return Err(bad("open: name a Bitcoin group, or a Bitcoin family and a network")),
        }
        lines.push("It will see every address and transaction of that wallet, and can ask you to sign.".into());
        if let Some(t) = &p.unlock {
            lines.push(format!("It also asks to unlock it: {}", t.describe(requester)));
        }
        if !p.reason.trim().is_empty() {
            lines.push(format!("Reason (claimed by the requester): {}", p.reason.trim()));
        }
        Ok(self.push(requester, Kind::Open(p), lines))
    }

    /// A module asks for an account to stay unlocked on terms the person decides.
    pub fn request_unlock(&mut self, signers: &mut Registry, requester: &str, params_json: &str) -> Result<(String, String)> {
        self.admit(requester)?;
        let p: UnlockParams = serde_json::from_str(params_json).map_err(|e| bad(format!("unlock: {e}")))?;
        p.terms().check()?;
        check_displayable(&p.reason, "reason")?;
        let found = signers.find(&p.account)?;
        if found.name != KEYSTORE {
            return Err(bad("unlock: a device account signs on its device; there is nothing to unlock"));
        }
        let name = found.account.label.clone().unwrap_or_else(|| found.account.id.clone());
        let mut lines = vec![
            format!("{requester} asks to unlock {name}"),
            format!("Terms asked: {}", p.terms().describe(requester)),
        ];
        if !p.reason.trim().is_empty() {
            lines.push(format!("Reason (claimed by the requester): {}", p.reason.trim()));
        }
        Ok(self.push(requester, Kind::Unlock(p), lines))
    }

    pub fn queue(&mut self) -> Vec<Summary> {
        self.sweep();
        let now = Instant::now();
        self.records
            .iter()
            .filter(|r| !matches!(r.state, State::Settled(_)))
            .map(|r| Summary {
                handle: r.handle.clone(),
                requester: r.requester.clone(),
                kind: match r.kind {
                    Kind::Open(_) => "open",
                    Kind::Unlock(_) => "unlock",
                },
                state: match r.state {
                    State::Rendered => "rendered",
                    State::Opening => "opening",
                    _ => "offered",
                },
                age_ms: now.duration_since(r.offered_at).as_millis(),
            })
            .collect()
    }

    pub fn acknowledge(&mut self, signers: &mut Registry, handle: &str, gate: &Gate) -> Result<Shown> {
        self.sweep();
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        if !self.may(signers, &self.records[idx], gate)? {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        for r in &mut self.records {
            if r.state == State::Rendered && r.handle != handle && r.opener.as_deref() == Some(gate.caller) {
                r.state = State::Offered;
            }
        }
        let holders = match &self.records[idx].kind {
            Kind::Open(OpenParams { group: Some(g), .. }) => signers
                .holders(g)
                .unwrap_or_default()
                .iter()
                .filter(|f| (gate.opens)(&f.name) || (gate.custodian && f.name == KEYSTORE))
                .map(crate::roster::holder_json)
                .collect(),
            _ => Vec::new(),
        };
        let r = &mut self.records[idx];
        match r.state {
            State::Settled(o) => return Err(bad(format!("already settled: {o}"))),
            State::Opening => {}
            _ => r.state = State::Rendered,
        }
        r.opener = Some(gate.caller.to_string());
        Ok(Shown {
            holders,
            handle: r.handle.clone(),
            requester: r.requester.clone(),
            kind: match r.kind {
                Kind::Open(_) => "open",
                Kind::Unlock(_) => "unlock",
            },
            bundle_id: hex::encode(r.bundle_id),
            lines: r.lines.clone(),
            asked: match &r.kind {
                Kind::Open(p) => serde_json::json!({ "group": p.group, "family": p.family, "network": p.network,
                                                     "unlock": p.unlock }),
                Kind::Unlock(p) => serde_json::json!({ "account": p.account, "terms": p.terms() }),
            },
        })
    }

    /// The person decided, in the keys app or a holder's app: the wallet, the holder that opens it
    /// and its secret, and any unlock terms.
    pub fn approve(
        &mut self,
        signers: &mut Registry,
        keys: &mut dyn KeyHolder,
        handle: &str,
        bundle_id_echo: &str,
        decision: Decision,
        gate: &Gate,
    ) -> Result<Approved> {
        self.sweep();
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        if !self.may(signers, &self.records[idx], gate)? {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let r = &self.records[idx];
        if r.state != State::Rendered {
            return Err(bad("approve_access: this handle was not the one being shown"));
        }
        if bundle_id_echo.trim().trim_start_matches("0x") != hex::encode(r.bundle_id) {
            return Err(bad("approve_access: bundle_id does not match what was shown"));
        }
        let requester = r.requester.clone();
        let password = Zeroizing::new(decision.password);
        let via = match (&r.kind, decision.signer) {
            (_, Some(name)) => Some(name),
            // A keystore that keeps its xpub sealed opens by its key too, behind its password.
            (Kind::Open(p), None) if gate.custodian => p
                .group
                .as_ref()
                .or(decision.group.as_ref())
                .and_then(|g| signers.find(g).ok())
                .filter(|f| f.name == KEYSTORE && f.account.xpub.is_none() && f.info.wallet_key)
                .map(|f| f.name),
            _ => None,
        };
        if let (Kind::Open(p), Some(name)) = (&r.kind, via.as_deref()) {
            if decision.birthday.is_some() {
                return Err(bad("approve_access: a wallet opened by its key takes no birthday; its app asks for one"));
            }
            let group = match (&p.group, &decision.group) {
                (Some(asked), Some(picked)) if asked != picked => {
                    return Err(bad("approve_access: this request names its wallet"));
                }
                (Some(g), _) | (None, Some(g)) => g.clone(),
                (None, None) => return Err(bad("approve_access: pick the wallet to open")),
            };
            let start = StartOpen {
                name: name.to_string(),
                group,
                family: p.family,
                network: p.network.clone(),
                terms: decision.unlock.or_else(|| p.unlock.clone()),
                password,
            };
            return self.start_open(signers, keys, idx, gate, start);
        }
        // Naming no holder is the keys app's own path, as before.
        if !gate.custodian {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let (result, scope) = match &r.kind {
            Kind::Open(p) => {
                let group = match (&p.group, &decision.group) {
                    (Some(asked), Some(picked)) if asked != picked => {
                        return Err(bad("approve_access: this request names its wallet"));
                    }
                    (Some(g), _) | (None, Some(g)) => g.clone(),
                    (None, None) => return Err(bad("approve_access: pick the wallet to open")),
                };
                let found = signers.find(&group)?;
                let acct = AccountPublic::from_account(&found.account)?;
                if let (Some(f), Some(n)) = (&p.family, &p.network) {
                    if found.account.family != *f {
                        return Err(bad("approve_access: the wallet picked is not the family asked for"));
                    }
                    acct.chain.network(n)?;
                }
                // A device account signs on its device, and its database key has a vault of its own.
                let on_device = found.name != KEYSTORE;
                if on_device && decision.unlock.is_some() {
                    return Err(bad("approve_access: a device account signs on its device; there is nothing to unlock"));
                }
                if !on_device && decision.birthday.is_some() {
                    return Err(bad("approve_access: a keystore wallet's birthday was set when it was made"));
                }
                let terms = if on_device { None } else { decision.unlock.or_else(|| p.unlock.clone()) };
                let opened = if on_device {
                    let (signer, account) = database_holder(signers, keys, &found)?;
                    keys.device_database_key(&signer, &account, &password, decision.birthday.as_deref())?
                } else {
                    keys.database_key(&group, Some(&password))?
                };
                let scope = match &terms {
                    Some(t) => {
                        t.check()?;
                        keys.unlock(&group, &password, t.ttl_ms, t.count)?;
                        Some(scope_for(&group, t, &requester))
                    }
                    None => None,
                };
                let result = serde_json::json!({
                    "group": group, "family": found.account.family, "chain": acct.chain.as_str(), "network": p.network,
                    "external": acct.descriptor(0), "internal": acct.descriptor(1),
                    "fingerprint": acct.fingerprint.to_string(), "databaseKey": opened.database_key.as_str(),
                    "origin": opened.origin, "birthday": opened.birthday, "unlocked": terms,
                });
                self.grants.retain(|(m, g)| !(m == &requester && g == &group));
                self.grants.push((requester.clone(), group));
                (result, scope)
            }
            Kind::Unlock(p) => {
                let terms = decision.unlock.unwrap_or_else(|| p.terms());
                terms.check()?;
                let found = signers.find(&p.account)?;
                let u = keys.unlock(&found.account.id, &password, terms.ttl_ms, terms.count)?;
                let result = serde_json::json!({ "account": found.account.id, "terms": terms,
                                                 "expiresInMs": u.expires_in_ms, "countLeft": u.count_left });
                (result, Some(scope_for(&found.account.id, &terms, &requester)))
            }
        };
        if let Some(s) = scope {
            self.scopes.retain(|x| x.account != s.account);
            self.scopes.push(s);
        }
        let r = &mut self.records[idx];
        r.result = Some(result);
        r.state = State::Settled("approved");
        Ok(Approved::Settled)
    }

    /// Hand the open to the chosen holder: it works out the account's open key in its own time.
    fn start_open(
        &mut self,
        signers: &mut Registry,
        keys: &mut dyn KeyHolder,
        idx: usize,
        gate: &Gate,
        start: StartOpen,
    ) -> Result<Approved> {
        if !(gate.opens)(&start.name) && !(gate.custodian && start.name == KEYSTORE) {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let found = signers.holder(&start.group, &start.name)?;
        if !found.info.wallet_key || !found.account.family.is_bitcoin() {
            return Err(bad(format!("approve_access: {} doesn't open Bitcoin wallets itself", start.name)));
        }
        if start.family.is_some_and(|f| f != found.account.family) {
            return Err(bad("approve_access: the wallet picked is not the family asked for"));
        }
        if start.terms.is_some() && start.name != KEYSTORE {
            return Err(bad("approve_access: a device account signs on its device; there is nothing to unlock"));
        }
        if let Some(t) = &start.terms {
            t.check()?;
        }
        let secret = (!start.password.is_empty()).then(|| Secret::new(start.password.as_str()));
        let request = WalletKeyRequest { account: found.account.id.clone(), secret };
        let job = signers.signer(found.signer).wallet_key(request)?;
        let r = &mut self.records[idx];
        r.state = State::Opening;
        r.last_error = None;
        r.opening = Some(Opening {
            found,
            group: start.group,
            network: start.network,
            job,
            step: "working",
            password: start.password,
            terms: start.terms,
        });
        let handle = r.handle.clone();
        // A wrong PIN, or a holder that answers at once, comes back here and not as an event.
        let failed = self.advance(signers, keys, &handle);
        self.moves.retain(|m| !matches!(m, Move::Settled(h, "approved") | Move::Rendered(h) if *h == handle));
        let r = self.records.iter().find(|r| r.handle == handle).expect("advanced, not removed");
        match (r.state, failed) {
            (State::Opening, _) => Ok(Approved::Opening),
            (State::Settled("approved"), _) => Ok(Approved::Settled),
            (_, Some(e)) => Err(e),
            (State::Settled(o), None) => Err(bad(format!("the holder settled this as {o}"))),
            _ => Err(bad("the holder did not open the wallet")),
        }
    }

    /// Move every open whose holder is working, once.
    pub fn progress(&mut self, signers: &mut Registry, keys: &mut dyn KeyHolder) {
        self.sweep();
        let working: Vec<String> =
            self.records.iter().filter(|r| r.state == State::Opening).map(|r| r.handle.clone()).collect();
        for h in working {
            self.advance(signers, keys, &h);
        }
    }

    /// Ask the holder how its open key stands, and settle the open when it has it. The error, when
    /// it went back on screen or was declined.
    fn advance(&mut self, signers: &mut Registry, keys: &mut dyn KeyHolder, handle: &str) -> Option<ManagerError> {
        let idx = self.records.iter().position(|r| r.handle == handle)?;
        let requester = self.records[idx].requester.clone();
        let o = self.records[idx].opening.as_mut()?;
        let signer = signers.signer(o.found.signer);
        let outcome = (|| -> Result<Option<(serde_json::Value, Option<Scope>)>> {
            let st = signer.wallet_key_status(&o.job)?;
            match st.state {
                JobState::Working | JobState::ConfirmOnDevice => {
                    o.step = st.state.as_str();
                    Ok(None)
                }
                JobState::Done => {
                    let key = signer.wallet_key_result(&o.job)?;
                    Ok(Some(opened(o, key, keys, &requester)?))
                }
                JobState::Refused => Err(ManagerError::Refused("declined on the device".into())),
                JobState::Failed | JobState::Cancelled => Err(st.error.map(ManagerError::from).unwrap_or_else(|| {
                    ManagerError::Signing(format!("the holder's job ended {}", st.state.as_str()))
                })),
            }
        })();
        let r = &mut self.records[idx];
        let mut failed = None;
        let moved = match outcome {
            Ok(None) => return None,
            Ok(Some((result, scope))) => {
                let group = r.opening.as_ref().map(|o| o.group.clone()).unwrap_or_default();
                r.result = Some(result);
                r.state = State::Settled("approved");
                r.opening = None;
                self.grants.retain(|(m, g)| !(m == &requester && g == &group));
                self.grants.push((requester, group));
                if let Some(s) = scope {
                    self.scopes.retain(|x| x.account != s.account);
                    self.scopes.push(s);
                }
                Move::Settled(handle.to_string(), "approved")
            }
            Err(e @ ManagerError::Refused(_)) => {
                r.state = State::Settled("rejected");
                r.opening = None;
                failed = Some(e);
                Move::Settled(handle.to_string(), "rejected")
            }
            Err(e) => {
                // Back on screen, saying why, so the person can try again or pick another holder.
                r.last_error = Some((e.wire_code(), e.to_string()));
                r.state = State::Rendered;
                r.opening = None;
                failed = Some(e);
                Move::Rendered(handle.to_string())
            }
        };
        self.moves.push(moved);
        failed
    }

    /// What moved since the last call, for the glue to announce.
    pub fn drain_moves(&mut self) -> Vec<Move> {
        std::mem::take(&mut self.moves)
    }

    /// How an open stands, for the app showing it: `{ state, step?, outcome?, code?, error? }`.
    pub fn progress_of(&mut self, signers: &mut Registry, keys: &mut dyn KeyHolder, handle: &str, gate: &Gate) -> Result<serde_json::Value> {
        self.progress(signers, keys);
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        if !self.may(signers, &self.records[idx], gate)? {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let r = &self.records[idx];
        let (code, error) = r.last_error.clone().map_or((None, None), |(c, e)| (c, Some(e)));
        Ok(match r.state {
            State::Offered => serde_json::json!({ "state": "offered" }),
            State::Rendered => serde_json::json!({ "state": "rendered", "code": code, "error": error }),
            State::Opening => serde_json::json!({ "state": "opening", "step": r.opening.as_ref().map(|o| o.step) }),
            State::Settled(o) => serde_json::json!({ "state": "settled", "outcome": o }),
        })
    }

    pub fn reject(&mut self, signers: &mut Registry, handle: &str, gate: &Gate) -> Result<()> {
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        if !self.may(signers, &self.records[idx], gate)? {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let r = &mut self.records[idx];
        if let State::Settled(o) = r.state {
            return Err(bad(format!("already settled: {o}")));
        }
        cancel_opening(signers, r);
        r.state = State::Settled("rejected");
        Ok(())
    }

    pub fn status(&mut self, handle: &str, receipt: &str) -> Result<(&'static str, Option<&'static str>)> {
        self.sweep();
        Ok(match self.by_receipt(handle, receipt)?.state {
            State::Offered => ("offered", None),
            State::Rendered => ("rendered", None),
            State::Opening => ("opening", None),
            State::Settled(o) => ("settled", Some(o)),
        })
    }

    /// The open's descriptors and database key, or the unlock's granted terms. Repeatable until acked.
    pub fn fetch(&mut self, handle: &str, receipt: &str) -> Result<serde_json::Value> {
        self.sweep();
        self.by_receipt(handle, receipt)?.result.clone().ok_or_else(|| bad("no result for this handle"))
    }

    pub fn ack(&mut self, handle: &str, receipt: &str) -> Result<()> {
        self.by_receipt(handle, receipt)?.result = None;
        self.sweep();
        Ok(())
    }

    pub fn cancel(&mut self, signers: &mut Registry, handle: &str, receipt: &str) -> Result<()> {
        let r = self.by_receipt(handle, receipt)?;
        if !matches!(r.state, State::Settled(_)) {
            cancel_opening(signers, r);
            r.state = State::Settled("cancelled");
        }
        r.result = None;
        self.sweep();
        Ok(())
    }

    /// A wallet's descriptors again, for a module it is open for.
    pub fn descriptors(&self, signers: &mut Registry, module: &str, group: &str) -> Result<(String, String)> {
        if !self.grants.iter().any(|(m, g)| m == module && g == group.trim()) {
            return Err(ManagerError::Refused("this wallet is not open for this module".into()));
        }
        let found = signers.find(group)?;
        let acct = AccountPublic::from_account(&found.account)?;
        Ok((acct.descriptor(0), acct.descriptor(1)))
    }

    /// Close a wallet for a module; an unlock scoped to that module alone ends with it.
    pub fn close(&mut self, keys: &mut dyn KeyHolder, module: &str, group: &str) -> Result<bool> {
        let before = self.grants.len();
        self.grants.retain(|(m, g)| !(m == module && g == group.trim()));
        let closed = self.grants.len() != before;
        let account = lower(group);
        if closed && self.scopes.iter().any(|s| s.account == account && s.apps == [module.to_string()]) {
            self.scopes.retain(|s| s.account != account);
            keys.lock(Some(group.trim()))?;
        }
        Ok(closed)
    }

    pub fn open_accounts(&self) -> Vec<(String, String)> {
        self.grants.clone()
    }

    /// The person's own unlock from the keys app, with nobody asking.
    pub fn unlock(&mut self, signers: &mut Registry, keys: &mut dyn KeyHolder, account: &str, password: &str, terms: &Terms) -> Result<Unlocked> {
        terms.check()?;
        if terms.apps.is_empty() {
            return Err(bad("unlock: name the apps it covers"));
        }
        let found = signers.find(account)?;
        let u = keys.unlock(&found.account.id, password, terms.ttl_ms, terms.count)?;
        let s = scope_for(&found.account.id, terms, "");
        self.scopes.retain(|x| x.account != s.account);
        self.scopes.push(s);
        Ok(u)
    }

    pub fn lock(&mut self, keys: &mut dyn KeyHolder, account: Option<&str>) -> Result<usize> {
        match account {
            Some(a) => self.scopes.retain(|s| s.account != lower(a)),
            None => self.scopes.clear(),
        }
        keys.lock(account)
    }

    /// The keystore's unlocks, with the apps and confirmation this module keeps for each.
    pub fn unlocked(&mut self, keys: &mut dyn KeyHolder) -> Result<Vec<(Unlocked, Vec<String>, bool)>> {
        let held = keys.unlocked()?;
        self.scopes.retain(|s| held.iter().any(|u| lower(&u.account) == s.account));
        Ok(held
            .into_iter()
            .map(|u| {
                let s = self.scopes.iter().find(|s| s.account == lower(&u.account));
                let (apps, confirm) = s.map_or((Vec::new(), true), |s| (s.apps.clone(), s.confirm));
                (u, apps, confirm)
            })
            .collect())
    }

    /// Does an unlock of `account` cover a request from `requester`, and how?
    pub fn covers(&self, account: &str, requester: &str) -> Cover {
        let Some(s) = self.scopes.iter().find(|s| s.account == lower(account)) else { return Cover::No };
        let named = s.apps.iter().any(|a| a == requester);
        match (named, s.apps.iter().any(|a| a == "*"), s.confirm) {
            (true, _, false) => Cover::WithoutAsking,
            (true, _, true) | (false, true, true) => Cover::Confirmed,
            _ => Cover::No,
        }
    }

    /// The keystore answered `locked` for an account this module thought unlocked: its time or count ran out.
    pub fn expired(&mut self, account: &str) {
        self.scopes.retain(|s| s.account != lower(account));
    }
}

/// An open, as the person decided it, for the holder to start.
struct StartOpen {
    name: String,
    group: String,
    family: Option<Family>,
    network: Option<String>,
    terms: Option<Terms>,
    password: Zeroizing<String>,
}

fn cancel_opening(signers: &mut Registry, r: &mut Record) {
    if let Some(o) = r.opening.take() {
        let _ = signers.signer(o.found.signer).cancel_wallet_key(&o.job);
    }
}

/// The open's result from the holder's answer: its xpub proven to be the account's, the
/// descriptors, and the database key its seed gives. The manager keeps neither once collected.
fn opened(o: &Opening, key: WalletKey, keys: &mut dyn KeyHolder, requester: &str) -> Result<(serde_json::Value, Option<Scope>)> {
    let account = &o.found.account;
    let roster_key = crate::roster::key_of(account).ok_or_else(|| bad("this wallet has no roster key"))?;
    walletkey::check_xpub(&roster_key, account.family, account.chain, &key.xpub)
        .map_err(|_| bad("the holder answered with another wallet's xpub"))?;
    let acct = AccountPublic::from_account(&Account { xpub: Some(key.xpub.clone()), ..account.clone() })?;
    if let Some(n) = &o.network {
        acct.chain.network(n)?;
    }
    let database_key = match (&key.database_key, account.opens_by_password) {
        (Some(k), _) if k.expose().len() == 64 && k.expose().bytes().all(|b| b.is_ascii_hexdigit()) => Some(k.expose()),
        (None, true) => None,
        _ => return Err(bad("the holder answered without a database key")),
    };
    let origin = key.origin.as_deref().filter(|o| *o == "created").unwrap_or("restored");
    let birthday = key.birthday.as_deref().filter(|b| is_day(b));
    let scope = match &o.terms {
        Some(t) => {
            keys.unlock(&o.group, &o.password, t.ttl_ms, t.count)?;
            Some(scope_for(&o.group, t, requester))
        }
        None => None,
    };
    let result = serde_json::json!({
        "group": o.group, "family": account.family, "chain": acct.chain.as_str(), "network": o.network,
        "external": acct.descriptor(0), "internal": acct.descriptor(1),
        "fingerprint": acct.fingerprint.to_string(), "databaseKey": database_key,
        "opensByPassword": account.opens_by_password, "origin": origin, "birthday": birthday,
        "unlocked": o.terms, "signer": o.found.name,
    });
    Ok((result, scope))
}

/// `YYYY-MM-DD`; anything else is dropped, not passed on.
fn is_day(s: &str) -> bool {
    s.len() == 10 && s.bytes().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == b'-' } else { c.is_ascii_digit() })
}

/// Whose name a device wallet's database key is kept under: the holder that already has one,
/// else the first in configured order. So reopening it through the Shell instead of the reader
/// finds the same key, and the wallet's database with it.
fn database_holder(signers: &mut Registry, keys: &mut dyn KeyHolder, found: &Found) -> Result<(String, String)> {
    let mut holders: Vec<Found> =
        signers.holders(&found.account.id)?.into_iter().filter(|f| f.name != KEYSTORE).collect();
    holders.sort_by_key(|f| f.signer);
    let kept = keys.device_wallets()?;
    let pick = holders
        .iter()
        .find(|f| kept.iter().any(|(s, a)| *s == f.name && *a == f.account.id))
        .or(holders.first())
        .unwrap_or(found);
    Ok((pick.name.clone(), pick.account.id.clone()))
}

fn scope_for(account: &str, terms: &Terms, requester: &str) -> Scope {
    let apps = if terms.apps.is_empty() { vec![requester.to_string()] } else { terms.apps.clone() };
    Scope { account: lower(account), apps, confirm: terms.confirm }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Collects, JobStatus, SignRequest, Signature, Signer, SignerInfo};

    /// The keystore's extras, in memory: password "pw", a fixed database key, unlocks by account.
    #[derive(Default)]
    pub(crate) struct FakeKeys {
        pub unlocks: Vec<Unlocked>,
        /// Device wallets by signer and account: their password, key and birthday.
        pub devices: std::collections::HashMap<(String, String), (String, String, Option<String>)>,
    }

    impl KeyHolder for FakeKeys {
        fn database_key(&mut self, _: &str, password: Option<&str>) -> Result<OpenedWallet> {
            match password {
                Some("pw") => Ok(OpenedWallet {
                    database_key: Zeroizing::new("ab".repeat(32)),
                    origin: "restored".into(),
                    birthday: Some("2021-11-14".into()),
                }),
                _ => Err(ManagerError::Signer(logos_signer_interface::SignerError::new(
                    logos_signer_interface::ErrorCode::WrongSecret,
                    "the password for this account is not correct",
                ))),
            }
        }
        fn device_database_key(&mut self, signer: &str, account: &str, password: &str, birthday: Option<&str>)
            -> Result<OpenedWallet> {
            let n = self.devices.len() + 1;
            let (pw, key, day) = self.devices.entry((signer.into(), account.into())).or_insert_with(|| {
                (password.into(), format!("{n:02x}").repeat(32), birthday.map(str::to_string))
            });
            if pw != password {
                return Err(ManagerError::Signer(logos_signer_interface::SignerError::new(
                    logos_signer_interface::ErrorCode::WrongSecret,
                    "the password for this wallet's database key is not correct",
                )));
            }
            Ok(OpenedWallet { database_key: Zeroizing::new(key.clone()), origin: "restored".into(), birthday: day.clone() })
        }
        fn device_wallets(&mut self) -> Result<Vec<(String, String)>> {
            Ok(self.devices.keys().cloned().collect())
        }
        fn unlock(&mut self, account: &str, password: &str, ttl_ms: Option<u64>, count: Option<u32>) -> Result<Unlocked> {
            self.database_key(account, Some(password))?;
            let u = Unlocked { account: account.to_ascii_lowercase(), expires_in_ms: ttl_ms, count_left: count };
            self.unlocks.retain(|x| x.account != u.account);
            self.unlocks.push(u.clone());
            Ok(u)
        }
        fn lock(&mut self, account: Option<&str>) -> Result<usize> {
            let before = self.unlocks.len();
            match account {
                Some(a) => self.unlocks.retain(|u| u.account != a.to_ascii_lowercase()),
                None => self.unlocks.clear(),
            }
            Ok(before - self.unlocks.len())
        }
        fn unlocked(&mut self) -> Result<Vec<Unlocked>> {
            Ok(self.unlocks.clone())
        }
    }

    fn no_holder(_: &str) -> bool {
        false
    }

    /// The keys app: the custodian, opening nobody's accounts but the keystore's.
    pub(crate) fn keys_app() -> Gate<'static> {
        Gate { caller: "evm_keystore_ui", custodian: true, opens: &no_holder }
    }

    /// A holder's app, opening the accounts of the signers it serves.
    fn app(caller: &'static str, serves: &'static [&'static str]) -> Gate<'static> {
        Gate { caller, custodian: false, opens: Box::leak(Box::new(move |s: &str| serves.contains(&s))) }
    }

    fn fixture() -> (Registry, FakeKeys, Access) {
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions::default())));
        (r, FakeKeys::default(), Access::new())
    }

    #[test]
    fn reopening_a_wallet_may_name_its_network_and_a_wrong_one_is_refused_up_front() {
        let (mut s, mut k, mut a) = fixture();
        let req = |n: &str| format!(r#"{{"group":"mock-segwit","network":"{n}"}}"#);
        assert!(a.request_open(&mut s, "bitcoin_wallet_core_module", &req("bitcoin")).is_err(), "a test wallet on mainnet");
        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", &req("regtest")).unwrap();
        let shown = a.acknowledge(&mut s, &h, &keys_app()).unwrap();
        assert!(shown.lines.iter().any(|l| l.ends_with("test chain) on regtest")), "{:?}", shown.lines);
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &keys_app()).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["network"], "regtest");
        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", r#"{"group":"mock-segwit"}"#).unwrap();
        let shown = a.acknowledge(&mut s, &h, &keys_app()).unwrap();
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &keys_app()).unwrap();
        assert!(a.fetch(&h, &r).unwrap()["network"].is_null(), "named nothing, echoes nothing");
    }

    fn decide(group: Option<&str>, password: &str, unlock: Option<Terms>) -> Decision {
        Decision { group: group.map(str::to_string), password: password.into(), unlock, birthday: None, signer: None }
    }

    /// A device's module offering the mock's accounts, and no keystore.
    fn device_fixture() -> (Registry, FakeKeys, Access) {
        let mut r = Registry::new();
        r.add("keycard_shell_module", Box::new(MockSigner::new(MockOptions::default())));
        (r, FakeKeys::default(), Access::new())
    }

    #[test]
    fn a_device_wallet_opens_with_a_password_set_at_its_first_open_and_has_nothing_to_unlock() {
        let (mut s, mut k, mut a) = device_fixture();
        let ask = r#"{"group":"mock-segwit","network":"regtest","unlock":{"ttlMs":60000}}"#;
        let open = |a: &mut Access, s: &mut Registry| {
            let (h, r) = a.request_open(s, "bitcoin_wallet_core_module", ask).unwrap();
            let bundle = a.acknowledge(s, &h, &keys_app()).unwrap().bundle_id;
            (h, r, bundle)
        };
        let decision = |pw: &str, unlock: Option<Terms>, birthday: Option<&str>| Decision {
            group: None,
            password: pw.into(),
            unlock,
            birthday: birthday.map(str::to_string),
            signer: None,
        };
        let (h, r, b) = open(&mut a, &mut s);
        let terms = Terms { ttl_ms: Some(1000), confirm: true, ..Default::default() };
        assert!(a.approve(&mut s, &mut k, &h, &b, decision("data-pw", Some(terms), None), &keys_app()).is_err(), "nothing to unlock");
        a.approve(&mut s, &mut k, &h, &b, decision("data-pw", None, Some("2021-11-14")), &keys_app()).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!((got["origin"].as_str(), got["birthday"].as_str()), (Some("restored"), Some("2021-11-14")));
        assert_eq!(got["unlocked"], serde_json::Value::Null, "the app asked for terms; a device grants none");
        assert!(k.devices.contains_key(&("keycard_shell_module".to_string(), "mock-segwit".to_string())));
        let first = got["databaseKey"].as_str().unwrap().to_string();

        // Opened again: the same key, behind the password set the first time.
        let (h, r, b) = open(&mut a, &mut s);
        assert!(a.approve(&mut s, &mut k, &h, &b, decision("nope", None, None), &keys_app()).is_err());
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong password leaves it on screen");
        a.approve(&mut s, &mut k, &h, &b, decision("data-pw", None, None), &keys_app()).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some(first.as_str()));

        // And an unlock is refused before anything is shown.
        let unlock = r#"{"account":"mock-segwit","ttlMs":60000}"#;
        assert!(a.request_unlock(&mut s, "bitcoin_wallet_core_module", unlock).is_err());
    }

    #[test]
    fn a_device_wallet_keeps_its_database_key_whichever_transport_opens_it() {
        let mut s = Registry::new();
        s.add("keycard_module", Box::new(MockSigner::new(MockOptions::default())));
        s.add("keycard_shell_module", Box::new(MockSigner::new(MockOptions::default())));
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        // First opened through the Shell; now the card is in a reader, which is preferred.
        let shell = ("keycard_shell_module".to_string(), "mock-segwit".to_string());
        k.devices.insert(shell.clone(), ("data-pw".into(), "cd".repeat(32), None));
        assert_eq!(s.find("mock-segwit").unwrap().name, "keycard_module");
        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", r#"{"group":"mock-segwit"}"#).unwrap();
        let bundle = a.acknowledge(&mut s, &h, &keys_app()).unwrap().bundle_id;
        a.approve(&mut s, &mut k, &h, &bundle, decide(None, "data-pw", None), &keys_app()).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some("cd".repeat(32).as_str()));
        assert_eq!(k.devices.keys().collect::<Vec<_>>(), vec![&shell], "no second key, no second database");
    }

    #[test]
    fn a_keystore_wallet_takes_no_birthday_at_open() {
        let (mut s, mut k, mut a) = fixture();
        let (h, _) = a.request_open(&mut s, "bitcoin_wallet_core_module", r#"{"group":"mock-segwit","network":"regtest"}"#).unwrap();
        let bundle = a.acknowledge(&mut s, &h, &keys_app()).unwrap().bundle_id;
        let d = Decision { group: None, password: "pw".into(), unlock: None, birthday: Some("2021-11-14".into()), signer: None };
        assert!(a.approve(&mut s, &mut k, &h, &bundle, d, &keys_app()).is_err(), "it was set when the wallet was made");
    }

    #[test]
    fn an_open_request_gives_the_requester_its_wallet_and_nobody_else_its_descriptors() {
        let (mut s, mut k, mut a) = fixture();
        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", r#"{"family":"bitcoin","network":"signet"}"#).unwrap();
        let shown = a.acknowledge(&mut s, &h, &keys_app()).unwrap();
        assert!(shown.lines.join("\n").contains("Any native segwit wallet on signet"), "{:?}", shown.lines);
        assert_eq!(shown.asked, serde_json::json!({ "group": null, "family": "bitcoin", "network": "signet", "unlock": null }));
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &keys_app()).is_err(), "no wallet picked");
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-taproot"), "pw", None), &keys_app()).is_err(), "wrong family");
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-segwit"), "nope", None), &keys_app()).is_err());
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong password leaves it on screen");
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-segwit"), "pw", None), &keys_app()).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!(got["group"], "mock-segwit");
        assert_eq!((got["chain"].as_str(), got["network"].as_str()), (Some("test"), Some("signet")));
        assert_eq!(got["databaseKey"], "ab".repeat(32));
        assert_eq!((got["origin"].as_str(), got["birthday"].as_str()), (Some("restored"), Some("2021-11-14")));
        assert!(got["external"].as_str().unwrap().starts_with("wpkh(["));
        let (ext, _) = a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").unwrap();
        assert_eq!(ext, got["external"].as_str().unwrap());
        assert!(a.descriptors(&mut s, "someone_else", "mock-segwit").is_err());
        a.ack(&h, &r).unwrap();
        assert!(a.fetch(&h, &r).is_err());
        assert!(a.close(&mut k, "bitcoin_wallet_core_module", "mock-segwit").unwrap());
        assert!(a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").is_err());
    }

    #[test]
    fn an_open_with_unlock_terms_unlocks_for_the_requester_and_closing_locks_it() {
        let (mut s, mut k, mut a) = fixture();
        let (h, _) = a
            .request_open(&mut s, "wallet_core", r#"{"group":"mock-taproot","unlock":{"ttlMs":3600000}}"#)
            .unwrap();
        let shown = a.acknowledge(&mut s, &h, &keys_app()).unwrap();
        assert!(shown.lines.join("\n").contains("for 60 minutes, for wallet_core, each one confirmed"), "{:?}", shown.lines);
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &keys_app()).unwrap();
        assert_eq!(a.covers("mock-taproot", "wallet_core"), Cover::Confirmed);
        assert_eq!(a.covers("mock-taproot", "another_app"), Cover::No);
        assert_eq!(k.unlocks.len(), 1);
        a.close(&mut k, "wallet_core", "mock-taproot").unwrap();
        assert_eq!(a.covers("mock-taproot", "wallet_core"), Cover::No);
        assert!(k.unlocks.is_empty(), "an unlock scoped to the wallet ends when it closes");
    }

    #[test]
    fn the_person_decides_the_terms_not_the_app() {
        let (mut s, mut k, mut a) = fixture();
        let (h, r) = a
            .request_unlock(&mut s, "game", r#"{"account":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","count":50,"ttlMs":1800000,"confirm":false,"apps":["game"]}"#)
            .unwrap();
        let shown = a.acknowledge(&mut s, &h, &keys_app()).unwrap();
        assert!(shown.lines.join("\n").contains("WITHOUT showing them to you"), "{:?}", shown.lines);
        // The person keeps confirmation on and allows ten.
        let granted = Terms { ttl_ms: Some(600_000), count: Some(10), apps: vec!["game".into()], confirm: true };
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", Some(granted)), &keys_app()).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!(got["terms"]["count"], 10);
        assert_eq!(got["terms"]["confirm"], true);
        assert_eq!(a.covers("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266", "game"), Cover::Confirmed);
    }

    #[test]
    fn signing_without_asking_names_its_apps_and_any_app_needs_confirmation() {
        let (mut s, mut k, mut a) = fixture();
        let acct = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let any_unseen = Terms { ttl_ms: None, count: None, apps: vec!["*".into()], confirm: false };
        assert!(a.unlock(&mut s, &mut k, acct, "pw", &any_unseen).is_err());
        let named = Terms { ttl_ms: Some(60_000), count: Some(3), apps: vec!["game".into()], confirm: false };
        a.unlock(&mut s, &mut k, acct, "pw", &named).unwrap();
        assert_eq!(a.covers(acct, "game"), Cover::WithoutAsking);
        assert_eq!(a.covers(acct, "wallet"), Cover::No);
        let any_confirmed = Terms { ttl_ms: None, count: None, apps: vec!["*".into()], confirm: true };
        a.unlock(&mut s, &mut k, acct, "pw", &any_confirmed).unwrap();
        assert_eq!(a.covers(acct, "wallet"), Cover::Confirmed);
        assert_eq!(a.lock(&mut k, None).unwrap(), 1);
        assert_eq!(a.covers(acct, "wallet"), Cover::No);
    }

    #[test]
    fn an_unlock_ends_here_when_the_keystore_ends_it_and_one_lock_leaves_the_rest() {
        let (mut s, mut k, mut a) = fixture();
        let acct = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let terms = Terms { ttl_ms: Some(60_000), count: Some(2), apps: vec!["game".into()], confirm: true };
        a.unlock(&mut s, &mut k, acct, "pw", &terms).unwrap();
        // The keystore answered `locked`: its time or count ran out first.
        a.expired(acct);
        assert_eq!(a.covers(acct, "game"), Cover::No);
        // The keystore dropped it on its own: the next listing drops this module's terms too.
        a.unlock(&mut s, &mut k, acct, "pw", &terms).unwrap();
        k.unlocks.clear();
        assert!(a.unlocked(&mut k).unwrap().is_empty());
        assert_eq!(a.covers(acct, "game"), Cover::No);
        // Locking one account leaves the others unlocked.
        a.unlock(&mut s, &mut k, acct, "pw", &terms).unwrap();
        a.unlock(&mut s, &mut k, "mock-segwit", "pw", &terms).unwrap();
        assert_eq!(a.lock(&mut k, Some(acct)).unwrap(), 1);
        assert_eq!((a.covers(acct, "game"), a.covers("mock-segwit", "game")), (Cover::No, Cover::Confirmed));
    }

    #[test]
    fn a_requester_cannot_flood_the_custodian() {
        let (mut s, _, mut a) = fixture();
        for _ in 0..MAX_PENDING_PER_REQUESTER {
            a.request_open(&mut s, "noisy", r#"{"group":"mock-segwit"}"#).unwrap();
        }
        assert!(a.request_open(&mut s, "noisy", r#"{"group":"mock-segwit"}"#).is_err());
        assert!(a.request_open(&mut s, "quiet", r#"{"group":"mock-segwit"}"#).is_ok());
        assert!(a.request_open(&mut s, "x", r#"{"group":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"}"#).is_err(), "an EVM account is no wallet");
    }

    /// A device the test presses, shared with the registry; it may answer with another wallet's xpub.
    #[derive(Clone)]
    struct Pressable {
        device: std::sync::Arc<std::sync::Mutex<MockSigner>>,
        lie: Option<String>,
    }

    impl Pressable {
        fn new(opts: MockOptions) -> Self {
            Pressable { device: std::sync::Arc::new(std::sync::Mutex::new(MockSigner::new(opts))), lie: None }
        }
        fn press(&self, yes: bool) {
            let mut d = self.device.lock().unwrap();
            let jobs = d.waiting_keys();
            assert_eq!(jobs.len(), 1, "one open waiting on the device");
            if yes { d.confirm(&jobs[0]).unwrap() } else { d.refuse(&jobs[0]).unwrap() }
        }
        fn waiting(&self) -> usize {
            self.device.lock().unwrap().waiting_keys().len()
        }
    }

    impl Signer for Pressable {
        fn info(&self) -> SignerInfo {
            self.device.lock().unwrap().info()
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
            self.device.lock().unwrap().accounts()
        }
        fn sign(&mut self, request: SignRequest) -> logos_signer_interface::Result<String> {
            self.device.lock().unwrap().sign(request)
        }
        fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.device.lock().unwrap().status(job)
        }
        fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            self.device.lock().unwrap().result(job)
        }
        fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.device.lock().unwrap().cancel(job)
        }
        fn wallet_key(&mut self, request: WalletKeyRequest) -> logos_signer_interface::Result<String> {
            self.device.lock().unwrap().wallet_key(request)
        }
        fn wallet_key_status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.device.lock().unwrap().wallet_key_status(job)
        }
        fn wallet_key_result(&mut self, job: &str) -> logos_signer_interface::Result<WalletKey> {
            let key = self.device.lock().unwrap().wallet_key_result(job)?;
            Ok(WalletKey { xpub: self.lie.clone().unwrap_or(key.xpub), ..key })
        }
        fn cancel_wallet_key(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.device.lock().unwrap().cancel_wallet_key(job)
        }
    }

    fn by(signer: &str, secret: &str) -> Decision {
        Decision { group: None, password: secret.into(), unlock: None, birthday: None, signer: Some(signer.into()) }
    }

    /// One seed in a reader (a PIN) and in the Shell (a press), neither listing its xpub.
    fn two_holders() -> (Registry, Pressable) {
        let pin = MockOptions { collects: Collects::Pin, secret: "123456".into(), list_xpub: false, ..Default::default() };
        let press = MockOptions { needs_confirmation: true, list_xpub: false, ..Default::default() };
        let shell = Pressable::new(press);
        let mut s = Registry::new();
        s.add("keycard_module", Box::new(Pressable::new(pin)));
        s.add("keycard_shell_module", Box::new(shell.clone()));
        (s, shell)
    }

    const OPEN: &str = r#"{"group":"mock-segwit","network":"regtest"}"#;

    fn refused<T>(r: Result<T>) -> bool {
        matches!(r, Err(ManagerError::Refused(_)))
    }

    #[test]
    fn a_device_wallet_opens_through_its_holders_app_and_each_holder_gives_the_same_key() {
        let (mut s, shell) = two_holders();
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        let keycard_ui = app("keycard_ui", &["keycard_module", "keycard_shell_module"]);

        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", OPEN).unwrap();
        let shown = a.acknowledge(&mut s, &h, &keycard_ui).unwrap();
        let mut holders: Vec<_> = shown.holders.iter().map(|x| (x["signer"].as_str().unwrap(), x["opens"] == true)).collect();
        holders.sort();
        assert_eq!(holders, [("keycard_module", true), ("keycard_shell_module", true)]);
        let wrong = a.approve(&mut s, &mut k, &h, &shown.bundle_id, by("keycard_module", "000000"), &keycard_ui).unwrap_err();
        assert_eq!(wrong.wire_code().as_deref(), Some("wrong_secret"));
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong PIN leaves it on screen");
        let opened = a.approve(&mut s, &mut k, &h, &shown.bundle_id, by("keycard_module", "123456"), &keycard_ui);
        assert_eq!(opened.unwrap(), Approved::Settled);
        assert!(a.drain_moves().is_empty(), "settled at once: the reply says so, no second event");
        let got = a.fetch(&h, &r).unwrap();
        let first = got["databaseKey"].as_str().unwrap().to_string();
        assert!(first.len() == 64 && got["external"].as_str().unwrap().starts_with("wpkh(["), "{got}");
        assert_eq!((got["signer"].as_str(), got["network"].as_str()), (Some("keycard_module"), Some("regtest")));
        assert_eq!((got["opensByPassword"] == false, got["origin"].as_str()), (true, Some("restored")));
        assert!(k.devices.is_empty(), "no data password, nothing kept in the keystore");

        // Again through the Shell: it waits for the press, and its seed gives the same key.
        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", OPEN).unwrap();
        let bundle = a.acknowledge(&mut s, &h, &keycard_ui).unwrap().bundle_id;
        let opening = a.approve(&mut s, &mut k, &h, &bundle, by("keycard_shell_module", ""), &keycard_ui);
        assert_eq!(opening.unwrap(), Approved::Opening);
        assert_eq!(a.status(&h, &r).unwrap().0, "opening");
        let p = a.progress_of(&mut s, &mut k, &h, &keycard_ui).unwrap();
        assert_eq!((p["state"].as_str(), p["step"].as_str()), (Some("opening"), Some("confirm_on_device")));
        assert!(a.queue().iter().any(|q| q.handle == h && q.state == "opening"));
        shell.press(true);
        a.progress(&mut s, &mut k);
        assert_eq!(a.drain_moves(), vec![Move::Settled(h.clone(), "approved")]);
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some(first.as_str()));
        assert!(a.open_accounts().contains(&("bitcoin_wallet_core_module".into(), "mock-segwit".into())));
    }

    #[test]
    fn only_a_holders_app_opens_it_and_the_first_to_show_it_keeps_it() {
        let (mut s, _) = two_holders();
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        let keycard_ui = app("keycard_ui", &["keycard_module", "keycard_shell_module"]);
        let qr_ui = app("qr_signer_ui", &["qr_signer_module"]);

        let (h, r) = a.request_open(&mut s, "bitcoin_wallet_core_module", OPEN).unwrap();
        assert!(refused(a.acknowledge(&mut s, &h, &qr_ui)), "QR Wallets holds no seed of this wallet");
        // The keys app may show it, and opens only with the keystore.
        let bundle = a.acknowledge(&mut s, &h, &keys_app()).unwrap().bundle_id;
        assert!(refused(a.approve(&mut s, &mut k, &h, &bundle, by("keycard_module", "123456"), &keys_app())));
        assert!(refused(a.acknowledge(&mut s, &h, &keycard_ui)), "shown in the keys app, it is the keys app's");
        a.cancel(&mut s, &h, &r).unwrap();

        let (h, _) = a.request_open(&mut s, "bitcoin_wallet_core_module", OPEN).unwrap();
        let bundle = a.acknowledge(&mut s, &h, &keycard_ui).unwrap().bundle_id;
        assert!(refused(a.acknowledge(&mut s, &h, &keys_app())), "shown in the Keycard app, it is the Keycard app's");
        assert!(refused(a.reject(&mut s, &h, &keys_app())));
        let legacy = a.approve(&mut s, &mut k, &h, &bundle, decide(None, "pw", None), &keycard_ui);
        assert!(refused(legacy), "naming no holder is the keys app's own path");
        assert!(refused(a.approve(&mut s, &mut k, &h, &bundle, by("qr_signer_module", ""), &keycard_ui)));

        // An open that names no wallet, and an unlock, stay with the keys app.
        let (h, _) = a.request_open(&mut s, "other_app", r#"{"family":"bitcoin","network":"regtest"}"#).unwrap();
        assert!(refused(a.acknowledge(&mut s, &h, &keycard_ui)));
    }

    #[test]
    fn a_declined_or_cancelled_open_ends_the_devices_job_and_a_foreign_xpub_opens_nothing() {
        let (mut s, shell) = two_holders();
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        let keycard_ui = app("keycard_ui", &["keycard_module", "keycard_shell_module"]);
        let start = |a: &mut Access, s: &mut Registry, k: &mut FakeKeys| {
            let (h, r) = a.request_open(s, "bitcoin_wallet_core_module", OPEN).unwrap();
            let bundle = a.acknowledge(s, &h, &keycard_ui).unwrap().bundle_id;
            assert_eq!(a.approve(s, k, &h, &bundle, by("keycard_shell_module", ""), &keycard_ui).unwrap(), Approved::Opening);
            (h, r)
        };
        let (h, r) = start(&mut a, &mut s, &mut k);
        shell.press(false);
        a.progress(&mut s, &mut k);
        assert_eq!(a.drain_moves(), vec![Move::Settled(h.clone(), "rejected")]);
        assert_eq!(a.status(&h, &r).unwrap(), ("settled", Some("rejected")));

        let (h, r) = start(&mut a, &mut s, &mut k);
        assert_eq!(shell.waiting(), 1);
        a.cancel(&mut s, &h, &r).unwrap();
        assert_eq!(shell.waiting(), 0, "the device stops asking");

        // A holder answering with another wallet's xpub: back on screen, nothing handed over.
        let mut s = Registry::new();
        let mut liar = Pressable::new(MockOptions { list_xpub: false, ..Default::default() });
        let (_, _, theirs) = crate::psbt::tests::ours(crate::btc::Family::Taproot);
        liar.lie = Some(theirs.xpub.to_string());
        s.add("keycard_module", Box::new(liar));
        let (h, r) = a.request_open(&mut s, "other_app", OPEN).unwrap();
        let bundle = a.acknowledge(&mut s, &h, &keycard_ui).unwrap().bundle_id;
        let e = a.approve(&mut s, &mut k, &h, &bundle, by("keycard_module", ""), &keycard_ui).unwrap_err();
        assert!(e.to_string().contains("another wallet's xpub"), "{e}");
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered");
        assert!(a.fetch(&h, &r).is_err());
        let p = a.progress_of(&mut s, &mut k, &h, &keycard_ui).unwrap();
        assert!(p["error"].as_str().unwrap().contains("another wallet's xpub"), "{p}");
    }

    #[test]
    fn the_keys_app_opens_a_keystore_wallet_that_keeps_its_xpub_sealed_by_its_key() {
        let mut s = Registry::new();
        let opts = MockOptions { collects: Collects::Password, secret: "pw".into(), list_xpub: false, ..Default::default() };
        s.add("keystore_module", Box::new(MockSigner::new(opts)));
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        let ask = r#"{"group":"mock-segwit","network":"regtest","unlock":{"ttlMs":60000}}"#;
        let (h, r) = a.request_open(&mut s, "wallet_core", ask).unwrap();
        let shown = a.acknowledge(&mut s, &h, &keys_app()).unwrap();
        assert_eq!(shown.holders.len(), 1, "the keys app opens with the keystore");
        let wrong = a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "nope", None), &keys_app()).unwrap_err();
        assert_eq!(wrong.wire_code().as_deref(), Some("wrong_secret"));
        let dated = Decision { birthday: Some("2021-11-14".into()), ..decide(None, "pw", None) };
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, dated, &keys_app()).is_err());
        let opened = a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &keys_app());
        assert_eq!(opened.unwrap(), Approved::Settled);
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!(got["signer"], "keystore_module");
        assert_ne!(got["databaseKey"], "ab".repeat(32), "the key's, not the keystore's stored one");
        assert!(got["external"].as_str().unwrap().starts_with("wpkh(["));
        assert_eq!(a.covers("mock-segwit", "wallet_core"), Cover::Confirmed, "the app's terms, granted");
        assert_eq!(k.unlocks.len(), 1);
    }
}
