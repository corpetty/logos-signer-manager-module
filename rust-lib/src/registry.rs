//! The signers the manager consults, in order, and the accounts they offer. A signer is anything
//! behind `logos.signer/1`: a module over IPC in production, a mock or a test double in tests.

use std::time::{Duration, Instant};

use logos_signer_interface::{Account, Family, Signer, SignerInfo};

use crate::error::{ManagerError, Result};

/// How long a signer that didn't answer is left alone. A module that isn't installed, such as a
/// default device module, costs the transport's wait of about a second at each ask.
const RESTING: Duration = Duration::from_secs(30);

struct Entry {
    name: String,
    signer: Box<dyn Signer + Send>,
    info: Option<SignerInfo>,
    accounts: Option<Vec<Account>>,
    /// When it last didn't answer.
    missed: Option<Instant>,
}

/// An account and the signer that holds it.
#[derive(Clone, Debug)]
pub struct Found {
    pub signer: usize,
    pub name: String,
    pub info: SignerInfo,
    pub account: Account,
}

#[derive(Default)]
pub struct Registry {
    entries: Vec<Entry>,
}

fn same_id(a: &Account, id: &str) -> bool {
    match a.family {
        Family::Evm => a.id.eq_ignore_ascii_case(id.trim()),
        _ => a.id == id.trim(),
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Signers are consulted in the order added: when two offer the same account, the first holds it.
    pub fn add(&mut self, name: impl Into<String>, signer: Box<dyn Signer + Send>) {
        self.entries.push(Entry { name: name.into(), signer, info: None, accounts: None, missed: None });
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// Drop these signers' listings and ask them again, resting or not: they said their accounts
    /// changed. Every other signer keeps its listing, and one that is resting keeps resting.
    pub fn forget(&mut self, names: &[String]) {
        for e in self.entries.iter_mut().filter(|e| names.contains(&e.name)) {
            e.info = None;
            e.accounts = None;
            e.missed = None;
        }
    }

    /// Read every listing again, except from a signer still resting: it was asked moments ago.
    fn reread(&mut self) {
        for e in &mut self.entries {
            e.info = None;
            e.accounts = None;
        }
    }

    /// Read a signer's info and accounts once. One that doesn't answer offers nothing, and rests.
    fn load(&mut self, i: usize) {
        let e = &mut self.entries[i];
        if e.info.is_none() {
            if e.missed.is_some_and(|t| t.elapsed() < RESTING) {
                return;
            }
            e.info = e.signer.info_checked();
            e.missed = e.info.is_none().then(Instant::now);
        }
        if e.accounts.is_none() && e.info.is_some() {
            e.accounts = e.signer.accounts().ok();
        }
    }

    fn lookup(&self, id: &str) -> Option<Found> {
        for (i, e) in self.entries.iter().enumerate() {
            let (Some(info), Some(accounts)) = (&e.info, &e.accounts) else { continue };
            if let Some(a) = accounts.iter().find(|a| same_id(a, id)) {
                return Some(Found { signer: i, name: e.name.clone(), info: info.clone(), account: a.clone() });
            }
        }
        None
    }

    /// The account `id` and its signer, reading the signers again once if it isn't known.
    pub fn find(&mut self, id: &str) -> Result<Found> {
        for i in 0..self.entries.len() {
            self.load(i);
        }
        if let Some(f) = self.lookup(id) {
            return Ok(f);
        }
        self.reread();
        for i in 0..self.entries.len() {
            self.load(i);
        }
        self.lookup(id).ok_or_else(|| ManagerError::NotFound(format!("no signer offers the account {}", id.trim())))
    }

    /// Every account, each under the first signer that offers it.
    pub fn accounts(&mut self) -> Vec<(String, Account)> {
        let mut out: Vec<(String, Account)> = Vec::new();
        for i in 0..self.entries.len() {
            self.load(i);
            let e = &self.entries[i];
            for a in e.accounts.iter().flatten() {
                if !out.iter().any(|(_, seen)| same_id(seen, &a.id)) {
                    out.push((e.name.clone(), a.clone()));
                }
            }
        }
        out
    }

    /// Each signer's info, or `None` for one that doesn't answer.
    pub fn infos(&mut self) -> Vec<(String, Option<SignerInfo>)> {
        (0..self.entries.len())
            .map(|i| {
                self.load(i);
                (self.entries[i].name.clone(), self.entries[i].info.clone())
            })
            .collect()
    }

    pub fn signer(&mut self, i: usize) -> &mut (dyn Signer + Send) {
        self.entries[i].signer.as_mut()
    }
}

/// `info` is infallible on the trait; a signer over IPC reports an unreachable module as an empty interface.
trait InfoChecked {
    fn info_checked(&self) -> Option<SignerInfo>;
}

impl<S: Signer + ?Sized> InfoChecked for S {
    fn info_checked(&self) -> Option<SignerInfo> {
        let info = self.info();
        (info.interface == logos_signer_interface::INTERFACE).then_some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Collects, JobStatus, SignRequest, Signature};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    /// A module that isn't installed: it never answers, and counts the asks.
    struct Absent(Arc<AtomicUsize>);

    impl Signer for Absent {
        fn info(&self) -> SignerInfo {
            self.0.fetch_add(1, SeqCst);
            SignerInfo {
                interface: String::new(),
                kind: String::new(),
                model: String::new(),
                families: Vec::new(),
                request_kinds: Vec::new(),
                shows_request: false,
                collects: Collects::Nothing,
            }
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
            unreachable!("asked only after it answers")
        }
        fn sign(&mut self, _: SignRequest) -> logos_signer_interface::Result<String> {
            unreachable!()
        }
        fn status(&mut self, _: &str) -> logos_signer_interface::Result<JobStatus> {
            unreachable!()
        }
        fn result(&mut self, _: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            unreachable!()
        }
        fn cancel(&mut self, _: &str) -> logos_signer_interface::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn a_signer_that_does_not_answer_rests_until_it_announces_a_change_itself() {
        let asks = Arc::new(AtomicUsize::new(0));
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions::default())));
        r.add("keycard_module", Box::new(Absent(asks.clone())));
        assert_eq!(r.accounts().len(), 3);
        assert_eq!(r.accounts().len(), 3);
        assert!(r.find("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266").is_ok());
        assert_eq!(asks.load(SeqCst), 1, "asked once, then left alone");
        // The keystore announces at every import; each cost a second per absent module, under the lock.
        r.forget(&["keystore_module".to_string()]);
        r.accounts();
        assert!(r.find("0x0000000000000000000000000000000000000001").is_err());
        assert_eq!(asks.load(SeqCst), 1, "another signer's news, and an unknown account, leave it resting");
        r.forget(&["keycard_module".to_string()]);
        r.accounts();
        assert_eq!(asks.load(SeqCst), 2, "asked again once it announces a change itself");
    }

    #[test]
    fn an_account_is_found_under_the_first_signer_that_offers_it() {
        let mut r = Registry::new();
        r.add("first", Box::new(MockSigner::new(MockOptions::default())));
        r.add("second", Box::new(MockSigner::new(MockOptions::default())));
        let f = r.find("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266").unwrap();
        assert_eq!(f.name, "first");
        assert_eq!(r.accounts().len(), 3, "the second signer's copies are not offered twice");
        assert!(r.find("0x0000000000000000000000000000000000000001").is_err());
        assert!(r.find("MOCK-SEGWIT").is_err(), "a Bitcoin id is exact");
    }
}
