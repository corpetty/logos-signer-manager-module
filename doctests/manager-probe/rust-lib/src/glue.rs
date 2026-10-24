//! One headless module in three roles, so a signature can be asked for, shown, approved and
//! collected without a GUI: the keystore's custodian, a requester, and the manager's approver.

use serde_json::json;

pub trait ManagerProbeModule: Send + 'static {
    /// Import a raw private key into the keystore, as its custodian.
    fn import_key(&mut self, priv_hex: String, password: String) -> String;
    /// Make a Bitcoin wallet in the keystore, as its custodian: `import_bitcoin`'s params.
    fn import_bitcoin(&mut self, params_json: String) -> String;
    /// Derive an EVM account from a phrase into the keystore, as its custodian: `import_mnemonic`'s params.
    fn import_phrase(&mut self, params_json: String) -> String;
    /// Make an identity group in the keystore, as its custodian: `import_identity`'s params.
    fn import_identity(&mut self, params_json: String) -> String;
    /// An identity key for a purpose and a context, as the keystore's custodian: `derive_identity`'s params.
    fn derive_identity(&mut self, params_json: String) -> String;
    /// Unlock an account on terms, as the manager's custodian: `unlock`'s params.
    fn unlock(&mut self, params_json: String) -> String;
    /// Lock an account, or every one, as the manager's custodian: `lock`'s params.
    fn lock(&mut self, params_json: String) -> String;
    /// Every account with every signer holding it, as a named module reads it.
    fn roster(&mut self) -> String;
    /// The approver chose which holder signs a request on screen.
    fn choose(&mut self, handle: String, bundle_id: String, signer: String) -> String;
    /// Ask the manager for a signature, as a requester: `{ ok, handle, receipt, state }`.
    fn request(&mut self, intent_json: String) -> String;
    fn status(&mut self, handle: String, receipt: String) -> String;
    fn fetch(&mut self, handle: String, receipt: String) -> String;
    fn cancel(&mut self, handle: String, receipt: String) -> bool;
    /// The manager's approver: the queue, a request claimed for display, a yes and a no.
    fn pending(&mut self) -> String;
    fn acknowledge(&mut self, handle: String) -> String;
    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String;
    fn reject(&mut self, handle: String) -> bool;
    /// Ask the keystore to sign directly, past the manager: refused unless this were the manager.
    fn sign_direct(&mut self, request_json: String) -> String;
    /// Ask the manager to open a Bitcoin wallet for this module, as a requester.
    fn open(&mut self, params_json: String) -> String;
    /// The manager's custodian: the queue, a request shown, and the person's decision.
    fn queue(&mut self) -> String;
    fn show(&mut self, handle: String) -> String;
    fn decide(&mut self, params_json: String) -> String;
    /// An open wallet's descriptors again, and closing it, as the module it is open for.
    fn descriptors(&mut self, group: String) -> String;
    fn close(&mut self, group: String) -> String;
    /// The manager's events heard since the last call, as a listening requester hears them:
    /// `{ ok, events: [{ event, data }] }`.
    fn heard(&mut self) -> String;

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct ManagerProbeModuleImpl {
    heard: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

fn pass(reply: Result<String, impl std::fmt::Debug>) -> String {
    match reply {
        Ok(s) => s,
        Err(e) => json!({ "ok": false, "error": format!("{e:?}") }).to_string(),
    }
}

impl ManagerProbeModule for ManagerProbeModuleImpl {
    fn import_key(&mut self, priv_hex: String, password: String) -> String {
        pass(modules().keystore_module.import_private_key(&priv_hex, &password))
    }

    fn import_bitcoin(&mut self, params_json: String) -> String {
        pass(modules().keystore_module.import_bitcoin(&params_json))
    }

    fn import_phrase(&mut self, params_json: String) -> String {
        pass(modules().keystore_module.import_mnemonic(&params_json))
    }

    fn import_identity(&mut self, params_json: String) -> String {
        pass(modules().keystore_module.import_identity(&params_json))
    }

    fn derive_identity(&mut self, params_json: String) -> String {
        pass(modules().keystore_module.derive_identity(&params_json))
    }

    fn unlock(&mut self, params_json: String) -> String {
        pass(modules().signer_manager_module.unlock(&params_json))
    }

    fn lock(&mut self, params_json: String) -> String {
        pass(modules().signer_manager_module.lock(&params_json))
    }

    fn roster(&mut self) -> String {
        pass(modules().signer_manager_module.roster())
    }

    fn choose(&mut self, handle: String, bundle_id: String, signer: String) -> String {
        pass(modules().signer_manager_module.choose_signer(&handle, &bundle_id, &signer))
    }

    fn request(&mut self, intent_json: String) -> String {
        pass(modules().signer_manager_module.request_approval(&intent_json))
    }

    fn status(&mut self, handle: String, receipt: String) -> String {
        pass(modules().signer_manager_module.approval_status(&handle, &receipt))
    }

    fn fetch(&mut self, handle: String, receipt: String) -> String {
        pass(modules().signer_manager_module.fetch_result(&handle, &receipt))
    }

    fn cancel(&mut self, handle: String, receipt: String) -> bool {
        modules().signer_manager_module.cancel_approval(&handle, &receipt).unwrap_or(false)
    }

    fn pending(&mut self) -> String {
        pass(modules().signer_manager_module.pending())
    }

    fn acknowledge(&mut self, handle: String) -> String {
        pass(modules().signer_manager_module.acknowledge(&handle))
    }

    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String {
        pass(modules().signer_manager_module.approve(&handle, &bundle_id, &password))
    }

    fn reject(&mut self, handle: String) -> bool {
        modules().signer_manager_module.reject(&handle).unwrap_or(false)
    }

    fn sign_direct(&mut self, request_json: String) -> String {
        pass(modules().keystore_module.sign(&request_json))
    }

    fn open(&mut self, params_json: String) -> String {
        pass(modules().signer_manager_module.request_open(&params_json))
    }

    fn queue(&mut self) -> String {
        pass(modules().signer_manager_module.access_requests())
    }

    fn show(&mut self, handle: String) -> String {
        pass(modules().signer_manager_module.acknowledge_access(&handle))
    }

    fn decide(&mut self, params_json: String) -> String {
        pass(modules().signer_manager_module.approve_access(&params_json))
    }

    fn descriptors(&mut self, group: String) -> String {
        pass(modules().signer_manager_module.account_descriptors(&group))
    }

    fn close(&mut self, group: String) -> String {
        pass(modules().signer_manager_module.close_account(&json!({ "group": group }).to_string()))
    }

    fn heard(&mut self) -> String {
        let events = std::mem::take(&mut *self.heard.lock().unwrap());
        json!({ "ok": true, "events": events }).to_string()
    }

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {
        // Off the dispatch thread: subscribing may wait on the manager.
        let heard = self.heard.clone();
        std::thread::spawn(move || {
            let mut m = modules();
            let subs = [m.signer_manager_module.on_approval_settled(), m.signer_manager_module.on_accounts_changed()];
            for sub in subs.into_iter().flatten() {
                let heard = heard.clone();
                std::thread::spawn(move || {
                    for ev in sub {
                        heard.lock().unwrap().push(json!({ "event": ev.event, "data": ev.data }));
                    }
                });
            }
        });
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<ManagerProbeModuleImpl>();
}
