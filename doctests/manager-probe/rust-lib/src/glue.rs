//! One headless module in three roles, so a signature can be asked for, shown, approved and
//! collected without a GUI: the keystore's custodian, a requester, and the manager's approver.

use serde_json::json;

pub trait ManagerProbeModule: Send + 'static {
    /// Import a raw private key into the keystore, as its custodian.
    fn import_key(&mut self, priv_hex: String, password: String) -> String;
    /// Make a Bitcoin wallet in the keystore, as its custodian: `import_bitcoin`'s params.
    fn import_bitcoin(&mut self, params_json: String) -> String;
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

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct ManagerProbeModuleImpl;

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
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<ManagerProbeModuleImpl>();
}
