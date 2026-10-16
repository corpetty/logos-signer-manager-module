//! Optional display metadata, joined only to the account selected by the registry.
use serde_json::Value;

pub fn attach(inventory: &mut Value, provider: &str, source: &Value) {
    if source["ok"] != true { return; }
    let Some(source) = source["accounts"].as_array() else { return; };
    let Some(rows) = inventory["accounts"].as_array_mut() else { return; };
    for row in rows {
        if row["signer"].as_str() != Some(provider) { continue; }
        let Some(id) = row["id"].as_str() else { continue; };
        let evm = row["family"] == "evm";
        if let Some(origin) = source.iter().find(|a| {
            a["family"] == row["family"] && a["id"].as_str().is_some_and(|other|
                if evm { other.eq_ignore_ascii_case(id) } else { other == id })
        }).and_then(|a| a.get("origin")).filter(|o| o.is_object()) {
            row["origin"] = origin.clone();
        }
    }
}

/// The `origin` a signer's last listing gave one of its accounts.
pub fn of(snapshots: &std::collections::BTreeMap<String, Value>, signer: &str, account: &logos_signer_interface::Account) -> Option<Value> {
    let evm = account.family == logos_signer_interface::Family::Evm;
    snapshots.get(signer)?["accounts"]
        .as_array()?
        .iter()
        .find(|a| a["id"].as_str().is_some_and(|id| if evm { id.eq_ignore_ascii_case(&account.id) } else { id == account.id }))?
        .get("origin")
        .filter(|o| o.is_object())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_origin_is_read_off_the_signer_that_listed_the_account() {
        let snapshots = [("keycard_module".to_string(), json!({"accounts":[
            {"id":"0xab","family":"evm","origin":{"phrase":{"name":"Main"}}}]}))].into_iter().collect();
        let mut a: logos_signer_interface::Account = serde_json::from_value(json!({
            "id":"0xAB","family":"evm","address":"0xAB","available":true})).unwrap();
        assert_eq!(of(&snapshots, "keycard_module", &a).unwrap()["phrase"]["name"], "Main");
        assert!(of(&snapshots, "keystore_module", &a).is_none());
        a.id = "0xcd".into();
        assert!(of(&snapshots, "keycard_module", &a).is_none());
    }
    #[test]
    fn origin_follows_selected_provider_not_duplicate_address() {
        let mut inventory = json!({"accounts":[{"id":"0xAb", "family":"evm", "signer":"keystore_module"}]});
        let source = json!({"ok":true,"accounts":[{"id":"0xab","family":"evm","origin":{"phrase":{"id":"seed"}}}]});
        attach(&mut inventory, "keycard_module", &source);
        assert!(inventory["accounts"][0]["origin"].is_null());
        attach(&mut inventory, "keystore_module", &source);
        assert_eq!(inventory["accounts"][0]["origin"]["phrase"]["id"], "seed");
        let before = inventory.clone();
        attach(&mut inventory, "keystore_module", &json!({"ok":false,"accounts":[]}));
        assert_eq!(inventory, before);
    }
}
