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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
