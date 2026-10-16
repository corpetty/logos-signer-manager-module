//! Transient public offers shared by the two Keycard transports. No account files are copied.
use serde_json::{json, Value};

pub fn peer(name: &str) -> Option<&'static str> {
    match name { "keycard_module" => Some("keycard_shell_module"), "keycard_shell_module" => Some("keycard_module"), _ => None }
}

fn available(target: &Value, row: &Value) -> bool {
    let Some(root) = row["keycardAccount"]["masterKeyId"].as_str().filter(|s| s.len() == 64) else { return false };
    if target["transport"] == "shell" { return target["connected"] == true; }
    target["connections"].as_array().is_some_and(|connections| connections.iter().any(|c|
        c["masterKeyId"] == root && c["available"] == true
        && (row["family"] != "bitcoin_taproot" || c["taproot"] == true)))
}

pub fn inventory(mut own: Value, other: &Value) -> Value {
    let target = own["keycardRouting"].clone();
    let mut rows = own["accounts"].as_array().cloned().unwrap_or_default();
    for row in other["accounts"].as_array().into_iter().flatten() {
        if !row["keycardAccount"].is_object() { continue; }
        if rows.iter().any(|a| a["id"].as_str().zip(row["id"].as_str()).is_some_and(|(a,b)| a.eq_ignore_ascii_case(b))) { continue; }
        // Offered here, kept by the other transport.
        let mut routed = row.clone();
        routed["routed"] = true.into();
        rows.push(routed);
    }
    for row in &mut rows {
        if !row["keycardAccount"].is_object() { continue; }
        row["available"] = available(&target, row).into();
        let root = row["keycardAccount"]["masterKeyId"].clone();
        // The cards themselves, by name, before the generic device below replaces them.
        if row["origin"]["devices"].as_array().is_some_and(|d| !d.is_empty()) {
            row["origin"]["cards"] = row["origin"]["devices"].clone();
        }
        // The seed wallet is the source. A particular reader/Shell is chosen for each request.
        row["origin"]["devices"] = json!([{"kind":"keycard", "id":root, "name":"Keycard"}]);
    }
    own["accounts"] = rows.into();
    own
}

#[cfg(test)]
mod tests {
    use super::*;
    fn account(root: &str, family: &str) -> Value {
        json!({"id":"a", "family":family, "origin":{"phrase":{"name":"Savings"}},
            "keycardAccount":{"masterKeyId":root, "key":"public"}})
    }
    #[test]
    fn shared_offer_follows_current_reader_seed_and_capabilities() {
        let root = "1".repeat(64); let other = json!({"accounts":[account(&root,"evm")]});
        let own = json!({"accounts":[],"keycardRouting":{"transport":"reader","connections":[
            {"masterKeyId":root,"available":true,"taproot":false}]}});
        let got = inventory(own.clone(), &other);
        assert_eq!(got["accounts"][0]["available"], true);
        assert_eq!(got["accounts"][0]["routed"], true);
        assert_eq!(got["accounts"][0]["origin"]["phrase"]["name"], "Savings");
        assert_eq!(inventory(own.clone(), &json!({"accounts":[account(&"2".repeat(64),"evm")]}))["accounts"][0]["available"], false);
        assert_eq!(inventory(own, &json!({"accounts":[account(&root,"bitcoin_taproot")]}))["accounts"][0]["available"], false);
    }
    #[test]
    fn shell_is_a_candidate_without_remembering_the_account_or_seed() {
        let other = json!({"accounts":[account(&"1".repeat(64),"evm")]});
        for connected in [false,true] {
            let got=inventory(json!({"accounts":[],"keycardRouting":{"transport":"shell","connected":connected}}), &other);
            assert_eq!(got["accounts"][0]["available"],connected);
        }
        let legacy=json!({"accounts":[{"id":"old","family":"evm"}]});
        assert!(inventory(json!({"accounts":[]}), &legacy)["accounts"].as_array().unwrap().is_empty());
    }
    #[test]
    fn own_rows_keep_their_cards_and_are_not_routed() {
        let mut own_row = account(&"1".repeat(64), "evm");
        own_row["origin"]["devices"] = json!([{"kind":"keycard","id":"c1","name":"Daily"}]);
        let got = inventory(json!({"accounts":[own_row],"keycardRouting":{"transport":"reader","connections":[]}}), &json!({}));
        assert!(got["accounts"][0]["routed"].is_null());
        assert_eq!(got["accounts"][0]["origin"]["cards"][0]["name"], "Daily");
        assert_eq!(got["accounts"][0]["origin"]["devices"][0]["name"], "Keycard");
    }
}
