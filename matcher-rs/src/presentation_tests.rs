#[cfg(test)]
mod tests {
    use crate::presentation::*;
    use crate::credman::CredmanApi;
    use std::collections::HashMap;
    use std::ffi::{CStr};

    #[derive(Debug, Clone)]
    struct AddedEntry {
        cred_id: String,
        title: String,
        subtitle: Option<String>,
        fields: Vec<(String, Option<String>)>,
        metadata: String,
    }

    struct AddedPaymentEntry {
        cred_id: String,
        merchant_name: String,
        transaction_amount: String,
        additional_info: Option<String>,
    }

    struct FakeCredman {
        request_json: String,
        registry_json: String,
        wasm_version: u32,
        added_entries: Vec<AddedEntry>,
        added_payment_entries: Vec<AddedPaymentEntry>,
        added_sets: HashMap<String, i32>,
        added_inline: Vec<String>,
    }

    impl CredmanApi for FakeCredman {
        fn get_request_buffer(&self) -> Vec<u8> {
            self.request_json.as_bytes().to_vec()
        }
        fn get_registered_data(&self) -> Vec<u8> {
            let json_bytes = self.registry_json.as_bytes();
            let mut result = vec![0u8; 4];
            result[0..4].copy_from_slice(&4u32.to_le_bytes());
            result.extend_from_slice(json_bytes);
            result
        }
        fn get_wasm_version(&self) -> u32 { self.wasm_version }
        fn add_entry_set(&mut self, set_id: &CStr, set_length: i32) {
            self.added_sets.insert(set_id.to_str().unwrap().to_string(), set_length);
        }
        fn add_entry_to_set(&mut self, cred_id: &CStr, _icon: Option<&[u8]>, title: &CStr, subtitle: Option<&CStr>, _explainer: Option<&CStr>, metadata: &CStr, _set_id: &CStr, _set_index: i32) {
            self.added_entries.push(AddedEntry {
                cred_id: cred_id.to_str().unwrap().to_string(),
                title: title.to_str().unwrap().to_string(),
                subtitle: subtitle.map(|s| s.to_str().unwrap().to_string()),
                fields: Vec::new(),
                metadata: metadata.to_str().unwrap().to_string(),
            });
        }
        fn add_field_to_entry_set(&mut self, cred_id: &CStr, field_display_name: &CStr, field_display_value: Option<&CStr>, _set_id: &CStr, _set_index: i32) {
            if let Some(entry) = self.added_entries.iter_mut().find(|e| e.cred_id == cred_id.to_str().unwrap()) {
                entry.fields.push((
                    field_display_name.to_str().unwrap().to_string(),
                    field_display_value.map(|s| s.to_str().unwrap().to_string()),
                ));
            }
        }
        fn add_payment_entry_to_set_v2(&mut self, cred_id: &CStr, merchant_name: &CStr, _title: &CStr, _subtitle: Option<&CStr>, _icon: Option<&[u8]>, transaction_amount: &CStr, additional_info: Option<&CStr>, _metadata: &CStr, _set_id: &CStr, _set_index: i32) {
            self.added_payment_entries.push(AddedPaymentEntry {
                cred_id: cred_id.to_str().unwrap().to_string(),
                merchant_name: merchant_name.to_str().unwrap().to_string(),
                transaction_amount: transaction_amount.to_str().unwrap().to_string(),
                additional_info: additional_info.map(|s| s.to_str().unwrap().to_string()),
            });
        }
        fn add_inline_issuance_entry(&mut self, cred_id: &CStr, _icon: Option<&[u8]>, _title: Option<&CStr>, _subtitle: Option<&CStr>) {
            self.added_inline.push(cred_id.to_str().unwrap().to_string());
        }
        fn add_metadata_display_text_to_entry_set(&mut self, _cred_id: &CStr, _metadata_display_text: &CStr, _set_id: &CStr, _set_index: i32) {}
        fn add_string_id_entry(&mut self, _entry_id: &CStr, _icon: Option<&[u8]>, _title: Option<&CStr>, _subtitle: Option<&CStr>, _disclaimer: Option<&CStr>, _warning: Option<&CStr>) {}
    }

    fn create_fake_credman(request: &str, registry: &str) -> FakeCredman {
        FakeCredman {
            request_json: request.to_string(),
            registry_json: registry.to_string(),
            wasm_version: 6,
            added_entries: Vec::new(),
            added_payment_entries: Vec::new(),
            added_sets: HashMap::new(),
            added_inline: Vec::new(),
        }
    }

    #[test]
    fn test_mdoc_basic() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [
                        {
                            "id": "mdl_1",
                            "display": { "verification": { "title": "MDL" } },
                            "paths": {
                                "org.iso.18013.5.1": {
                                    "family_name": {
                                        "display": { "verification": { "display": "Last Name", "display_value": "Doe" } },
                                        "value": "Doe"
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "q1",
                            "format": "mso_mdoc",
                            "meta": { "doctype_value": "dl" },
                            "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].cred_id, "mdl_1");
    }

    #[test]
    fn test_sdjwt_basic() {
        let registry_json = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "vct": [{
                        "id": "s1",
                        "display": { "verification": { "title": "S" } },
                        "paths": {
                            "": {
                                "given_name": {
                                    "display": { "verification": { "display": "G", "display_value": "Jane" } },
                                    "value": "Jane"
                                }
                            }
                        }
                    }]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "c1",
                            "format": "dc+sd-jwt",
                            "meta": { "vct_values": ["vct"] },
                            "claims": [{"path": ["", "given_name"]}]
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].cred_id, "s1");
    }

    #[test]
    fn test_sdjwt_multi_vct() {
        let registry_json = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "v1": [{"id": "c1", "display": {"verification": {"title": "T1"}}, "paths": {}}],
                    "v2": [{"id": "c2", "display": {"verification": {"title": "T2"}}, "paths": {}}]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "q1",
                            "format": "dc+sd-jwt",
                            "meta": { "vct_values": ["v1", "v2"] }
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 2);
    }

    #[test]
    fn test_allowed_values_match() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{
                        "id": "m1",
                        "display": {"verification": {"title": "T"}},
                        "paths": {"org.iso.18013.5.1": {"over_18": {"display": {"verification": {"display": "D"}}, "value": "true"}}}
                    }]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "c1",
                            "format": "mso_mdoc",
                            "meta": {"doctype_value": "dl"},
                            "claims": [{"path": ["org.iso.18013.5.1", "over_18"], "values": ["true"]}]
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
    }

    #[test]
    fn test_allowed_values_no_match() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{
                        "id": "m1",
                        "display": {"verification": {"title": "T"}},
                        "paths": {"org.iso.18013.5.1": {"over_18": {"display": {"verification": {"display": "D"}}, "value": "true"}}}
                    }]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "c1",
                            "format": "mso_mdoc",
                            "meta": {"doctype_value": "dl"},
                            "claims": [{"path": ["org.iso.18013.5.1", "over_18"], "values": ["false"]}]
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 0);
    }

    #[test]
    fn test_claim_sets_or() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{
                        "id": "m1",
                        "display": {"verification": {"title": "T"}},
                        "paths": {"org.iso.18013.5.1": {"given_name": {"display": {"verification": {"display": "G", "display_value": "J"}}, "value": "J"}}}
                    }]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "c1",
                            "format": "mso_mdoc",
                            "meta": {"doctype_value": "dl"},
                            "claims": [
                                {"id": "f", "path": ["org.iso.18013.5.1", "family_name"]},
                                {"id": "g", "path": ["org.iso.18013.5.1", "given_name"]}
                            ],
                            "claim_sets": [["f"], ["g"]]
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].fields.len(), 1);
        assert_eq!(credman.added_entries[0].fields[0].0, "G");
    }

    #[test]
    fn test_credential_sets_basic() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{"id": "m1", "display": {"verification": {"title": "M"}}, "paths": {}}]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [
                            {"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}},
                            {"id": "c2", "format": "dc+sd-jwt", "meta": {"vct_values": ["vct"]}}
                        ],
                        "credential_sets": [{"options": [["c1"], ["c2"]]}]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].cred_id, "m1");
    }

    #[test]
    fn test_transaction_eudi() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{"id": "m1", "display": {"verification": {"title": "M"}}, "paths": {}}]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}}]
                    },
                    "transaction_data": ["eyJ0eXBlIjogInVybjpldWRpOnNjYTpwYXltZW50OjEiLCAicGF5bG9hZCI6IHsicGF5ZWUiOiB7Im5hbWUiOiAiTWVyY2hhbnQifSwgImFtb3VudCI6IDEwLjUsICJjdXJyZW5jeSI6ICJFVVIifSwgImNyZWRlbnRpYWxfaWRzIjogWyJjMSJdfQ"]
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_payment_entries.len(), 1);
        assert_eq!(credman.added_payment_entries[0].merchant_name, "Merchant");
        assert_eq!(credman.added_payment_entries[0].transaction_amount, "EUR 10.50");
    }

    #[test]
    fn test_signed_request_basic() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{"id": "m1", "display": {"verification": {"title": "M"}}, "paths": {}}]
                }
            }
        }"#;
        let payload = r#"{"dcql_query": {"credentials": [{"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}}]}}"#;
        let payload_b64 = "eyJkY3FsX3F1ZXJ5IjogeyJjcmVkZW50aWFscyI6IFt7ImlkIjogImMxIiwgImZvcm1hdCI6ICJtc29fbWRvYyIsICJtZXRhIjogeyJkb2N0eXBlX3ZhbHVlIjogImRsIn19XX19";
        let request_json = format!(r#"{{"requests": [{{"protocol": "openid4vp-v1-signed", "data": {{"request": "h.{}.s"}}}}]}}"#, payload_b64);
        let mut credman = create_fake_credman(&request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].cred_id, "m1");
    }

    #[test]
    fn test_inline_issuance_mdoc() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {},
                "issuance": { "mso_mdoc": [{"id": "p1", "supported": ["dl"], "title": "Prov"}] }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}}]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_inline.len(), 1);
        assert_eq!(credman.added_inline[0], "p1");
    }

    #[test]
    fn test_multiple_requests() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": { "dl": [{"id": "m1", "display": {"verification": {"title": "M"}}, "paths": {}}] },
                "dc+sd-jwt": { "vct": [{"id": "s1", "display": {"verification": {"title": "S"}}, "paths": {}}] }
            }
        }"#;
        let request_json = r#"{
            "requests": [
                {"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}}]}}},
                {"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "c2", "format": "dc+sd-jwt", "meta": {"vct_values": ["vct"]}}]}}}
            ]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 2);
    }

    #[test]
    fn test_complex_claim_sets() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "dl": [{
                        "id": "m1",
                        "display": {"verification": {"title": "M"}},
                        "paths": {
                            "ns": {
                                "a": {"display": {"verification": {"display": "A"}}, "value": "1"},
                                "b": {"display": {"verification": {"display": "B"}}, "value": "2"}
                            }
                        }
                    }]
                }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "c1",
                            "format": "mso_mdoc",
                            "meta": {"doctype_value": "dl"},
                            "claims": [
                                {"id": "ca", "path": ["ns", "a"]},
                                {"id": "cb", "path": ["ns", "b"]},
                                {"id": "cc", "path": ["ns", "c"]}
                            ],
                            "claim_sets": [ ["ca", "cb"], ["ca", "cc"] ]
                        }]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].fields.len(), 2); // Matched (a, b)
    }

    #[test]
    fn test_credential_sets_multiple_options() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": { "dl": [{"id": "m1", "display": {"verification": {"title": "M"}}, "paths": {}}] }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [
                            {"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}},
                            {"id": "c2", "format": "mso_mdoc", "meta": {"doctype_value": "id"}}
                        ],
                        "credential_sets": [
                            {"options": [ ["c1"], ["c2"] ]}
                        ]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].cred_id, "m1");
    }

    #[test]
    fn test_credential_sets_required_false() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": { "dl": [{"id": "m1", "display": {"verification": {"title": "M"}}, "paths": {}}] }
            }
        }"#;
        let request_json = r#"{
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [
                            {"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "dl"}},
                            {"id": "c2", "format": "mso_mdoc", "meta": {"doctype_value": "id"}}
                        ],
                        "credential_sets": [
                            {"required": true, "options": [ ["c1"] ]},
                            {"required": false, "options": [ ["c2"] ]}
                        ]
                    }
                }
            }]
        }"#;
        let mut credman = create_fake_credman(request_json, registry_json);
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 1);
        assert_eq!(credman.added_entries[0].cred_id, "m1");
    }
}
