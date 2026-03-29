use crate::credman::CredmanApi;
use crate::dcql::*;
use crate::dcql_engine::*;
use crate::openid4vp::*;
use nanoserde::{DeJson, SerJson};
use std::collections::HashMap;
use std::ffi::CString;

#[derive(SerJson, Default)]
pub struct MatchedMetadata {
    pub claims: Vec<Vec<String>>,
    pub dc_request_index: usize,
    pub dcql_cred_id: String,
    pub dcql_credential_set_index: String,
    pub dcql_option_index: String,
}

fn get_icon_bytes<'a>(icon: &RegistryIcon, data: &'a [u8]) -> Option<&'a [u8]> {
    if icon.length == 0 {
        None
    } else {
        data.get(icon.start..icon.start + icon.length)
    }
}

fn report_matched_credential(
    credman: &mut impl CredmanApi,
    info: &MatchedCredentialInfo,
    query_cred_id: &str,
    doc_idx: i32,
    req_idx: usize,
    set_id: &str,
    dcql_set_idx: &str,
    dcql_option_idx: &str,
    registered_data: &[u8],
    transaction_data: &Option<TransactionData>,
    wasm_version: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = MatchedMetadata {
        claims: info.matched_claim_metadata.clone(),
        dc_request_index: req_idx,
        dcql_cred_id: query_cred_id.to_string(),
        dcql_credential_set_index: dcql_set_idx.to_string(),
        dcql_option_index: dcql_option_idx.to_string(),
    };
    let metadata_json = SerJson::serialize_json(&metadata);
    let metadata_cstr = CString::new(metadata_json)?;
    let set_id_cstr = CString::new(set_id)?;
    let entry_id_cstr = CString::new(info.id.clone())?;

    let mut is_payment = false;
    if let Some(td) = transaction_data {
        if td.credential_ids.iter().any(|id| id == query_cred_id) {
            is_payment = true;
            let merchant_name = if !td.merchant_name.is_empty() {
                &td.merchant_name
            } else if !td.payee_name.is_empty() {
                &td.payee_name
            } else {
                &td.payload.payee.name
            };

            let amount = if !td.amount.is_empty() {
                td.amount.clone()
            } else if !td.payment_amount.is_empty() {
                format!("{} {}", td.payment_currency, td.payment_amount)
            } else if !td.payload.amount_display.is_empty() {
                td.payload.amount_display.clone()
            } else {
                format!("{} {}", td.payload.currency, td.payload.amount)
            };

            let merchant_name_cstr = CString::new(merchant_name.clone())?;
            let amount_cstr = CString::new(amount)?;
            let title_cstr = CString::new(info.display.verification.title.clone())?;
            let subtitle_cstr = CString::new(info.display.verification.subtitle.clone())?;
            let icon_bytes = get_icon_bytes(&info.display.verification.icon, registered_data);
            let additional_info_cstr = CString::new(td.additional_info.clone())?;

            credman.add_payment_entry_to_set_v2(
                &entry_id_cstr,
                &merchant_name_cstr,
                &title_cstr,
                &subtitle_cstr,
                icon_bytes,
                &amount_cstr,
                None, // bank_icon
                None, // provider_icon
                &additional_info_cstr,
                &metadata_cstr,
                &set_id_cstr,
                doc_idx,
            );
        }
    }

    if !is_payment {
        let title_cstr = CString::new(info.display.verification.title.clone())?;
        let subtitle_cstr = CString::new(info.display.verification.subtitle.clone())?;
        let disclaimer_cstr = CString::new(info.display.verification.explainer.clone())?;
        let warning = if !info.display.verification.warning.is_empty() {
            Some(CString::new(info.display.verification.warning.clone())?)
        } else {
            None
        };
        let icon_bytes = get_icon_bytes(&info.display.verification.icon, registered_data);

        credman.add_entry_to_set(
            &entry_id_cstr,
            icon_bytes,
            &title_cstr,
            &subtitle_cstr,
            &disclaimer_cstr,
            warning.as_deref(),
            &metadata_cstr,
            &set_id_cstr,
            doc_idx,
        );

        if wasm_version >= 5 && !info.display.verification.metadata_display_text.is_empty() {
            let meta_display_cstr =
                CString::new(info.display.verification.metadata_display_text.clone())?;
            credman.add_metadata_display_text_to_entry_set(
                &entry_id_cstr,
                &meta_display_cstr,
                &set_id_cstr,
                doc_idx,
            );
        }

        for (name, _value) in info
            .matched_claim_names
            .iter()
            .zip(info.matched_claim_metadata.iter())
        {
            let field_name_cstr = CString::new(name.display_name.clone())?;
            let field_value_cstr = if !name.display_value.is_empty() {
                Some(CString::new(name.display_value.clone())?)
            } else {
                None
            };
            credman.add_field_to_entry_set(
                &entry_id_cstr,
                &field_name_cstr,
                field_value_cstr.as_deref(),
                &set_id_cstr,
                doc_idx,
            );
        }
    }

    Ok(())
}

fn report_set_recursive(
    credman: &mut impl CredmanApi,
    matched_sets: &[Vec<MatchedOption>],
    curr_set_idx: usize,
    curr_doc_idx: i32,
    req_idx: usize,
    base_set_id: &str,
    matched_docs: &HashMap<String, MatchedQueryCredential>,
    registered_data: &[u8],
    transaction_data: &Option<TransactionData>,
    wasm_version: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if curr_set_idx >= matched_sets.len() {
        return Ok(());
    }

    for option in &matched_sets[curr_set_idx] {
        let mut new_doc_idx = curr_doc_idx;
        let set_id = if base_set_id.is_empty() {
            format!(
                "req:{};set:{};option:{}",
                req_idx, option.set_id, option.option_id
            )
        } else {
            base_set_id.to_string()
        };

        for q_id in &option.matched_credential_ids {
            if let Some(matched_query_cred) = matched_docs.get(q_id) {
                for info in &matched_query_cred.matched {
                    report_matched_credential(
                        credman,
                        info,
                        q_id,
                        new_doc_idx,
                        req_idx,
                        &set_id,
                        &option.set_id,
                        &option.option_id,
                        registered_data,
                        transaction_data,
                        wasm_version,
                    )?;
                    new_doc_idx += 1;
                }
            }
        }

        report_set_recursive(
            credman,
            matched_sets,
            curr_set_idx + 1,
            new_doc_idx,
            req_idx,
            &set_id,
            matched_docs,
            registered_data,
            transaction_data,
            wasm_version,
        )?;
    }

    Ok(())
}

fn report_set_length_recursive(
    credman: &mut impl CredmanApi,
    set_id: &str,
    curr_len: i32,
    curr_set_idx: usize,
    matched_sets: &[Vec<MatchedOption>],
) -> Result<(), Box<dyn std::error::Error>> {
    if curr_set_idx >= matched_sets.len() {
        let set_id_cstr = CString::new(set_id)?;
        credman.add_entry_set(&set_id_cstr, curr_len);
        return Ok(());
    }

    for option in &matched_sets[curr_set_idx] {
        report_set_length_recursive(
            credman,
            set_id,
            curr_len + option.matched_credential_ids.len() as i32,
            curr_set_idx + 1,
            matched_sets,
        )?;
    }
    Ok(())
}

pub fn presentation_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    let registered_data = credman.get_registered_data();
    if registered_data.len() < 4 {
        return Err("Invalid registered data".into());
    }
    let json_offset = u32::from_le_bytes(registered_data[0..4].try_into()?) as usize;
    let store: CredentialStore =
        DeJson::deserialize_json(std::str::from_utf8(&registered_data[json_offset..])?)?;

    let request_buffer = credman.get_request_buffer();
    let request_envelope: DigitalPresentationRequest =
        DeJson::deserialize_json(std::str::from_utf8(&request_buffer)?)?;

    let wasm_version = credman.get_wasm_version();

    let all_requests = if !request_envelope.requests.is_empty() {
        &request_envelope.requests
    } else {
        &request_envelope.providers
    };

    for (i, req) in all_requests.iter().enumerate() {
        if req.protocol != "openid4vp-v1-unsigned" && req.protocol != "openid4vp-v1-signed" {
            continue;
        }

        let data = if req.protocol == "openid4vp-v1-signed" {
            let payload = extract_signed_request_payload(&req.data.signed_request)?;
            DeJson::deserialize_json(&payload)?
        } else if !req.legacy_request_data.is_empty() {
            DeJson::deserialize_json(&req.legacy_request_data)?
        } else {
            req.data.clone()
        };

        let mut transaction_data = None;
        if !data.transaction_data.is_empty() {
            // Support first transaction data for now
            transaction_data = Some(decode_transaction_data(&data.transaction_data[0])?);
        }

        let match_result = dcql_query(&data.dcql_query, &store.credentials);

        if !match_result.matched_credential_sets.is_empty() {
            if wasm_version > 1 {
                if data.dcql_query.credential_sets.is_empty() {
                    let set_id = format!("req:{};null", i);
                    let set_id_cstr = CString::new(set_id)?;
                    let len = data.dcql_query.credentials.len() as i32;
                    credman.add_entry_set(&set_id_cstr, len);
                } else {
                    for option in &match_result.matched_credential_sets[0] {
                        let set_id = format!(
                            "req:{};set:{};option:{}",
                            i, option.set_id, option.option_id
                        );
                        report_set_length_recursive(
                            credman,
                            &set_id,
                            option.matched_credential_ids.len() as i32,
                            1,
                            &match_result.matched_credential_sets,
                        )?;
                    }
                }
            }

            // Report sets
            report_set_recursive(
                credman,
                &match_result.matched_credential_sets,
                0,
                0,
                i,
                "",
                &match_result.matched_credentials,
                &registered_data,
                &transaction_data,
                wasm_version,
            )?;
        }

        if let Some(issuance) = match_result.inline_issuance {
            let id_cstr = CString::new(issuance.id)?;
            let title_cstr = CString::new(issuance.title)?;
            let subtitle_cstr = CString::new(issuance.subtitle)?;
            let icon_bytes = get_icon_bytes(&issuance.icon, &registered_data);
            credman.add_inline_issuance_entry(&id_cstr, icon_bytes, &title_cstr, &subtitle_cstr);
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ffi::CStr;

    #[derive(Default)]
    struct FakeCredman {
        request_json: String,
        registered_json: String,
        added_sets: Vec<(String, i32)>,
        added_entries_to_set: Vec<String>, // format "set_id:cred_id:metadata"
        added_fields: Vec<String>,         // format "cred_id:field_name:field_value"
        added_payments: Vec<String>,       // format "merchant:amount:info"
        added_issuance: Vec<String>,       // format "id:title"
        added_metadata_text: Vec<String>,  // format "id:text"
        wasm_version: u32,
    }

    impl CredmanApi for FakeCredman {
        fn get_request_buffer(&self) -> Vec<u8> {
            self.request_json.as_bytes().to_vec()
        }
        fn get_registered_data(&self) -> Vec<u8> {
            let mut result = vec![0u8; 4];
            result[0] = 4; // offset
            result.extend_from_slice(self.registered_json.as_bytes());
            result
        }
        fn add_string_id_entry(
            &mut self,
            _: &CStr,
            _: Option<&[u8]>,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: Option<&CStr>,
        ) {
        }
        fn add_entry_set(&mut self, set_id: &CStr, set_length: i32) {
            self.added_sets
                .push((set_id.to_str().unwrap().to_string(), set_length));
        }
        fn add_entry_to_set(
            &mut self,
            cred_id: &CStr,
            _: Option<&[u8]>,
            _: &CStr,
            _: &CStr,
            _: &CStr,
            _: Option<&CStr>,
            metadata: &CStr,
            set_id: &CStr,
            _: i32,
        ) {
            self.added_entries_to_set.push(format!(
                "{}:{}:{}",
                set_id.to_str().unwrap(),
                cred_id.to_str().unwrap(),
                metadata.to_str().unwrap()
            ));
        }
        fn add_field_to_entry_set(
            &mut self,
            cred_id: &CStr,
            field_name: &CStr,
            field_value: Option<&CStr>,
            _: &CStr,
            _: i32,
        ) {
            self.added_fields.push(format!(
                "{}:{}:{}",
                cred_id.to_str().unwrap(),
                field_name.to_str().unwrap(),
                field_value.map_or("", |v| v.to_str().unwrap())
            ));
        }
        fn add_payment_entry_to_set_v2(
            &mut self,
            _: &CStr,
            merchant_name: &CStr,
            _: &CStr,
            _: &CStr,
            _: Option<&[u8]>,
            transaction_amount: &CStr,
            _: Option<&[u8]>,
            _: Option<&[u8]>,
            additional_info: &CStr,
            _: &CStr,
            _: &CStr,
            _: i32,
        ) {
            self.added_payments.push(format!(
                "{}:{}:{}",
                merchant_name.to_str().unwrap(),
                transaction_amount.to_str().unwrap(),
                additional_info.to_str().unwrap()
            ));
        }
        fn add_inline_issuance_entry(
            &mut self,
            id: &CStr,
            _: Option<&[u8]>,
            title: &CStr,
            _: &CStr,
        ) {
            self.added_issuance.push(format!(
                "{}:{}",
                id.to_str().unwrap(),
                title.to_str().unwrap()
            ));
        }
        fn get_wasm_version(&self) -> u32 {
            self.wasm_version
        }
        fn set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(
            &mut self,
            _: &CStr,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: &CStr,
            _: i32,
        ) {
        }
        fn add_metadata_display_text_to_entry_set(
            &mut self,
            cred_id: &CStr,
            text: &CStr,
            _: &CStr,
            _: i32,
        ) {
            self.added_metadata_text.push(format!(
                "{}:{}",
                cred_id.to_str().unwrap(),
                text.to_str().unwrap()
            ));
        }
    }

    #[test]
    fn test_mdoc_match() {
        let mut credman = FakeCredman {
            request_json: r#"{
                "requests": [
                    {
                        "protocol": "openid4vp-v1-unsigned",
                        "data": {
                            "dcql_query": {
                                "credentials": [
                                    {
                                        "id": "mDL",
                                        "format": "mso_mdoc",
                                        "meta": {
                                            "doctype_value": "org.iso.18013.5.1.mDL"
                                        },
                                        "claims": [
                                            {
                                                "id": "given_name",
                                                "path": ["org.iso.18013.5.1", "given_name"]
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                ]
            }"#
            .to_string(),
            registered_json: r#"{
                "credentials": {
                    "mso_mdoc": {
                        "org.iso.18013.5.1.mDL": [
                            {
                                "id": "cred1",
                                "display": {
                                    "verification": {
                                        "title": "MDL",
                                        "subtitle": "Subtitle",
                                        "icon": {"start": 0, "length": 0}
                                    }
                                },
                                "paths": {
                                    "org.iso.18013.5.1": {
                                        "given_name": {
                                            "value": "Bruce",
                                            "display": {
                                                "verification": {
                                                    "display": "Given Name"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            }"#
            .to_string(),
            ..Default::default()
        };

        presentation_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries_to_set.len(), 1);
        assert!(credman.added_entries_to_set[0].contains("cred1"));
        assert!(credman
            .added_fields
            .iter()
            .any(|f| f.contains("Given Name")));
    }

    #[test]
    fn test_sd_jwt_match() {
        let mut credman = FakeCredman {
            request_json: r#"{
                "requests": [
                    {
                        "protocol": "openid4vp-v1-unsigned",
                        "data": {
                            "dcql_query": {
                                "credentials": [
                                    {
                                        "id": "sd_jwt_cred",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["https://credentials.example.com/identity_credential"]
                                        },
                                        "claims": [{"id": "family_name", "path": ["family_name"]}]
                                    }
                                ]
                            }
                        }
                    }
                ]
            }"#
            .to_string(),
            registered_json: r#"{
                "credentials": {
                    "dc+sd-jwt": {
                        "https://credentials.example.com/identity_credential": [
                            {
                                "id": "sd_cred_1",
                                "display": {
                                    "verification": {
                                        "title": "SD-JWT",
                                        "subtitle": "Subtitle",
                                        "icon": {"start": 0, "length": 0}
                                    }
                                },
                                "paths": {
                                    "family_name": {
                                        "value": "Wayne",
                                        "display": {"verification": {"display": "Family Name"}}
                                    }
                                }
                            }
                        ]
                    }
                }
            }"#
            .to_string(),
            ..Default::default()
        };

        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries_to_set.len(), 1);
        assert!(credman.added_entries_to_set[0].contains("sd_cred_1"));
    }

    #[test]
    fn test_claim_value_match() {
        let mut credman = FakeCredman {
            request_json: r#"{
                "requests": [
                    {
                        "protocol": "openid4vp-v1-unsigned",
                        "data": {
                            "dcql_query": {
                                "credentials": [
                                    {
                                        "id": "mDL",
                                        "format": "mso_mdoc",
                                        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                                        "claims": [
                                            {
                                                "id": "age_over_21",
                                                "path": ["org.iso.18013.5.1", "age_over_21"],
                                                "values": ["true"]
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                ]
            }"#
            .to_string(),
            registered_json: r#"{
                "credentials": {
                    "mso_mdoc": {
                        "org.iso.18013.5.1.mDL": [
                            {
                                "id": "cred_true",
                                "display": {"verification": {"title": "T", "subtitle": "S", "icon": {"start": 0, "length": 0}}},
                                "paths": {
                                    "org.iso.18013.5.1": {
                                        "age_over_21": {
                                            "value": "true",
                                            "display": {"verification": {"display": "Age"}}
                                        }
                                    }
                                }
                            },
                            {
                                "id": "cred_false",
                                "display": {"verification": {"title": "F", "subtitle": "S", "icon": {"start": 0, "length": 0}}},
                                "paths": {
                                    "org.iso.18013.5.1": {
                                        "age_over_21": {
                                            "value": "false",
                                            "display": {"verification": {"display": "Age"}}
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            }"#
            .to_string(),
            ..Default::default()
        };

        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries_to_set.len(), 1);
        assert!(credman.added_entries_to_set[0].contains("cred_true"));
    }

    #[test]
    fn test_credential_sets() {
        let mut credman = FakeCredman {
            request_json: r#"{
                "requests": [
                    {
                        "protocol": "openid4vp-v1-unsigned",
                        "data": {
                            "dcql_query": {
                                "credentials": [
                                    {
                                        "id": "cred_a",
                                        "format": "mso_mdoc",
                                        "meta": {"doctype_value": "type_a"}
                                    },
                                    {
                                        "id": "cred_b",
                                        "format": "mso_mdoc",
                                        "meta": {"doctype_value": "type_b"}
                                    }
                                ],
                                "credential_sets": [
                                    {
                                        "options": [["cred_a"], ["cred_b"]],
                                        "required": true
                                    }
                                ]
                            }
                        }
                    }
                ]
            }"#
            .to_string(),
            registered_json: r#"{
                "credentials": {
                    "mso_mdoc": {
                        "type_a": [],
                        "type_b": [
                            {
                                "id": "actual_b",
                                "display": {"verification": {"title": "B", "subtitle": "S", "icon": {"start": 0, "length": 0}}},
                                "paths": {}
                            }
                        ]
                    }
                }
            }"#
            .to_string(),
            ..Default::default()
        };

        presentation_main(&mut credman).unwrap();
        // Should match option ["cred_b"] because ["cred_a"] is not available
        assert_eq!(credman.added_entries_to_set.len(), 1);
        assert!(credman.added_entries_to_set[0].contains("actual_b"));
        assert!(credman.added_entries_to_set[0].contains("option:1"));
    }

    #[test]
    fn test_payment_transaction_data() {
        let mut credman = FakeCredman {
            request_json: r#"{
                "requests": [
                    {
                        "protocol": "openid4vp-v1-unsigned",
                        "data": {
                            "dcql_query": {
                                "credentials": [{"id": "pay_cred", "format": "mso_mdoc", "meta": {"doctype_value": "pay_type"}}]
                            },
                            "transaction_data": ["eyJ0eXBlIjogInVybjpldWRpOnNjYTpwYXltZW50OjEiLCAicGF5bG9hZCI6IHsicGF5ZWUiOiB7Im5hbWUiOiAiTWVyY2hhbnQgWCJ9LCAiYW1vdW50X2Rpc3BsYXkiOiAiRVVSIDEwLjAwIn0sICJjcmVkZW50aWFsX2lkcyI6IFsicGF5X2NyZWQiXX0"]
                        }
                    }
                ]
            }"#.to_string(),
            registered_json: r#"{
                "credentials": {
                    "mso_mdoc": {
                        "pay_type": [
                            {
                                "id": "card_1",
                                "display": {"verification": {"title": "Card", "subtitle": "S", "icon": {"start": 0, "length": 0}}},
                                "paths": {}
                            }
                        ]
                    }
                }
            }"#.to_string(),
            ..Default::default()
        };

        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_payments.len(), 1);
        assert!(credman.added_payments[0].contains("Merchant X"));
        assert!(credman.added_payments[0].contains("EUR 10.00"));
    }

    #[test]
    fn test_signed_request() {
        // Payload: {"dcql_query": {"credentials": [{"id": "c1", "format": "mso_mdoc", "meta": {"doctype_value": "t1"}}]}}
        let payload_b64 = "eyJkY3FsX3F1ZXJ5IjogeyJjcmVkZW50aWFscyI6IFt7ImlkIjogImMxIiwgImZvcm1hdCI6ICJtc29fbWRvYyIsICJtZXRhIjogeyJkb2N0eXBlX3ZhbHVlIjogInQxIn19XX19";
        let signed_jwt = format!("header.{}.signature", payload_b64);

        let mut credman = FakeCredman {
            request_json: format!(r#"{{"requests": [{{"protocol": "openid4vp-v1-signed", "data": {{"request": "{}"}}}}]}}"#, signed_jwt),
            registered_json: r#"{
                "credentials": {
                    "mso_mdoc": {
                        "t1": [
                            {
                                "id": "cred_signed",
                                "display": {"verification": {"title": "T", "subtitle": "S", "icon": {"start": 0, "length": 0}}},
                                "paths": {}
                            }
                        ]
                    }
                }
            }"#.to_string(),
            ..Default::default()
        };

        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries_to_set.len(), 1);
        assert!(credman.added_entries_to_set[0].contains("cred_signed"));
    }
}
