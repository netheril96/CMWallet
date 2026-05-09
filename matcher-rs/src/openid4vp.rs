use crate::base64url::decode_base64url;
use crate::credman::CredmanApi;
use crate::json_value::{DeterministicMap, JsonValue};
pub use crate::openid4vp_models::*;
use nanoserde::DeJson;
use std::borrow::Cow;

fn parse_protocol_request_data<'a>(
    pr: &'a ProtocolRequest,
) -> Result<Cow<'a, OpenId4VpData>, Box<dyn std::error::Error>> {
    if pr.protocol == "openid4vp-v1-signed" {
        log::debug!("Handling signed OpenID4VP request");
        let jws: &'a str = if let Some(data) = &pr.data {
            match data {
                ProtocolRequestData::String(s) => s,
                ProtocolRequestData::Object(obj) => {
                    if obj.request.is_empty() {
                        return Err("Missing 'request' field in signed data object".into());
                    }
                    &obj.request
                }
            }
        } else if !pr.request.is_empty() {
            &pr.request
        } else {
            return Err("Missing signed request data".into());
        };

        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() < 2 {
            log::error!("Invalid JWS parts");
            return Err("Invalid JWS".into());
        }

        let decoded = decode_base64url(parts[1])?;
        return Ok(Cow::Owned(DeJson::deserialize_json(std::str::from_utf8(
            &decoded,
        )?)?));
    }

    log::debug!("Handling unsigned OpenID4VP request");
    if let Some(data) = &pr.data {
        return match data {
            ProtocolRequestData::Object(obj) => Ok(Cow::Borrowed(obj)),
            ProtocolRequestData::String(s) => Ok(Cow::Owned(DeJson::deserialize_json(s)?)),
        };
    }

    if !pr.request.is_empty() {
        return Ok(Cow::Owned(DeJson::deserialize_json(&pr.request)?));
    }

    Err("Missing unsigned request data".into())
}

pub fn openid4vp_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Starting OpenID4VP matching process");
    let matcher_data_buffer = credman.get_registered_data();
    if matcher_data_buffer.len() < 4 {
        log::error!(
            "Matcher data buffer is too small: {}",
            matcher_data_buffer.len()
        );
        return Err("Matcher data too small".into());
    }

    let json_start = u32::from_le_bytes(matcher_data_buffer[..4].try_into()?);
    log::debug!("Registry JSON starts at offset: {}", json_start);
    let matcher_data_str = std::str::from_utf8(&matcher_data_buffer[json_start as usize..])?;
    log::debug!("Registry JSON: {}", matcher_data_str);
    let registry: Registry = match DeJson::deserialize_json(matcher_data_str) {
        Ok(data) => data,
        Err(e) => {
            log::error!(
                "Failed to deserialize registry: {:?}. JSON snippet: {}",
                e,
                &matcher_data_str[..std::cmp::min(100, matcher_data_str.len())]
            );
            return Err(e.into());
        }
    };
    log::info!("Successfully parsed registry");

    let request_buffer = credman.get_request_buffer();
    let request_str = std::str::from_utf8(&request_buffer)?;
    log::debug!("Request JSON: {}", request_str);
    let request: OpenId4VpRequest = match DeJson::deserialize_json(request_str) {
        Ok(req) => req,
        Err(e) => {
            log::error!(
                "Failed to deserialize request: {:?}. JSON: {}",
                e,
                request_str
            );
            return Err(e.into());
        }
    };

    let protocol_requests = if !request.requests.is_empty() {
        request.requests
    } else {
        request.providers
    };
    log::info!("Found {} protocol requests", protocol_requests.len());

    for (i, pr) in protocol_requests.iter().enumerate() {
        log::debug!("Processing request {}: protocol={}", i, pr.protocol);
        if pr.protocol != "openid4vp-v1-unsigned" && pr.protocol != "openid4vp-v1-signed" {
            log::warn!("Unsupported protocol: {}", pr.protocol);
            continue;
        }

        let data_json = parse_protocol_request_data(pr)?;
        let query = data_json.dcql_query.as_ref().ok_or("Missing dcql_query")?;
        let match_result = crate::dcql::dcql_query(query, &registry);

        report_match_result(credman, &match_result, i, &data_json, &matcher_data_buffer)?;
    }

    log::info!("OpenID4VP matching process completed");
    Ok(())
}

fn report_credential_set_length(
    credman: &mut impl CredmanApi,
    set_id: &str,
    curr_length: usize,
    curr_set_idx: usize,
    matched_credential_sets: &[Vec<MatchedCredentialSetInfo<'_>>],
) {
    if curr_set_idx == matched_credential_sets.len() {
        credman.add_entry_set(set_id, curr_length as i32);
        return;
    }

    let options = &matched_credential_sets[curr_set_idx];
    for opt in options {
        report_credential_set_length(
            credman,
            set_id,
            curr_length + opt.matched_credential_ids.len(),
            curr_set_idx + 1,
            matched_credential_sets,
        );
    }
}

fn report_payment_transaction_entry(
    credman: &mut impl CredmanApi,
    c: &MatchedCredential<'_>,
    doc_idx: i32,
    set_id: &str,
    metadata_str: &str,
    merchant: &str,
    amount: &str,
    additional: &str,
    creds_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Reporting as payment entry: {}", c.id);

    let icon_bytes = c
        .display
        .verification
        .icon
        .as_ref()
        .map_or(&[][..], |i| &creds_blob[i.start..i.start + i.length]);

    credman.add_payment_entry_to_set_v2(
        c.id,
        merchant,
        &c.display.verification.title,
        &c.display.verification.subtitle,
        icon_bytes,
        amount,
        &[],
        &[],
        additional,
        metadata_str,
        set_id,
        doc_idx,
    );
    Ok(())
}

fn report_standard_verification_entry(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    c: &MatchedCredential<'_>,
    doc_idx: i32,
    set_id: &str,
    metadata_str: &str,
    creds_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Reporting as standard entry: {}", c.id);

    let icon_bytes = c
        .display
        .verification
        .icon
        .as_ref()
        .map_or(&[][..], |i| &creds_blob[i.start..i.start + i.length]);

    credman.add_entry_to_set(
        c.id,
        icon_bytes,
        &c.display.verification.title,
        &c.display.verification.subtitle,
        &c.display.verification.explainer,
        "",
        metadata_str,
        set_id,
        doc_idx,
    );

    log::trace!(
        "Reporting {} claims for entry {}",
        c.matched_claim_names.len(),
        c.id
    );
    for claim in &c.matched_claim_names {
        let JsonValue::Object(obj) = claim else {
            continue;
        };

        let Some(JsonValue::Object(v)) = obj.get("verification") else {
            continue;
        };

        let Some(JsonValue::String(display_name)) = v.get("display") else {
            continue;
        };

        let display_value = match v.get("display_value") {
            Some(JsonValue::String(s)) => s,
            _ => "",
        };

        credman.add_field_to_entry_set(&c.id, display_name, display_value, set_id, doc_idx);
    }

    if wasm_version >= 5 && !c.display.verification.metadata_display_text.is_empty() {
        log::trace!(
            "Adding metadata display text: {}",
            c.display.verification.metadata_display_text
        );
        credman.add_metadata_display_text_to_entry_set(
            &c.id,
            &c.display.verification.metadata_display_text,
            set_id,
            doc_idx,
        );
    }
    Ok(())
}

fn report_matched_credential(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    matched_doc: &DcqlMatchedCredentialEntry<'_>,
    matched_credential_id: &str,
    doc_idx: i32,
    request_id: usize,
    set_id: &str,
    dcql_set_idx: Option<&str>,
    dcql_option_idx: Option<&str>,
    creds_blob: &[u8],
    transaction_info: &Option<(Vec<String>, String, String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!(
        "Reporting matched credential: id={}, dcql_id={}, doc_idx={}",
        matched_doc.id,
        matched_credential_id,
        doc_idx
    );
    for c in &matched_doc.matched {
        let metadata = SelectionMetadata {
            claims: &c.matched_claim_metadata,
            dc_request_index: request_id,
            dcql_cred_id: matched_credential_id,
            dcql_credential_set_index: dcql_set_idx.unwrap_or(""),
            dcql_option_index: dcql_option_idx.unwrap_or(""),
        };
        let metadata_str = nanoserde::SerJson::serialize_json(&metadata);

        let mut reported = false;
        if let Some((td_ids, merchant, amount, additional)) = transaction_info {
            if td_ids.iter().any(|id| id == matched_credential_id) {
                report_payment_transaction_entry(
                    credman,
                    c,
                    doc_idx,
                    set_id,
                    &metadata_str,
                    merchant,
                    amount,
                    additional,
                    creds_blob,
                )?;
                reported = true;
            }
        }

        if !reported {
            report_standard_verification_entry(
                credman,
                wasm_version,
                c,
                doc_idx,
                set_id,
                &metadata_str,
                creds_blob,
            )?;
        }
    }
    Ok(())
}

fn report_matched_credential_set(
    credman: &mut impl CredmanApi,
    set_id: &str,
    curr_set_idx: usize,
    matched_credential_sets: &[Vec<MatchedCredentialSetInfo<'_>>],
    curr_doc_idx: &mut i32,
    wasm_version: u32,
    matched_docs: &DeterministicMap<&str, DcqlMatchedCredentialEntry<'_>>,
    request_id: usize,
    creds_blob: &[u8],
    transaction_info: &Option<(Vec<String>, String, String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if curr_set_idx >= matched_credential_sets.len() {
        return Ok(());
    }

    let options = &matched_credential_sets[curr_set_idx];
    for opt in options {
        let mut doc_idx = *curr_doc_idx;
        for cred_id in &opt.matched_credential_ids {
            let Some(doc) = matched_docs.get(*cred_id) else {
                continue;
            };

            report_matched_credential(
                credman,
                wasm_version,
                doc,
                cred_id,
                doc_idx,
                request_id,
                set_id,
                Some(&opt.set_id),
                Some(&opt.option_id),
                creds_blob,
                transaction_info,
            )?;
            doc_idx += 1;
        }

        report_matched_credential_set(
            credman,
            set_id,
            curr_set_idx + 1,
            matched_credential_sets,
            &mut doc_idx,
            wasm_version,
            matched_docs,
            request_id,
            creds_blob,
            transaction_info,
        )?;
    }
    Ok(())
}

fn extract_transaction_info(
    data_json: &OpenId4VpData,
) -> Result<Option<(Vec<String>, String, String, String)>, Box<dyn std::error::Error>> {
    if data_json.transaction_data.len() != 1 {
        return Ok(None);
    }

    log::debug!("Decoding transaction data");
    let decoded = decode_base64url(&data_json.transaction_data[0])?;
    let td: TransactionData = DeJson::deserialize_json(std::str::from_utf8(&decoded)?)?;

    if !td.transaction_type.is_empty() {
        log::trace!("Transaction type: {}", td.transaction_type);
        if td.transaction_type == "urn:eudi:sca:payment:1" {
            if let Some(payload) = &td.payload {
                let merchant_name = payload
                    .payee
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_default();
                let transaction_amount = if !payload.amount_display.is_empty() {
                    payload.amount_display.clone()
                } else if !payload.currency.is_empty() {
                    format!("{} {:.2}", payload.currency, payload.amount.unwrap_or(0.0))
                } else {
                    format!("{:.2}", payload.amount.unwrap_or(0.0))
                };
                log::info!(
                    "Found transaction data (sca): merchant={}, amount={}",
                    merchant_name,
                    transaction_amount
                );
                return Ok(Some((
                    td.credential_ids,
                    merchant_name,
                    transaction_amount,
                    td.additional_info.clone(),
                )));
            }
        } else if td.transaction_type == "payment_details" {
            let merchant_name = td.payee_name.clone();
            let transaction_amount = format!("{} {}", td.payment_currency, td.payment_amount);
            log::info!(
                "Found transaction data (details): merchant={}, amount={}",
                merchant_name,
                transaction_amount
            );
            return Ok(Some((
                td.credential_ids,
                merchant_name,
                transaction_amount,
                td.additional_info.clone(),
            )));
        }
    }

    log::info!(
        "Found transaction data: merchant={}, amount={}",
        td.merchant_name,
        td.amount
    );
    Ok(Some((
        td.credential_ids,
        td.merchant_name,
        td.amount,
        td.additional_info,
    )))
}

fn report_match_result(
    credman: &mut impl CredmanApi,
    res: &DcqlMatchResult<'_>,
    request_idx: usize,
    data_json: &OpenId4VpData,
    creds_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let wasm_version = credman.get_wasm_version();
    log::info!("Reporting match results. Wasm version: {}", wasm_version);

    if !res.matched_credential_sets.is_empty() {
        let transaction_info = extract_transaction_info(data_json)?;
        let first_set = &res.matched_credential_sets[0];
        log::debug!(
            "Reporting {} options from the first matched set",
            first_set.len()
        );
        for opt in first_set {
            let set_id_str = if !opt.set_id.is_empty() {
                format!(
                    "req:{};set:{};option:{}",
                    request_idx, opt.set_id, opt.option_id
                )
            } else {
                format!("req:{};null", request_idx)
            };
            log::debug!("Set ID: {}", set_id_str);

            if wasm_version > 1 {
                log::trace!("Reporting credential set lengths for {}", set_id_str);
                report_credential_set_length(
                    credman,
                    &set_id_str,
                    opt.matched_credential_ids.len(),
                    1,
                    &res.matched_credential_sets,
                );
            }

            let mut doc_idx = 0;
            for cred_id in &opt.matched_credential_ids {
                let Some(doc) = res.matched_credentials.get(*cred_id) else {
                    continue;
                };

                report_matched_credential(
                    credman,
                    wasm_version,
                    doc,
                    cred_id,
                    doc_idx,
                    request_idx,
                    &set_id_str,
                    if opt.set_id.is_empty() {
                        None
                    } else {
                        Some(&opt.set_id)
                    },
                    if opt.option_id.is_empty() {
                        None
                    } else {
                        Some(&opt.option_id)
                    },
                    creds_blob,
                    &transaction_info,
                )?;
                doc_idx += 1;
            }

            let mut next_doc_idx = doc_idx;
            report_matched_credential_set(
                credman,
                &set_id_str,
                1,
                &res.matched_credential_sets,
                &mut next_doc_idx,
                wasm_version,
                &res.matched_credentials,
                request_idx,
                creds_blob,
                &transaction_info,
            )?;
        }
    }

    if let Some(inline) = &res.inline_issuance {
        log::info!("Reporting inline issuance entry: {}", inline.id);
        let icon_bytes = inline
            .icon
            .as_ref()
            .map_or(&[][..], |i| &creds_blob[i.start..i.start + i.length]);

        credman.add_inline_issuance_entry(&inline.id, icon_bytes, &inline.title, &inline.subtitle);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use nanoserde::{DeJson, SerJson};

    #[derive(SerJson, DeJson, PartialEq, Debug, Clone, Default)]
    enum EntryType {
        #[default]
        Verification,
        InlineIssuance,
        Payment,
        UserInfo,
        Export,
    }

    #[derive(SerJson, DeJson, PartialEq, Debug, Clone, Default)]
    struct FakeEntry {
        #[nserde(rename = "credId")]
        cred_id: String,
        #[nserde(rename = "type")]
        entry_type: EntryType,
        #[nserde(default)]
        title: String,
        #[nserde(default)]
        subtitle: String,
        #[nserde(default)]
        disclaimer: String,
        #[nserde(default)]
        warning: String,
        #[nserde(default)]
        metadata_display_text: String,
        #[nserde(default)]
        fields: Vec<(String, String)>,
        #[nserde(default)]
        merchant_name: String,
        #[nserde(default)]
        transaction_amount: String,
        #[nserde(default)]
        additional_info: String,
    }

    #[derive(SerJson, DeJson, PartialEq, Debug, Clone)]
    struct FakeEntrySet {
        #[nserde(rename = "setId")]
        set_id: String,
        #[nserde(rename = "setLength")]
        set_length: i32,
        #[nserde(default)]
        entries: DeterministicMap<String, DeterministicMap<String, FakeEntry>>,
    }

    #[derive(SerJson, DeJson, PartialEq, Debug)]
    struct FakeCredmanResult {
        #[nserde(rename = "entrySets")]
        entry_sets: DeterministicMap<String, FakeEntrySet>,
        #[nserde(rename = "standaloneEntries")]
        standalone_entries: Vec<FakeEntry>,
    }

    struct FakeCredman {
        entry_sets: DeterministicMap<String, FakeEntrySet>,
        standalone_entries: Vec<FakeEntry>,
        wasm_version: u32,
        request_json: String,
        credentials_blob: Vec<u8>,
    }

    impl FakeCredman {
        fn new() -> Self {
            Self {
                entry_sets: DeterministicMap::new(),
                standalone_entries: Vec::new(),
                wasm_version: 9999,
                request_json: String::new(),
                credentials_blob: Vec::new(),
            }
        }
    }

    impl CredmanApi for FakeCredman {
        fn get_request_buffer(&self) -> Vec<u8> {
            self.request_json.as_bytes().to_vec()
        }
        fn get_registered_data(&self) -> Vec<u8> {
            self.credentials_blob.clone()
        }
        fn get_wasm_version(&self) -> u32 {
            self.wasm_version
        }
        fn add_string_id_entry(
            &mut self,
            _id: &str,
            _icon: &[u8],
            _title: &str,
            _subtitle: &str,
            _disclaimer: &str,
            _warning: &str,
        ) {
        }
        fn add_entry_set(&mut self, set_id: &str, set_length: i32) {
            let s_id = set_id.to_string();
            self.entry_sets.insert(
                s_id.clone(),
                FakeEntrySet {
                    set_id: s_id,
                    set_length,
                    entries: DeterministicMap::new(),
                },
            );
        }
        fn add_entry_to_set(
            &mut self,
            cred_id: &str,
            _icon: &[u8],
            title: &str,
            subtitle: &str,
            disclaimer: &str,
            warning: &str,
            _metadata: &str,
            set_id: &str,
            set_index: i32,
        ) {
            let s_id = set_id.to_string();
            let c_id = cred_id.to_string();
            let entry = FakeEntry {
                cred_id: c_id.clone(),
                entry_type: EntryType::Verification,
                title: title.to_string(),
                subtitle: subtitle.to_string(),
                disclaimer: disclaimer.to_string(),
                warning: warning.to_string(),
                metadata_display_text: String::new(),
                fields: Vec::new(),
                merchant_name: String::new(),
                transaction_amount: String::new(),
                additional_info: String::new(),
            };
            self.entry_sets
                .get_mut(&s_id)
                .unwrap()
                .entries
                .entry(set_index.to_string())
                .or_insert_with(DeterministicMap::new)
                .insert(c_id, entry);
        }
        fn add_field_to_entry_set(
            &mut self,
            cred_id: &str,
            field_display_name: &str,
            field_display_value: &str,
            set_id: &str,
            set_index: i32,
        ) {
            let s_id = set_id.to_string();
            let c_id = cred_id.to_string();
            let f_name = field_display_name.to_string();
            let f_val = field_display_value.to_string();
            self.entry_sets
                .get_mut(&s_id)
                .unwrap()
                .entries
                .get_mut(&set_index.to_string())
                .unwrap()
                .get_mut(&c_id)
                .unwrap()
                .fields
                .push((f_name, f_val));
        }
        fn add_payment_entry_to_set_v2(
            &mut self,
            cred_id: &str,
            merchant_name: &str,
            _method_name: &str,
            _method_subtitle: &str,
            _icon: &[u8],
            transaction_amount: &str,
            _bank_icon: &[u8],
            _provider_icon: &[u8],
            additional_info: &str,
            _metadata: &str,
            set_id: &str,
            set_index: i32,
        ) {
            let s_id = set_id.to_string();
            let c_id = cred_id.to_string();
            let entry = FakeEntry {
                cred_id: c_id.clone(),
                entry_type: EntryType::Payment,
                title: String::new(),
                subtitle: String::new(),
                disclaimer: String::new(),
                warning: String::new(),
                metadata_display_text: String::new(),
                fields: Vec::new(),
                merchant_name: merchant_name.to_string(),
                transaction_amount: transaction_amount.to_string(),
                additional_info: additional_info.to_string(),
            };
            self.entry_sets
                .get_mut(&s_id)
                .unwrap()
                .entries
                .entry(set_index.to_string())
                .or_insert_with(DeterministicMap::new)
                .insert(c_id, entry);
        }
        fn add_inline_issuance_entry(
            &mut self,
            cred_id: &str,
            _icon: &[u8],
            title: &str,
            subtitle: &str,
        ) {
            let entry = FakeEntry {
                cred_id: cred_id.to_string(),
                entry_type: EntryType::InlineIssuance,
                title: title.to_string(),
                subtitle: subtitle.to_string(),
                disclaimer: String::new(),
                warning: String::new(),
                metadata_display_text: String::new(),
                fields: Vec::new(),
                merchant_name: String::new(),
                transaction_amount: String::new(),
                additional_info: String::new(),
            };
            self.standalone_entries.push(entry);
        }
        fn add_metadata_display_text_to_entry_set(
            &mut self,
            cred_id: &str,
            metadata_display_text: &str,
            set_id: &str,
            set_index: i32,
        ) {
            let s_id = set_id.to_string();
            let c_id = cred_id.to_string();
            self.entry_sets
                .get_mut(&s_id)
                .unwrap()
                .entries
                .get_mut(&set_index.to_string())
                .unwrap()
                .get_mut(&c_id)
                .unwrap()
                .metadata_display_text = metadata_display_text.to_string();
        }
    }

    fn create_registry_blob(json_str: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        let offset = 4 + 10;
        blob.extend_from_slice(&(offset as u32).to_le_bytes());
        for i in 0..10 {
            blob.push(i as u8);
        }
        blob.extend_from_slice(json_str.as_bytes());
        blob
    }

    fn run_test_impl(test_name: &str, custom_registry: Option<&str>) {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let testdata_dir = std::path::PathBuf::from(manifest_dir).join("testdata");

        let registry_json = match custom_registry {
            Some(s) => s.to_string(),
            None => std::fs::read_to_string(testdata_dir.join("registry.json")).unwrap(),
        };

        let request_path = testdata_dir.join(format!("{}_request.json", test_name));
        let expected_path = testdata_dir.join(format!("{}_expected.json", test_name));

        let request_json = std::fs::read_to_string(&request_path)
            .unwrap_or_else(|_| panic!("Failed to read {:?}", request_path));
        let expected_json = std::fs::read_to_string(&expected_path)
            .unwrap_or_else(|_| panic!("Failed to read {:?}", expected_path));

        let mut credman = FakeCredman::new();
        credman.credentials_blob = create_registry_blob(&registry_json);
        credman.request_json = request_json;

        openid4vp_main(&mut credman).unwrap();

        let result = FakeCredmanResult {
            entry_sets: credman.entry_sets,
            standalone_entries: credman.standalone_entries,
        };

        let expected_result: FakeCredmanResult = DeJson::deserialize_json(&expected_json).unwrap();

        assert_eq!(result, expected_result, "Test {} failed", test_name);
    }

    macro_rules! define_test {
        ($func_name:ident, $test_name:expr) => {
            #[test]
            fn $func_name() {
                run_test_impl($test_name, None);
            }
        };
    }

    define_test!(tc07_mdoc_match, "TC07_MdocMatch");
    define_test!(tc08_mdoc_mismatch, "TC08_MdocMismatch");
    define_test!(tc09_sdjwt_match, "TC09_SdjwtMatch");
    define_test!(tc10_sdjwt_mismatch, "TC10_SdjwtMismatch");
    define_test!(tc11_inline_issuance_fallback, "TC11_InlineIssuanceFallback");
    define_test!(tc12_missing_format, "TC12_MissingFormat");
    define_test!(tc13_return_all_claims, "TC13_ReturnAllClaims");
    define_test!(tc14_match_specific_claims, "TC14_MatchSpecificClaims");
    define_test!(tc15_match_nested_claims, "TC15_MatchNestedClaims");
    define_test!(tc16_fail_missing_claims, "TC16_FailMissingClaims");
    define_test!(tc17_match_claim_values_bool, "TC17_MatchClaimValuesBool");
    define_test!(tc18_fail_claim_values_bool, "TC18_FailClaimValuesBool");
    define_test!(tc19_match_claim_values_int, "TC19_MatchClaimValuesInt");
    define_test!(tc20_fail_claim_values_int, "TC20_FailClaimValuesInt");
    define_test!(tc21_match_first_claim_set, "TC21_MatchFirstClaimSet");
    define_test!(tc22_match_second_claim_set, "TC22_MatchSecondClaimSet");
    define_test!(tc23_fail_all_claim_sets, "TC23_FailAllClaimSets");
    define_test!(tc24_dcql_query_single, "TC24_DcqlQuerySingle");
    define_test!(tc25_dcql_query_set_match, "TC25_DcqlQuerySetMatch");
    define_test!(
        tc26_dcql_query_set_fail_required,
        "TC26_DcqlQuerySetFailRequired"
    );
    define_test!(
        tc27_dcql_query_set_fail_optional,
        "TC27_DcqlQuerySetFailOptional"
    );
    define_test!(
        tc28_dcql_query_complex_overlapping_sets,
        "TC28_DcqlQueryComplexOverlappingSets"
    );
    define_test!(
        tc29_dcql_query_openid4vp_spec_example,
        "TC29_DcqlQueryOpenID4VPSpecExample"
    );
    define_test!(tc30_parse_v1_unsigned, "TC30_ParseV1Unsigned");
    define_test!(tc31_parse_v1_signed, "TC31_ParseV1Signed");
    define_test!(tc32_extract_payment_sca1, "TC32_ExtractPaymentSca1");
    define_test!(tc33_extract_payment_details, "TC33_ExtractPaymentDetails");
    define_test!(tc34_extract_payment_generic, "TC34_ExtractPaymentGeneric");
    define_test!(tc35_wasm_add_entry_to_set, "TC35_WasmAddEntryToSet");
    define_test!(tc36_wasm_payment_v2, "TC36_WasmPaymentV2");

    #[test]
    fn tc37_wasm_metadata_text() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let testdata_dir = std::path::PathBuf::from(manifest_dir).join("testdata");
        let mut registry_json =
            std::fs::read_to_string(testdata_dir.join("registry.json")).unwrap();
        let target = "\"title\": \"John's Driving License\"";
        if let Some(pos) = registry_json.find(target) {
            registry_json.insert_str(pos, "\"metadata_display_text\": \"Verified Member\", ");
        }
        run_test_impl("TC37_WasmMetadataText", Some(&registry_json));
    }
}
