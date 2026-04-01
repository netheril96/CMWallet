use crate::credman::CredmanApi;
use crate::json_value::{DeterministicMap, JsonValue};
pub use crate::openid4vp_models::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use nanoserde::DeJson;
use std::ffi::{CStr, CString};

pub fn decode_base64url(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut normalized = input.replace('+', "-").replace('/', "_");
    // Add padding if necessary
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }
    Ok(URL_SAFE.decode(normalized)?)
}

fn parse_protocol_request_data(
    pr: &ProtocolRequest,
) -> Result<OpenId4VpData, Box<dyn std::error::Error>> {
    let mut data_json_str = String::new();

    if let Some(data) = &pr.data {
        match data {
            JsonValue::String(s) => {
                data_json_str = s.clone();
            }
            _ => {}
        }
    } else if let Some(req_str) = &pr.request {
        data_json_str = req_str.clone();
    }

    if data_json_str.is_empty() {
        if let Some(data) = &pr.data {
            data_json_str = serialize_json_value(data);
        }
    }

    if pr.protocol == "openid4vp-v1-signed" {
        log::debug!("Handling signed OpenID4VP request");
        let parts: Vec<&str> = data_json_str.split('.').collect();
        if parts.len() >= 2 {
            let decoded = decode_base64url(parts[1])?;
            Ok(DeJson::deserialize_json(std::str::from_utf8(&decoded)?)?)
        } else {
            if let Some(JsonValue::Object(obj)) = &pr.data {
                if let Some(JsonValue::String(signed_req)) = obj.get("request") {
                    let parts: Vec<&str> = signed_req.split('.').collect();
                    if parts.len() >= 2 {
                        let decoded = decode_base64url(parts[1])?;
                        Ok(DeJson::deserialize_json(std::str::from_utf8(&decoded)?)?)
                    } else {
                        log::error!("Invalid JWS parts in nested request");
                        Err("Invalid JWS".into())
                    }
                } else {
                    log::error!("Missing 'request' field in signed data object");
                    Err("Missing signed request".into())
                }
            } else {
                log::error!("Invalid signed request data format: {}", data_json_str);
                Err("Invalid signed request data".into())
            }
        }
    } else {
        log::debug!("Handling unsigned OpenID4VP request");
        Ok(DeJson::deserialize_json(&data_json_str)?)
    }
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
        if pr.protocol == "openid4vp-v1-unsigned" || pr.protocol == "openid4vp-v1-signed" {
            let data_json = parse_protocol_request_data(pr)?;
            let query = data_json.dcql_query.as_ref().ok_or("Missing dcql_query")?;
            let match_result = crate::dcql::dcql_query(query, &registry);

            report_match_result(credman, &match_result, i, &data_json, &matcher_data_buffer)?;
        } else {
            log::warn!("Unsupported protocol: {}", pr.protocol);
        }
    }

    log::info!("OpenID4VP matching process completed");
    Ok(())
}

fn serialize_json_value(val: &JsonValue) -> String {
    match val {
        JsonValue::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Null => "null".to_string(),
        JsonValue::Array(arr) => {
            let items: Vec<String> = arr.iter().map(serialize_json_value).collect();
            format!("[{}]", items.join(","))
        }
        JsonValue::Object(obj) => {
            let items: Vec<String> = obj
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, serialize_json_value(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

fn report_credential_set_length(
    credman: &mut impl CredmanApi,
    set_id: &CStr,
    curr_length: usize,
    curr_set_idx: usize,
    matched_credential_sets: &[Vec<MatchedCredentialSetInfo>],
) {
    if curr_set_idx == matched_credential_sets.len() {
        credman.add_entry_set(set_id, curr_length as i32);
    } else {
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
}

fn report_payment_transaction_entry(
    credman: &mut impl CredmanApi,
    c: &MatchedCredential,
    doc_idx: i32,
    set_id: &CStr,
    metadata_cstr: &CStr,
    merchant: &str,
    amount: &str,
    additional: &Option<String>,
    creds_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Reporting as payment entry: {}", c.id);
    let title = CString::new(c.display.verification.title.clone())?;
    let subtitle = c
        .display
        .verification
        .subtitle
        .as_ref()
        .map(|s| CString::new(s.clone()))
        .transpose()?;
    let merchant_cstr = CString::new(merchant.to_string())?;
    let amount_cstr = CString::new(amount.to_string())?;
    let additional_cstr = additional
        .as_ref()
        .map(|s| CString::new(s.clone()))
        .transpose()?;
    let cred_id_cstr = CString::new(c.id.clone())?;

    let icon_bytes = c
        .display
        .verification
        .icon
        .as_ref()
        .map(|i| &creds_blob[i.start..i.start + i.length]);

    credman.add_payment_entry_to_set_v2(
        &cred_id_cstr,
        Some(&merchant_cstr),
        Some(&title),
        subtitle.as_deref(),
        icon_bytes,
        Some(&amount_cstr),
        None,
        None,
        additional_cstr.as_deref(),
        Some(metadata_cstr),
        set_id,
        doc_idx,
    );
    Ok(())
}

fn report_standard_verification_entry(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    c: &MatchedCredential,
    doc_idx: i32,
    set_id: &CStr,
    metadata_cstr: &CStr,
    creds_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Reporting as standard entry: {}", c.id);
    let title = CString::new(c.display.verification.title.clone())?;
    let subtitle = c
        .display
        .verification
        .subtitle
        .as_ref()
        .map(|s| CString::new(s.clone()))
        .transpose()?;
    let explainer = c
        .display
        .verification
        .explainer
        .as_ref()
        .map(|s| CString::new(s.clone()))
        .transpose()?;
    let cred_id_cstr = CString::new(c.id.clone())?;
    let icon_bytes = c
        .display
        .verification
        .icon
        .as_ref()
        .map(|i| &creds_blob[i.start..i.start + i.length]);

    credman.add_entry_to_set(
        &cred_id_cstr,
        icon_bytes,
        Some(&title),
        subtitle.as_deref(),
        explainer.as_deref(),
        None,
        Some(metadata_cstr),
        set_id,
        doc_idx,
    );

    log::trace!(
        "Reporting {} claims for entry {}",
        c.matched_claim_names.len(),
        c.id
    );
    for claim in &c.matched_claim_names {
        if let JsonValue::Object(obj) = claim {
            if let Some(JsonValue::Object(v)) = obj.get("verification") {
                if let Some(JsonValue::String(display_name)) = v.get("display") {
                    let display_value = match v.get("display_value") {
                        Some(JsonValue::String(s)) => Some(CString::new(s.clone())?),
                        _ => None,
                    };
                    let name_cstr = CString::new(display_name.clone())?;
                    credman.add_field_to_entry_set(
                        &cred_id_cstr,
                        &name_cstr,
                        display_value.as_deref(),
                        set_id,
                        doc_idx,
                    );
                }
            }
        }
    }

    if wasm_version >= 5 {
        if let Some(meta_text) = &c.display.verification.metadata_display_text {
            let meta_text_cstr = CString::new(meta_text.clone())?;
            log::trace!("Adding metadata display text: {}", meta_text);
            credman.add_metadata_display_text_to_entry_set(
                &cred_id_cstr,
                &meta_text_cstr,
                set_id,
                doc_idx,
            );
        }
    }
    Ok(())
}

fn report_matched_credential(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    matched_doc: &DcqlMatchedCredentialEntry,
    matched_credential_id: &str,
    doc_idx: i32,
    request_id: usize,
    set_id: &CStr,
    dcql_set_idx: Option<&str>,
    dcql_option_idx: Option<&str>,
    creds_blob: &[u8],
    transaction_info: &Option<(Vec<String>, String, String, Option<String>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!(
        "Reporting matched credential: id={}, dcql_id={}, doc_idx={}",
        matched_doc.id,
        matched_credential_id,
        doc_idx
    );
    for c in &matched_doc.matched {
        let metadata = Metadata {
            claims: c.matched_claim_metadata.clone(),
            dc_request_index: request_id,
            dcql_cred_id: matched_credential_id.to_string(),
            dcql_credential_set_index: dcql_set_idx.map(|s| s.to_string()),
            dcql_option_index: dcql_option_idx.map(|s| s.to_string()),
        };
        let metadata_str = nanoserde::SerJson::serialize_json(&metadata);
        let metadata_cstr = CString::new(metadata_str)?;

        let mut reported = false;
        if let Some((td_ids, merchant, amount, additional)) = transaction_info {
            if td_ids.iter().any(|id| id == matched_credential_id) {
                report_payment_transaction_entry(
                    credman,
                    c,
                    doc_idx,
                    set_id,
                    &metadata_cstr,
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
                &metadata_cstr,
                creds_blob,
            )?;
        }
    }
    Ok(())
}

fn report_matched_credential_set(
    credman: &mut impl CredmanApi,
    set_id: &CStr,
    curr_set_idx: usize,
    matched_credential_sets: &[Vec<MatchedCredentialSetInfo>],
    curr_doc_idx: &mut i32,
    wasm_version: u32,
    matched_docs: &DeterministicMap<String, DcqlMatchedCredentialEntry>,
    request_id: usize,
    creds_blob: &[u8],
    transaction_info: &Option<(Vec<String>, String, String, Option<String>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if curr_set_idx < matched_credential_sets.len() {
        let options = &matched_credential_sets[curr_set_idx];
        for opt in options {
            let mut doc_idx = *curr_doc_idx;
            for cred_id in &opt.matched_credential_ids {
                if let Some(doc) = matched_docs.get(cred_id) {
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
    }
    Ok(())
}

fn extract_transaction_info(
    data_json: &OpenId4VpData,
) -> Result<Option<(Vec<String>, String, String, Option<String>)>, Box<dyn std::error::Error>> {
    if !data_json.transaction_data.is_empty() {
        if data_json.transaction_data.len() == 1 {
            log::debug!("Decoding transaction data");
            let decoded = decode_base64url(&data_json.transaction_data[0])?;
            let td: TransactionData = DeJson::deserialize_json(std::str::from_utf8(&decoded)?)?;

            let mut merchant_name = td.merchant_name.clone().unwrap_or_default();
            let mut transaction_amount = td.amount.clone().unwrap_or_default();
            let additional_info = td.additional_info.clone();

            if let Some(t_type) = &td.transaction_type {
                log::trace!("Transaction type: {}", t_type);
                if t_type == "urn:eudi:sca:payment:1" {
                    if let Some(payload) = &td.payload {
                        merchant_name = payload
                            .payee
                            .as_ref()
                            .and_then(|p| p.name.clone())
                            .unwrap_or_default();
                        transaction_amount = payload.amount_display.clone().unwrap_or_else(|| {
                            if let Some(curr) = &payload.currency {
                                format!("{} {:.2}", curr, payload.amount.unwrap_or(0.0))
                            } else {
                                format!("{:.2}", payload.amount.unwrap_or(0.0))
                            }
                        });
                    }
                } else if t_type == "payment_details" {
                    merchant_name = td.payee_name.clone().unwrap_or_default();
                    transaction_amount = format!(
                        "{} {}",
                        td.payment_currency.as_deref().unwrap_or(""),
                        td.payment_amount.as_deref().unwrap_or("")
                    );
                }
            }
            log::info!(
                "Found transaction data: merchant={}, amount={}",
                merchant_name,
                transaction_amount
            );
            return Ok(Some((
                td.credential_ids,
                merchant_name,
                transaction_amount,
                additional_info,
            )));
        }
    }
    Ok(None)
}

fn report_match_result(
    credman: &mut impl CredmanApi,
    res: &DcqlMatchResult,
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
            let set_id_cstr = CString::new(set_id_str.clone())?;
            log::debug!("Set ID: {}", set_id_str);

            if wasm_version > 1 {
                log::trace!("Reporting credential set lengths for {}", set_id_str);
                report_credential_set_length(
                    credman,
                    &set_id_cstr,
                    opt.matched_credential_ids.len(),
                    1,
                    &res.matched_credential_sets,
                );
            }

            let mut doc_idx = 0;
            for cred_id in &opt.matched_credential_ids {
                if let Some(doc) = res.matched_credentials.get(cred_id) {
                    report_matched_credential(
                        credman,
                        wasm_version,
                        doc,
                        cred_id,
                        doc_idx,
                        request_idx,
                        &set_id_cstr,
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
            }

            let mut next_doc_idx = doc_idx;
            report_matched_credential_set(
                credman,
                &set_id_cstr,
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
        let cred_id_cstr = CString::new(inline.id.clone())?;
        let title_cstr = inline
            .title
            .as_ref()
            .map(|s| CString::new(s.clone()))
            .transpose()?;
        let subtitle_cstr = inline
            .subtitle
            .as_ref()
            .map(|s| CString::new(s.clone()))
            .transpose()?;
        let icon_bytes = inline
            .icon
            .as_ref()
            .map(|i| &creds_blob[i.start..i.start + i.length]);

        credman.add_inline_issuance_entry(
            &cred_id_cstr,
            icon_bytes,
            title_cstr.as_deref(),
            subtitle_cstr.as_deref(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use nanoserde::{DeJson, SerJson};
    use std::ffi::CStr;

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
            _id: &CStr,
            _icon: Option<&[u8]>,
            _title: Option<&CStr>,
            _subtitle: Option<&CStr>,
            _disclaimer: Option<&CStr>,
            _warning: Option<&CStr>,
        ) {
        }
        fn add_entry_set(&mut self, set_id: &CStr, set_length: i32) {
            let s_id = set_id.to_str().unwrap().to_string();
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
            cred_id: &CStr,
            _icon: Option<&[u8]>,
            title: Option<&CStr>,
            subtitle: Option<&CStr>,
            disclaimer: Option<&CStr>,
            warning: Option<&CStr>,
            _metadata: Option<&CStr>,
            set_id: &CStr,
            set_index: i32,
        ) {
            let s_id = set_id.to_str().unwrap().to_string();
            let c_id = cred_id.to_str().unwrap().to_string();
            let entry = FakeEntry {
                cred_id: c_id.clone(),
                entry_type: EntryType::Verification,
                title: title
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
                subtitle: subtitle
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
                disclaimer: disclaimer
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
                warning: warning
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
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
            cred_id: &CStr,
            field_display_name: &CStr,
            field_display_value: Option<&CStr>,
            set_id: &CStr,
            set_index: i32,
        ) {
            let s_id = set_id.to_str().unwrap().to_string();
            let c_id = cred_id.to_str().unwrap().to_string();
            let f_name = field_display_name.to_str().unwrap().to_string();
            let f_val = field_display_value
                .map(|s| s.to_str().unwrap().to_string())
                .unwrap_or_default();
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
            cred_id: &CStr,
            merchant_name: Option<&CStr>,
            _method_name: Option<&CStr>,
            _method_subtitle: Option<&CStr>,
            _icon: Option<&[u8]>,
            transaction_amount: Option<&CStr>,
            _bank_icon: Option<&[u8]>,
            _provider_icon: Option<&[u8]>,
            additional_info: Option<&CStr>,
            _metadata: Option<&CStr>,
            set_id: &CStr,
            set_index: i32,
        ) {
            let s_id = set_id.to_str().unwrap().to_string();
            let c_id = cred_id.to_str().unwrap().to_string();
            let entry = FakeEntry {
                cred_id: c_id.clone(),
                entry_type: EntryType::Payment,
                title: String::new(),
                subtitle: String::new(),
                disclaimer: String::new(),
                warning: String::new(),
                metadata_display_text: String::new(),
                fields: Vec::new(),
                merchant_name: merchant_name
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
                transaction_amount: transaction_amount
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
                additional_info: additional_info
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
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
            cred_id: &CStr,
            _icon: Option<&[u8]>,
            title: Option<&CStr>,
            subtitle: Option<&CStr>,
        ) {
            let entry = FakeEntry {
                cred_id: cred_id.to_str().unwrap().to_string(),
                entry_type: EntryType::InlineIssuance,
                title: title
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
                subtitle: subtitle
                    .map(|s| s.to_str().unwrap().to_string())
                    .unwrap_or_default(),
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
            cred_id: &CStr,
            metadata_display_text: &CStr,
            set_id: &CStr,
            set_index: i32,
        ) {
            let s_id = set_id.to_str().unwrap().to_string();
            let c_id = cred_id.to_str().unwrap().to_string();
            self.entry_sets
                .get_mut(&s_id)
                .unwrap()
                .entries
                .get_mut(&set_index.to_string())
                .unwrap()
                .get_mut(&c_id)
                .unwrap()
                .metadata_display_text = metadata_display_text.to_str().unwrap().to_string();
        }
    }

    #[derive(SerJson, DeJson, PartialEq, Debug)]
    struct FakeCredmanResult {
        #[nserde(rename = "entrySets")]
        entry_sets: DeterministicMap<String, FakeEntrySet>,
        #[nserde(rename = "standaloneEntries")]
        standalone_entries: Vec<FakeEntry>,
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

    fn normalize_json(val: JsonValue) -> JsonValue {
        match val {
            JsonValue::Array(arr) => {
                // Check if it's an array of [number, object] from expected_json map serialization
                let is_map = !arr.is_empty()
                    && arr.iter().all(|item| {
                        if let JsonValue::Array(pair) = item {
                            pair.len() == 2
                                && matches!(pair[0], JsonValue::Number(_))
                                && matches!(pair[1], JsonValue::Object(_))
                        } else {
                            false
                        }
                    });

                if is_map {
                    let mut obj = DeterministicMap::new();
                    for item in arr {
                        if let JsonValue::Array(mut pair) = item {
                            let val = pair.pop().unwrap();
                            let key = pair.pop().unwrap();
                            if let JsonValue::Number(k) = key {
                                obj.insert(k.to_string(), normalize_json(val));
                            }
                        }
                    }
                    JsonValue::Object(obj)
                } else {
                    let mut normalized_arr: Vec<JsonValue> =
                        arr.into_iter().map(normalize_json).collect();
                    // Sort the array by serialized string representation to make comparison deterministic
                    normalized_arr.sort_by(|a, b| {
                        let a_str = serialize_json_value(a);
                        let b_str = serialize_json_value(b);
                        a_str.cmp(&b_str)
                    });
                    JsonValue::Array(normalized_arr)
                }
            }
            JsonValue::Object(obj) => {
                // Some empty arrays in nlohmann::json might be empty objects if it couldn't infer the type
                // But wait, if expected has empty object for fields, and we have empty array, let's normalize both to empty array
                // For simplicity, let's just normalize the contents.
                let mut new_obj = DeterministicMap::new();
                for (k, v) in obj.0.clone() {
                    if k == "fields" {
                        if let JsonValue::Object(inner) = &v {
                            if inner.is_empty() {
                                new_obj.insert(k, JsonValue::Array(Vec::new()));
                                continue;
                            }
                        }
                    }
                    new_obj.insert(k, normalize_json(v));
                }
                JsonValue::Object(new_obj)
            }
            _ => val,
        }
    }

    fn run_test_impl(test_name: &str, custom_registry: Option<&str>) {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let testdata_dir = std::path::PathBuf::from(manifest_dir).join("../matcher/testdata");

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

        let result_json_str = SerJson::serialize_json(&result);
        let result_val: JsonValue = DeJson::deserialize_json(&result_json_str).unwrap();
        let result_normalized = normalize_json(result_val);

        let expected_raw: JsonValue = DeJson::deserialize_json(&expected_json).unwrap();
        let expected_normalized = normalize_json(expected_raw);

        assert_eq!(
            result_normalized, expected_normalized,
            "Test {} failed",
            test_name
        );
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
        let testdata_dir = std::path::PathBuf::from(manifest_dir).join("../matcher/testdata");
        let mut registry_json =
            std::fs::read_to_string(testdata_dir.join("registry.json")).unwrap();
        let target = "\"title\": \"John's Driving License\"";
        if let Some(pos) = registry_json.find(target) {
            registry_json.insert_str(pos, "\"metadata_display_text\": \"Verified Member\", ");
        }
        run_test_impl("TC37_WasmMetadataText", Some(&registry_json));
    }
}
