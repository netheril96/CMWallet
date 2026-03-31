use crate::credman::CredmanApi;
use crate::dcql::{dcql_query, MatchedEntry};
use crate::openid4vp::*;
use nanoserde::DeJson;
use std::ffi::{CStr, CString};

pub fn presentation_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Starting OpenID4VP presentation matching");

    let credentials_buffer = credman.get_registered_data();
    if credentials_buffer.len() < 4 {
        log::error!("Credentials buffer too small: {} bytes", credentials_buffer.len());
        return Err("Credentials buffer too small".into());
    }
    let json_offset = u32::from_le_bytes(credentials_buffer[0..4].try_into()?);
    log::debug!("Registry JSON offset: {}", json_offset);
    if credentials_buffer.len() < json_offset as usize {
         log::error!("JSON offset {} out of bounds for buffer size {}", json_offset, credentials_buffer.len());
         return Err("JSON offset out of bounds".into());
    }
    let credentials_json = std::str::from_utf8(&credentials_buffer[json_offset as usize..])?;
    let registry: OpenId4VpRegistry = match DeJson::deserialize_json(credentials_json) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to deserialize registry JSON: {}", e);
            log::trace!("Registry JSON content: {}", credentials_json);
            return Err(e.into());
        }
    };
    log::info!("Parsed registry with {} mso_mdoc doctypes and {} dc+sd-jwt VCTs", registry.credentials.mso_mdoc.len(), registry.credentials.dc_sd_jwt.len());

    let request_buffer = credman.get_request_buffer();
    let request_json = std::str::from_utf8(&request_buffer)?;
    let dc_request: DigitalCredentialRequest = match DeJson::deserialize_json(request_json) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to deserialize request JSON: {}", e);
            log::trace!("Request JSON content: {}", request_json);
            return Err(e.into());
        }
    };
    log::debug!("Parsed digital credential request");

    let wasm_version = credman.get_wasm_version();
    log::info!("WASM runtime version: {}", wasm_version);

    let requests = if let Some(reqs) = dc_request.requests {
        reqs
    } else if let Some(provs) = dc_request.providers {
        log::debug!("Using legacy 'providers' field for requests");
        provs
    } else {
        log::warn!("No requests or providers found in DC request");
        return Ok(());
    };

    log::info!("Processing {} potential OpenID4VP requests", requests.len());

    for (request_idx, request) in requests.iter().enumerate() {
        log::debug!("Evaluating request index {}: protocol={}", request_idx, request.protocol);
        if request.protocol != "openid4vp-v1-unsigned" && request.protocol != "openid4vp-v1-signed" {
            log::trace!("Skipping unsupported protocol: {}", request.protocol);
            continue;
        }
        log::info!("Processing OpenID4VP request at index {}", request_idx);

        let mut data_json_opt: Option<OpenId4VpRequestData> = request.data.clone();
        
        // Handle signed request
        if request.protocol == "openid4vp-v1-signed" {
            log::debug!("Processing signed request at index {}", request_idx);
            if let Some(data) = &data_json_opt {
                if let Some(jwt) = &data.request {
                    log::trace!("Parsing signed JWT");
                    if let Some(payload_b64) = jwt.split('.').nth(1) {
                        match decode_b64_url(payload_b64) {
                            Ok(decoded_bytes) => {
                                if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                                    match OpenId4VpRequestData::deserialize_json(decoded_str) {
                                        Ok(signed_data) => {
                                            log::info!("Successfully decoded and parsed signed request JWT");
                                            data_json_opt = Some(signed_data);
                                        }
                                        Err(e) => log::error!("Failed to parse signed request JSON: {}", e),
                                    }
                                }
                            }
                            Err(e) => log::error!("Failed to decode signed request B64URL: {}", e),
                        }
                    } else {
                        log::error!("Invalid JWT format in signed request");
                    }
                } else {
                    log::error!("Signed request missing 'request' field (JWT)");
                }
            }
        }

        let Some(data_json) = data_json_opt else {
            log::warn!("Request {} has no valid data JSON", request_idx);
            continue;
        };
        let Some(query) = &data_json.dcql_query else {
            log::warn!("Request {} has no DCQL query", request_idx);
            continue;
        };

        // Process transaction data for payments
        let mut merchant_name = None;
        let mut transaction_amount = None;
        let mut additional_info = None;
        let mut transaction_credential_ids = None;

        if let Some(td_list) = &data_json.transaction_data {
            log::info!("Request {} contains {} transaction data items", request_idx, td_list.len());
            if !td_list.is_empty() {
                // Spec typically uses the first one
                if let Ok(decoded_bytes) = decode_b64_url(&td_list[0]) {
                    if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                        if let Ok(td) = TransactionData::deserialize_json(decoded_str) {
                            log::debug!("Parsed transaction data of type: {}", td.transaction_type);
                            transaction_credential_ids = td.credential_ids;
                            additional_info = td.additional_info;
                            
                            if td.transaction_type == "urn:eudi:sca:payment:1" {
                                if let Some(payload) = td.payload {
                                    merchant_name = payload.payee.map(|p| p.name);
                                    transaction_amount = payload.amount_display.or_else(|| {
                                        if let (Some(a), Some(c)) = (payload.amount, payload.currency) {
                                            Some(format!("{} {:.2}", c, a))
                                        } else {
                                            None
                                        }
                                    });
                                }
                            } else if td.transaction_type == "payment_details" {
                                merchant_name = td.payee_name;
                                transaction_amount = if let (Some(a), Some(c)) = (&td.payment_amount, &td.payment_currency) {
                                    Some(format!("{} {}", c, a))
                                } else {
                                    None
                                };
                            } else {
                                merchant_name = td.merchant_name;
                                transaction_amount = td.amount;
                            }
                            log::info!("Transaction summary: merchant={:?}, amount={:?}", merchant_name, transaction_amount);
                        } else {
                            log::error!("Failed to parse transaction data JSON");
                        }
                    }
                } else {
                    log::error!("Failed to decode transaction data B64URL");
                }
            }
        }

        let match_result = dcql_query(query, &registry.credentials);
        log::debug!("DCQL query completed for request {}: {} matched sets", request_idx, match_result.matched_credential_sets.len());

        if !match_result.matched_credential_sets.is_empty() {
            log::info!("Reporting matched credential sets for request {}", request_idx);
            // In many use cases, we might only report the first "best" set, or all of them.
            // Following existing C pattern: iterate over options of the first matched set.
            let first_set = &match_result.matched_credential_sets[0];
            log::debug!("Reporting {} options from the first matched credential set", first_set.len());
            for (opt_idx, option) in first_set.iter().enumerate() {
                let set_id_str = format!("req:{};set:{};option:{}", request_idx, option.set_id, option.option_id);
                let set_id = CString::new(set_id_str.clone())?;

                if wasm_version > 1 {
                    // Total length across ALL matched sets (as per C logic)
                    let total_length = match_result.matched_credential_sets.iter().fold(0, |acc, s| acc + s[0].matched_credential_ids.len());
                    log::trace!("Calling add_entry_set: id={}, length={}", set_id_str, total_length);
                    credman.add_entry_set(&set_id, total_length as i32);
                }

                let mut doc_idx = 0;
                log::debug!("Reporting option {} credentials", opt_idx);
                for cred_id in &option.matched_credential_ids {
                    if let Some(matched_cred_set) = match_result.matched_credentials.get(cred_id) {
                        for entry in &matched_cred_set.matched {
                            log::trace!("Reporting credential entry {} at index {}", entry.id, doc_idx);
                            report_matched_entry(
                                credman,
                                entry,
                                &credentials_buffer,
                                &set_id,
                                doc_idx,
                                request_idx,
                                wasm_version,
                                &transaction_credential_ids,
                                merchant_name.as_deref(),
                                transaction_amount.as_deref(),
                                additional_info.as_deref(),
                                Some(cred_id),
                                Some(&option.set_id),
                                Some(&option.option_id),
                            )?;
                            doc_idx += 1;
                        }
                    }
                }
                
                // Report credentials from other sets if present (multi-credential support)
                for (other_set_idx, other_set) in match_result.matched_credential_sets.iter().enumerate().skip(1) {
                    let other_option = &other_set[0];
                    log::debug!("Reporting supplemental credential set index {}", other_set_idx);
                    for cred_id in &other_option.matched_credential_ids {
                         if let Some(matched_cred_set) = match_result.matched_credentials.get(cred_id) {
                            for entry in &matched_cred_set.matched {
                                log::trace!("Reporting supplemental credential entry {} at index {}", entry.id, doc_idx);
                                report_matched_entry(
                                    credman,
                                    entry,
                                    &credentials_buffer,
                                    &set_id,
                                    doc_idx,
                                    request_idx,
                                    wasm_version,
                                    &transaction_credential_ids,
                                    merchant_name.as_deref(),
                                    transaction_amount.as_deref(),
                                    additional_info.as_deref(),
                                    Some(cred_id),
                                    Some(&other_option.set_id),
                                    Some(&other_option.option_id),
                                )?;
                                doc_idx += 1;
                            }
                        }
                    }
                }
            }
        } else if !match_result.matched_credentials.is_empty() && query.credential_sets.is_none() {
            log::info!("Reporting results for request {} (no credential_sets)", request_idx);
            let set_id_str = format!("req:{};null", request_idx);
            let set_id = CString::new(set_id_str.clone())?;
            let total_length = match_result.matched_credentials.values().fold(0, |acc, v| acc + v.matched.len());
            
            if wasm_version > 1 {
                log::trace!("Calling add_entry_set: id={}, length={}", set_id_str, total_length);
                credman.add_entry_set(&set_id, total_length as i32);
            }

            let mut doc_idx = 0;
            for dcql_cred in &query.credentials {
                let cred_id = &dcql_cred.id;
                if let Some(matched_cred_set) = match_result.matched_credentials.get(cred_id) {
                    log::debug!("Reporting results for DCQL cred id: {}", cred_id);
                    for entry in &matched_cred_set.matched {
                        log::trace!("Reporting credential entry {} at index {}", entry.id, doc_idx);
                        report_matched_entry(
                            credman,
                            entry,
                            &credentials_buffer,
                            &set_id,
                            doc_idx,
                            request_idx,
                            wasm_version,
                            &transaction_credential_ids,
                            merchant_name.as_deref(),
                            transaction_amount.as_deref(),
                            additional_info.as_deref(),
                            Some(cred_id),
                            None,
                            None,
                        )?;
                        doc_idx += 1;
                    }
                }
            }
        } else {
            log::info!("No matches found for request index {}", request_idx);
        }

        if let Some(inline) = match_result.inline_issuance {
            log::info!("Reporting inline issuance entry: {}", inline.id);
            let cred_id = CString::new(inline.id)?;
            let title = inline.title.as_ref().map(|s| CString::new(s.clone())).transpose()?;
            let subtitle = inline.subtitle.as_ref().map(|s| CString::new(s.clone())).transpose()?;
            let icon = if let Some(info) = inline.icon {
                Some(&credentials_buffer[info.start as usize..(info.start + info.length) as usize])
            } else {
                None
            };
            credman.add_inline_issuance_entry(&cred_id, icon, title.as_deref(), subtitle.as_deref());
        }
    }

    log::info!("OpenID4VP presentation matching finished");
    Ok(())
}

fn report_matched_entry(
    credman: &mut impl CredmanApi,
    entry: &MatchedEntry,
    creds_blob: &[u8],
    set_id: &CStr,
    doc_idx: i32,
    request_idx: usize,
    wasm_version: u32,
    transaction_credential_ids: &Option<Vec<String>>,
    merchant_name: Option<&str>,
    transaction_amount: Option<&str>,
    additional_info: Option<&str>,
    dcql_cred_id: Option<&str>,
    dcql_set_idx: Option<&str>,
    dcql_option_idx: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry_id = CString::new(entry.id.clone())?;
    let verification = entry.display.verification.as_ref().ok_or_else(|| {
        log::error!("Registry entry {} missing verification display properties", entry.id);
        "Missing verification display"
    })?;
    let title = CString::new(verification.title.clone())?;
    let subtitle = verification.subtitle.as_ref().map(|s| CString::new(s.clone())).transpose()?;
    let explainer = verification.explainer.as_ref().map(|s| CString::new(s.clone())).transpose()?;
    let metadata_display_text = verification.metadata_display_text.as_ref().map(|s| CString::new(s.clone())).transpose()?;

    let icon = if let Some(info) = &verification.icon {
        if (info.start + info.length) as usize <= creds_blob.len() {
            Some(&creds_blob[info.start as usize..(info.start + info.length) as usize])
        } else {
            log::error!("Icon range [{}, {}] out of bounds for registry blob size {}", info.start, info.start + info.length, creds_blob.len());
            None
        }
    } else {
        None
    };

    let matched_paths: Vec<Vec<String>> = entry.matched_claims.iter().map(|c| c.path.clone()).collect();
    let mut metadata_str = format!(r#"{{"claims":{:?},"dc_request_index":{}"#, matched_paths, request_idx);
    if let Some(cid) = dcql_cred_id {
        metadata_str.push_str(&format!(r#","dcql_cred_id":"{}""#, cid));
    }
    if let (Some(sid), Some(oid)) = (dcql_set_idx, dcql_option_idx) {
        metadata_str.push_str(&format!(r#","dcql_credential_set_index":"{}","dcql_option_index":"{}""#, sid, oid));
    }
    metadata_str.push('}');
    let metadata_cstring = CString::new(metadata_str.clone())?;

    let is_transaction = if let Some(tx_ids) = transaction_credential_ids {
        if let Some(cid) = dcql_cred_id {
            let matched = tx_ids.iter().any(|id| id == cid);
            if matched {
                 log::debug!("Credential ID {} matched for transaction", cid);
            }
            matched
        } else {
            false
        }
    } else {
        false
    };

    if is_transaction {
        log::info!("Reporting payment entry for credential: {}", entry.id);
        let m_name = CString::new(merchant_name.unwrap_or(""))?;
        let t_amount = CString::new(transaction_amount.unwrap_or(""))?;
        let a_info = additional_info.map(|s| CString::new(s.to_string())).transpose()?;
        
        credman.add_payment_entry_to_set_v2(
            &entry_id,
            &m_name,
            &title,
            subtitle.as_deref(),
            icon,
            &t_amount,
            a_info.as_deref(),
            &metadata_cstring,
            set_id,
            doc_idx,
        );
    } else {
        log::info!("Reporting standard entry for credential: {}, set_id={:?}, index={}", entry.id, set_id, doc_idx);
        log::trace!("Entry metadata: {}", metadata_str);
        credman.add_entry_to_set(
            &entry_id,
            icon,
            &title,
            subtitle.as_deref(),
            explainer.as_deref(),
            &metadata_cstring,
            set_id,
            doc_idx,
        );

        log::debug!("Reporting {} matched fields for credential: {}", entry.matched_claims.len(), entry.id);
        for matched_claim in &entry.matched_claims {
            if let Some(v) = &matched_claim.display.verification {
                let display_name = CString::new(v.display.clone())?;
                let display_value = if let Some(dv) = &v.display_value {
                    Some(CString::new(dv.clone())?)
                } else if let Some(val) = &matched_claim.value {
                    Some(CString::new(val.clone())?)
                } else {
                    None
                };
                log::trace!("  Field: {} = {:?}", v.display, display_value.as_ref().map(|s| s.to_string_lossy()));
                credman.add_field_to_entry_set(&entry_id, &display_name, display_value.as_deref(), set_id, doc_idx);
            }
        }

        if wasm_version >= 5 {
            if let Some(mdt) = metadata_display_text {
                log::trace!("  Metadata display text: {:?}", mdt.to_string_lossy());
                credman.add_metadata_display_text_to_entry_set(&entry_id, &mdt, set_id, doc_idx);
            }
        }
    }

    Ok(())
}

/// Decodes Base64URL strings manually to avoid additional dependencies and keep
/// the WASM binary size minimal.
fn decode_b64_url(input: &str) -> Result<Vec<u8>, String> {
    let mut input = input.to_string();
    input = input.replace('-', "+").replace('_', "/");
    while input.len() % 4 != 0 {
        input.push('=');
    }
    
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    
    for c in input.chars() {
        if c == '=' { break; }
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("Invalid character: {}", c)),
        };
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::CStr;

    struct AddedEntry {
        cred_id: String,
        title: String,
        subtitle: Option<String>,
        fields: Vec<(String, Option<String>)>,
    }

    struct FakeCredman {
        request_json: String,
        registry_json: String,
        wasm_version: u32,
        added_entries: Vec<AddedEntry>,
        added_sets: HashMap<String, i32>,
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
        fn add_entry_to_set(&mut self, cred_id: &CStr, _icon: Option<&[u8]>, title: &CStr, subtitle: Option<&CStr>, _explainer: Option<&CStr>, _metadata: &CStr, _set_id: &CStr, _set_index: i32) {
            self.added_entries.push(AddedEntry {
                cred_id: cred_id.to_str().unwrap().to_string(),
                title: title.to_str().unwrap().to_string(),
                subtitle: subtitle.map(|s| s.to_str().unwrap().to_string()),
                fields: Vec::new(),
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
        fn add_payment_entry_to_set_v2(&mut self, _cred_id: &CStr, _merchant_name: &CStr, _title: &CStr, _subtitle: Option<&CStr>, _icon: Option<&[u8]>, _transaction_amount: &CStr, _additional_info: Option<&CStr>, _metadata: &CStr, _set_id: &CStr, _set_index: i32) {}
        fn add_inline_issuance_entry(&mut self, _cred_id: &CStr, _icon: Option<&[u8]>, _title: Option<&CStr>, _subtitle: Option<&CStr>) {}
        fn add_metadata_display_text_to_entry_set(&mut self, _cred_id: &CStr, _metadata_display_text: &CStr, _set_id: &CStr, _set_index: i32) {}
        fn add_string_id_entry(&mut self, _entry_id: &CStr, _icon: Option<&[u8]>, _title: Option<&CStr>, _subtitle: Option<&CStr>, _disclaimer: Option<&CStr>, _warning: Option<&CStr>) {}
    }

    #[test]
    fn test_match_mdoc_basic() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "org.iso.18013.5.1.mDL": [
                        {
                            "id": "my_mdl",
                            "display": { "verification": { "title": "My Driver's License" } },
                            "paths": {
                                "org.iso.18013.5.1": {
                                    "family_name": {
                                        "display": { "verification": { "display": "Last Name" } },
                                        "value": "Doe"
                                    },
                                    "given_name": {
                                        "display": { "verification": { "display": "First Name" } },
                                        "value": "John"
                                    }
                                }
                            }
                        }
                    ]
                },
                "dc+sd-jwt": {},
                "issuance": { "mso_mdoc": [], "dc+sd-jwt": [] }
            }
        }"#;

        let request_json = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "mdl_request",
                                    "format": "mso_mdoc",
                                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                                    "claims": [
                                        { "path": ["org.iso.18013.5.1", "family_name"] }
                                    ]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let mut credman = FakeCredman {
            request_json: request_json.to_string(),
            registry_json: registry_json.to_string(),
            wasm_version: 2,
            added_entries: Vec::new(),
            added_sets: HashMap::new(),
        };

        presentation_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 1);
        let entry = &credman.added_entries[0];
        assert_eq!(entry.cred_id, "my_mdl");
        assert_eq!(entry.title, "My Driver's License");
        assert_eq!(entry.fields.len(), 1);
        assert_eq!(entry.fields[0].0, "Last Name");
        assert_eq!(entry.fields[0].1, Some("Doe".to_string()));
    }

    #[test]
    fn test_claim_sets_matching() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "org.iso.18013.5.1.mDL": [
                        {
                            "id": "my_mdl",
                            "display": { "verification": { "title": "My Driver's License" } },
                            "paths": {
                                "org.iso.18013.5.1": {
                                    "family_name": {
                                        "display": { "verification": { "display": "Last Name" } },
                                        "value": "Doe"
                                    }
                                }
                            }
                        }
                    ]
                },
                "dc+sd-jwt": {},
                "issuance": { "mso_mdoc": [], "dc+sd-jwt": [] }
            }
        }"#;

        let request_json = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "mdl_request",
                                    "format": "mso_mdoc",
                                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                                    "claims": [
                                        { "id": "last_name", "path": ["org.iso.18013.5.1", "family_name"] },
                                        { "id": "first_name", "path": ["org.iso.18013.5.1", "given_name"] }
                                    ],
                                    "claim_sets": [
                                        ["last_name"],
                                        ["first_name"]
                                    ]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let mut credman = FakeCredman {
            request_json: request_json.to_string(),
            registry_json: registry_json.to_string(),
            wasm_version: 2,
            added_entries: Vec::new(),
            added_sets: HashMap::new(),
        };

        presentation_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 1);
        let entry = &credman.added_entries[0];
        assert_eq!(entry.fields.len(), 1);
        assert_eq!(entry.fields[0].0, "Last Name");
    }

    #[test]
    fn test_credential_sets_and_payment() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "org.iso.18013.5.1.mDL": [
                        {
                            "id": "my_mdl",
                            "display": { "verification": { "title": "My Driver's License" } },
                            "paths": { "org.iso.18013.5.1": { "family_name": { "display": { "verification": { "display": "Last Name" } }, "value": "Doe" } } }
                        }
                    ]
                },
                "dc+sd-jwt": {},
                "issuance": { "mso_mdoc": [], "dc+sd-jwt": [] }
            }
        }"#;

        // Transaction data: {"type": "payment", "merchant_name": "Acme", "amount": "5 USD", "credential_ids": ["mdl_req"]}
        // Base64 URL: eyJ0eXBlIjogInBheW1lbnQiLCAibWVyY2hhbnRfbmFtZSI6ICJBY21lIiwgImFtb3VudCI6ICI1IFVTRCIsICJjcmVkZW50aWFsX2lkcyI6IFsibWRsX3JlcSJdfQ
        let request_json = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "mdl_req",
                                    "format": "mso_mdoc",
                                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
                                }
                            ],
                            "credential_sets": [
                                { "options": [ ["mdl_req"] ] }
                            ]
                        },
                        "transaction_data": ["eyJ0eXBlIjogInBheW1lbnQiLCAibWVyY2hhbnRfbmFtZSI6ICJBY21lIiwgImFtb3VudCI6ICI1IFVTRCIsICJjcmVkZW50aWFsX2lkcyI6IFsibWRsX3JlcSJdfQ"]
                    }
                }
            ]
        }"#;

        struct PaymentCredman {
            base: FakeCredman,
            payment_added: bool,
        }
        impl CredmanApi for PaymentCredman {
            fn get_request_buffer(&self) -> Vec<u8> { self.base.get_request_buffer() }
            fn get_registered_data(&self) -> Vec<u8> { self.base.get_registered_data() }
            fn get_wasm_version(&self) -> u32 { self.base.get_wasm_version() }
            fn add_entry_set(&mut self, id: &CStr, len: i32) { self.base.add_entry_set(id, len) }
            fn add_entry_to_set(&mut self, id: &CStr, icon: Option<&[u8]>, t: &CStr, s: Option<&CStr>, e: Option<&CStr>, m: &CStr, sid: &CStr, idx: i32) { self.base.add_entry_to_set(id, icon, t, s, e, m, sid, idx) }
            fn add_field_to_entry_set(&mut self, id: &CStr, n: &CStr, v: Option<&CStr>, sid: &CStr, idx: i32) { self.base.add_field_to_entry_set(id, n, v, sid, idx) }
            fn add_payment_entry_to_set_v2(&mut self, _id: &CStr, merchant: &CStr, _title: &CStr, _sub: Option<&CStr>, _icon: Option<&[u8]>, amount: &CStr, _info: Option<&CStr>, _meta: &CStr, _sid: &CStr, _idx: i32) {
                if merchant.to_str().unwrap() == "Acme" && amount.to_str().unwrap() == "5 USD" {
                    self.payment_added = true;
                }
            }
            fn add_inline_issuance_entry(&mut self, id: &CStr, icon: Option<&[u8]>, t: Option<&CStr>, s: Option<&CStr>) { self.base.add_inline_issuance_entry(id, icon, t, s) }
            fn add_metadata_display_text_to_entry_set(&mut self, id: &CStr, t: &CStr, sid: &CStr, idx: i32) { self.base.add_metadata_display_text_to_entry_set(id, t, sid, idx) }
            fn add_string_id_entry(&mut self, id: &CStr, icon: Option<&[u8]>, t: Option<&CStr>, s: Option<&CStr>, d: Option<&CStr>, w: Option<&CStr>) { self.base.add_string_id_entry(id, icon, t, s, d, w) }
        }

        let mut credman = PaymentCredman {
            base: FakeCredman {
                request_json: request_json.to_string(),
                registry_json: registry_json.to_string(),
                wasm_version: 2,
                added_entries: Vec::new(),
                added_sets: HashMap::new(),
            },
            payment_added: false,
        };

        presentation_main(&mut credman).unwrap();
        assert!(credman.payment_added);
    }

    #[test]
    fn test_dcql_no_match() {
        let registry_json = r#"{
            "credentials": {
                "mso_mdoc": {
                    "org.iso.18013.5.1.mDL": [
                        {
                            "id": "my_mdl",
                            "display": { "verification": { "title": "My Driver's License" } },
                            "paths": { "org.iso.18013.5.1": { "family_name": { "display": { "verification": { "display": "Last Name" } }, "value": "Doe" } } }
                        }
                    ]
                },
                "dc+sd-jwt": {},
                "issuance": { "mso_mdoc": [], "dc+sd-jwt": [] }
            }
        }"#;

        // Case 1: Wrong Doctype
        let request_json_1 = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "wrong_doctype",
                                    "format": "mso_mdoc",
                                    "meta": { "doctype_value": "wrong.doctype" }
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let mut credman = FakeCredman {
            request_json: request_json_1.to_string(),
            registry_json: registry_json.to_string(),
            wasm_version: 2,
            added_entries: Vec::new(),
            added_sets: HashMap::new(),
        };
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 0);

        // Case 2: Missing Claim
        let request_json_2 = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "mdl_request",
                                    "format": "mso_mdoc",
                                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                                    "claims": [
                                        { "path": ["org.iso.18013.5.1", "non_existent_claim"] }
                                    ]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;
        credman.request_json = request_json_2.to_string();
        credman.added_entries.clear();
        presentation_main(&mut credman).unwrap();
        assert_eq!(credman.added_entries.len(), 0);
    }
}
