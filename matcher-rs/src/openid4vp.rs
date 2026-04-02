use crate::credman::CredmanApi;
use crate::json_value::{DeterministicMap, JsonValue};
pub use crate::openid4vp_models::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nanoserde::DeJson;
use std::borrow::Cow;

pub fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

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
    matched_credential_sets: &[Vec<MatchedCredentialSetInfo>],
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
    c: &MatchedCredential,
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
        &c.id,
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
    c: &MatchedCredential,
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
        &c.id,
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

        credman.add_field_to_entry_set(
            &c.id,
            display_name,
            display_value,
            set_id,
            doc_idx,
        );
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
    matched_doc: &DcqlMatchedCredentialEntry,
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
        let metadata = Metadata {
            claims: c.matched_claim_metadata.clone(),
            dc_request_index: request_id,
            dcql_cred_id: matched_credential_id.to_string(),
            dcql_credential_set_index: dcql_set_idx.unwrap_or("").to_string(),
            dcql_option_index: dcql_option_idx.unwrap_or("").to_string(),
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
    matched_credential_sets: &[Vec<MatchedCredentialSetInfo>],
    curr_doc_idx: &mut i32,
    wasm_version: u32,
    matched_docs: &DeterministicMap<String, DcqlMatchedCredentialEntry>,
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
            let Some(doc) = matched_docs.get(cred_id) else {
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
                let Some(doc) = res.matched_credentials.get(cred_id) else {
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

        credman.add_inline_issuance_entry(
            &inline.id,
            icon_bytes,
            &inline.title,
            &inline.subtitle,
        );
    }

    Ok(())
}

#[cfg(test)]
mod openid4vp_test;


