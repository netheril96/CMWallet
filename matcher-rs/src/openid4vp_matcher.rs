use std::ffi::{CStr, CString};
use nanoserde::DeJson;

use crate::{
    credman::CredmanApi,
    dcql::{dcql_query, CredentialStore, MatchedCredential, MatchedOption, MatchResult, ClaimDisplayInfo},
    openid4vp::{decode_b64url, OpenId4VpRequestContainer, OpenId4VpRequestDataEnum, TransactionData},
};

const PROTOCOL_OPENID4VP_1_0_UNSIGNED: &str = "openid4vp-v1-unsigned";
const PROTOCOL_OPENID4VP_1_0_SIGNED: &str = "openid4vp-v1-signed";

pub fn openid4vp_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    let creds_buffer = credman.get_registered_data();
    if creds_buffer.len() < 4 {
        return Ok(());
    }
    let json_offset = u32::from_le_bytes(creds_buffer[..4].try_into()?) as usize;
    let creds_json_str = std::str::from_utf8(&creds_buffer[json_offset..])?;
    let store = CredentialStore::deserialize_json(creds_json_str)?;

    let request_buffer = credman.get_request_buffer();
    let request_json_str = std::str::from_utf8(&request_buffer)?;
    let container = OpenId4VpRequestContainer::deserialize_json(request_json_str)?;

    let requests = container.requests.or(container.providers).unwrap_or_default();
    let wasm_version = credman.get_wasm_version();

    for (req_idx, req) in requests.iter().enumerate() {
        if req.protocol == PROTOCOL_OPENID4VP_1_0_UNSIGNED || req.protocol == PROTOCOL_OPENID4VP_1_0_SIGNED {
            let mut data = match &req.data {
                OpenId4VpRequestDataEnum::Object(d) => d.clone(),
                OpenId4VpRequestDataEnum::String(s) => crate::openid4vp::OpenId4VpRequestData::deserialize_json(s)?,
            };

            if req.protocol == PROTOCOL_OPENID4VP_1_0_SIGNED {
                if let Some(signed_req_jwt) = &data.request {
                    let parts: Vec<&str> = signed_req_jwt.split('.').collect();
                    if parts.len() >= 2 {
                        if let Some(decoded_payload) = decode_b64url(parts[1]) {
                            let payload_str = std::str::from_utf8(&decoded_payload)?;
                            data = crate::openid4vp::OpenId4VpRequestData::deserialize_json(payload_str)?;
                        }
                    }
                }
            }

            if let Some(query) = &data.dcql_query {
                let match_result = dcql_query(query, &store);

                if !match_result.matched_credential_sets.is_empty() {
                    let (merchant_name, transaction_amount, additional_info, transaction_credential_ids) = 
                        extract_transaction_info(&data);

                    for options in &match_result.matched_credential_sets {
                        for opt in options {
                            let set_id_str = if opt.set_id == "null" {
                                format!("req:{};null", req_idx)
                            } else {
                                format!("req:{};set:{};option:{}", req_idx, opt.set_id, opt.option_id)
                            };
                            let set_id = CString::new(set_id_str)?;

                            if wasm_version > 1 {
                                let total_length = calculate_set_length(0, 0, &match_result.matched_credential_sets);
                                credman.add_entry_set(&set_id, total_length as i32);
                            }
                            
                            for (doc_idx, cred_id) in opt.matched_credential_ids.iter().enumerate() {
                                if let Some(matched_info) = match_result.matched_credentials.get(cred_id) {
                                    for m_cred in &matched_info.matched {
                                        report_matched(
                                            credman, 
                                            wasm_version,
                                            m_cred, 
                                            doc_idx, 
                                            req_idx, 
                                            &set_id, 
                                            &creds_buffer,
                                            merchant_name.as_deref(),
                                            transaction_amount.as_deref(),
                                            additional_info.as_deref(),
                                            transaction_credential_ids.as_ref(),
                                            cred_id
                                        )?;
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(inline) = match_result.inline_issuance {
                    let cred_id = CString::new(inline.id)?;
                    let title = CString::new(inline.title)?;
                    let subtitle = CString::new(inline.subtitle)?;
                    let icon_bytes = inline.icon.as_ref().map(|ic| &creds_buffer[ic.start..ic.start + ic.length]);
                    credman.add_inline_issuance_entry(&cred_id, icon_bytes, &title, &subtitle);
                }
            }
        }
    }

    Ok(())
}

fn extract_transaction_info(data: &crate::openid4vp::OpenId4VpRequestData) -> (Option<String>, Option<String>, Option<String>, Option<Vec<String>>) {
    let mut merchant_name = None;
    let mut transaction_amount = None;
    let mut additional_info = None;
    let mut transaction_credential_ids = None;

    if let Some(trans_list) = &data.transaction_data {
        if trans_list.len() == 1 {
            if let Some(decoded) = decode_b64url(&trans_list[0]) {
                if let Ok(trans_json_str) = std::str::from_utf8(&decoded) {
                    if let Ok(trans_data) = TransactionData::deserialize_json(trans_json_str) {
                        transaction_credential_ids = trans_data.credential_ids;
                        additional_info = trans_data.additional_info;
                        if trans_data.type_field == "urn:eudi:sca:payment:1" {
                            if let Some(payload) = trans_data.payload {
                                merchant_name = payload.payee.map(|p| p.name);
                                if let (Some(amt), Some(curr)) = (payload.amount, payload.currency) {
                                    transaction_amount = Some(format!("{} {}", curr, amt));
                                }
                            }
                        } else if trans_data.type_field == "payment_details" {
                            merchant_name = trans_data.payee_name;
                            if let (Some(amt), Some(curr)) = (trans_data.payment_amount, trans_data.payment_currency) {
                                transaction_amount = Some(format!("{} {}", curr, amt));
                            }
                        } else {
                            merchant_name = trans_data.merchant_name;
                            transaction_amount = trans_data.amount;
                        }
                    }
                }
            }
        }
    }
    (merchant_name, transaction_amount, additional_info, transaction_credential_ids)
}

fn calculate_set_length(curr_idx: usize, curr_len: usize, sets: &Vec<Vec<MatchedOption>>) -> usize {
    if curr_idx >= sets.len() {
        return curr_len;
    }
    let mut total = 0;
    for opt in &sets[curr_idx] {
        total += calculate_set_length(curr_idx + 1, curr_len + opt.matched_credential_ids.len(), sets);
    }
    total
}

fn report_matched(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    m_cred: &MatchedCredential,
    doc_idx: usize,
    req_idx: usize,
    set_id: &CStr,
    creds_blob: &[u8],
    merchant_name: Option<&str>,
    transaction_amount: Option<&str>,
    additional_info: Option<&str>,
    transaction_credential_ids: Option<&Vec<String>>,
    dcql_cred_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let matched_id = CString::new(m_cred.id.clone())?;
    
    // Metadata JSON for host
    // { "claims": [...], "dc_request_index": i, "dcql_cred_id": "..." }
    let claims_json = nanoserde::SerJson::serialize_json(&m_cred.matched_claim_metadata);
    let metadata_str = format!(
        "{{\"claims\":{},\"dc_request_index\":{},\"dcql_cred_id\":\"{}\"}}",
        claims_json, req_idx, dcql_cred_id
    );
    let metadata = CString::new(metadata_str)?;

    let is_payment = if let Some(ids) = transaction_credential_ids {
        ids.iter().any(|id| id == dcql_cred_id)
    } else {
        false
    };

    if is_payment {
        let m_name = CString::new(merchant_name.unwrap_or(""))?;
        let t_amount = CString::new(transaction_amount.unwrap_or(""))?;
        let a_info = additional_info.map(|s| CString::new(s).unwrap()).or(None);
        
        let mut title = None;
        let mut subtitle = None;
        let mut icon_bytes = None;
        
        if let Some(display) = &m_cred.display {
            if let Some(ver) = &display.verification {
                title = ver.title.as_ref().map(|s| CString::new(s.clone())).transpose()?;
                subtitle = ver.subtitle.as_ref().map(|s| CString::new(s.clone())).transpose()?;
                icon_bytes = ver.icon.as_ref().map(|ic| &creds_blob[ic.start..ic.start + ic.length]);
            }
        }

        credman.add_payment_entry_to_set_v2(
            &matched_id,
            &m_name,
            title.as_deref().unwrap_or(&CString::new("")?),
            subtitle.as_deref().unwrap_or(&CString::new("")?),
            icon_bytes,
            &t_amount,
            a_info.as_deref(),
            &metadata,
            set_id,
            doc_idx as i32,
        );
    } else {
        let mut title = None;
        let mut subtitle = None;
        let mut icon_bytes = None;
        let mut explainer = None;
        
        if let Some(display) = &m_cred.display {
            if let Some(ver) = &display.verification {
                title = ver.title.as_ref().map(|s| CString::new(s.clone())).transpose()?;
                subtitle = ver.subtitle.as_ref().map(|s| CString::new(s.clone())).transpose()?;
                explainer = ver.explainer.as_ref().map(|s| CString::new(s.clone())).transpose()?;
                icon_bytes = ver.icon.as_ref().map(|ic| &creds_blob[ic.start..ic.start + ic.length]);
            }
        }

        if wasm_version > 1 {
            credman.add_entry_to_set(
                &matched_id,
                icon_bytes,
                title.as_deref(),
                subtitle.as_deref(),
                explainer.as_deref(),
                None,
                &metadata,
                set_id,
                doc_idx as i32,
            );
        } else {
            credman.add_string_id_entry(
                &matched_id,
                icon_bytes,
                title.as_deref(),
                subtitle.as_deref(),
                None,
                None,
            );
        }

        for claim in &m_cred.matched_claim_names {
            let c_name = CString::new(claim.display.clone())?;
            let c_value = CString::new(claim.display_value.clone())?;
            credman.add_field_to_entry_set(&matched_id, &c_name, &c_value, set_id, doc_idx as i32);
        }
    }

    Ok(())
}
