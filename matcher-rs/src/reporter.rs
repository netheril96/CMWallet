use crate::json_value::{DeterministicMap, JsonValue};
use crate::credman::CredmanApi;
use crate::openid4vp_models::*;
use crate::base64url::decode_base64url;
use nanoserde::DeJson;

/// Reports a credential as a payment transaction entry to Credential Manager.
fn report_payment_transaction_entry(
    credman: &mut impl CredmanApi,
    matched_credential: &MatchedCredential<'_>,
    document_index: i32,
    credential_set_id: &str,
    selection_metadata_json: &str,
    merchant_name: &str,
    transaction_amount: &str,
    additional_info: &str,
    credentials_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Reporting as payment entry: {}", matched_credential.id);

    // Extract icon bytes from the blob if available.
    let icon_bytes = matched_credential
        .display
        .verification
        .icon
        .as_ref()
        .map_or(&[][..], |icon| &credentials_blob[icon.start..icon.start + icon.length]);

    credman.add_payment_entry_to_set_v2(
        matched_credential.id,
        merchant_name,
        &matched_credential.display.verification.title,
        &matched_credential.display.verification.subtitle,
        icon_bytes,
        transaction_amount,
        &[], // bank_icon (empty for now)
        &[], // provider_icon (empty for now)
        additional_info,
        selection_metadata_json,
        credential_set_id,
        document_index,
    );
    Ok(())
}

/// Reports a credential as a standard verification entry to Credential Manager.
fn report_standard_verification_entry(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    matched_credential: &MatchedCredential<'_>,
    document_index: i32,
    credential_set_id: &str,
    selection_metadata_json: &str,
    credentials_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Reporting as standard entry: {}", matched_credential.id);

    // Extract icon bytes from the blob if available.
    let icon_bytes = matched_credential
        .display
        .verification
        .icon
        .as_ref()
        .map_or(&[][..], |icon| &credentials_blob[icon.start..icon.start + icon.length]);

    credman.add_entry_to_set(
        matched_credential.id,
        icon_bytes,
        &matched_credential.display.verification.title,
        &matched_credential.display.verification.subtitle,
        &matched_credential.display.verification.explainer,
        "", // warning (empty for now)
        selection_metadata_json,
        credential_set_id,
        document_index,
    );

    log::trace!(
        "Reporting {} claims for entry {}",
        matched_credential.matched_claim_names.len(),
        matched_credential.id
    );
    // Report individual fields/claims for this credential.
    for claim in &matched_credential.matched_claim_names {
        let JsonValue::Object(claim_obj) = claim else {
            continue;
        };

        let Some(JsonValue::Object(verification_obj)) = claim_obj.get("verification") else {
            continue;
        };

        let Some(JsonValue::String(display_name)) = verification_obj.get("display") else {
            continue;
        };

        let display_value = match verification_obj.get("display_value") {
            Some(JsonValue::String(s)) => s,
            _ => "",
        };

        credman.add_field_to_entry_set(
            matched_credential.id,
            display_name,
            display_value,
            credential_set_id,
            document_index,
        );
    }

    // Report metadata display text if supported by Wasm version.
    if wasm_version >= 5 && !matched_credential.display.verification.metadata_display_text.is_empty() {
        log::trace!(
            "Adding metadata display text: {}",
            matched_credential.display.verification.metadata_display_text
        );
        credman.add_metadata_display_text_to_entry_set(
            matched_credential.id,
            &matched_credential.display.verification.metadata_display_text,
            credential_set_id,
            document_index,
        );
    }
    Ok(())
}

/// Reports a matched credential, deciding whether it's a payment or standard entry.
fn report_matched_credential(
    credman: &mut impl CredmanApi,
    wasm_version: u32,
    matched_credential_entry: &DcqlMatchedCredentialEntry<'_>,
    matched_credential_id: &str,
    document_index: i32,
    request_idx: usize,
    credential_set_id: &str,
    dcql_set_idx: Option<&str>,
    dcql_option_idx: Option<&str>,
    credentials_blob: &[u8],
    transaction_info: &Option<(Vec<String>, String, String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!(
        "Reporting matched credential: id={}, dcql_id={}, doc_idx={}",
        matched_credential_entry.id,
        matched_credential_id,
        document_index
    );
    for matched_credential in &matched_credential_entry.matched {
        let metadata = SelectionMetadata {
            claims: &matched_credential.matched_claim_metadata,
            dc_request_index: request_idx,
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
                    matched_credential,
                    document_index,
                    credential_set_id,
                    &metadata_str,
                    merchant,
                    amount,
                    additional,
                    credentials_blob,
                )?;
                reported = true;
            }
        }

        if !reported {
            report_standard_verification_entry(
                credman,
                wasm_version,
                matched_credential,
                document_index,
                credential_set_id,
                &metadata_str,
                credentials_blob,
            )?;
        }
    }
    Ok(())
}

/// Extracts transaction info from OpenId4VpData if present.
fn extract_transaction_info(
    openid4vp_data: &OpenId4VpData,
) -> Result<Option<(Vec<String>, String, String, String)>, Box<dyn std::error::Error>> {
    if openid4vp_data.transaction_data.len() != 1 {
        return Ok(None);
    }

    log::debug!("Decoding transaction data");
    let decoded = decode_base64url(&openid4vp_data.transaction_data[0])?;
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

/// Main entry point for reporting match results to Credential Manager.
/// It generates the Cartesian product of all options across all matched sets.
pub fn report_match_result(
    credman: &mut impl CredmanApi,
    match_result: &DcqlMatchResult<'_>,
    request_idx: usize,
    openid4vp_data: &OpenId4VpData,
    credentials_blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let wasm_version = credman.get_wasm_version();
    log::info!("Reporting match results. Wasm version: {}", wasm_version);

    if !match_result.matched_credential_sets.is_empty() {
        let transaction_info = extract_transaction_info(openid4vp_data)?;
        
        // Recursive helper to generate Cartesian product.
        fn report_combinations(
            credman: &mut impl CredmanApi,
            wasm_version: u32,
            request_idx: usize,
            credential_sets: &[Vec<MatchedCredentialSetInfo<'_>>],
            selected_option_indices: &mut Vec<usize>,
            candidate_matched_credentials: &DeterministicMap<&str, DcqlMatchedCredentialEntry<'_>>,
            credentials_blob: &[u8],
            transaction_info: &Option<(Vec<String>, String, String, String)>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            if selected_option_indices.len() == credential_sets.len() {
                // We have selected one option from each set. Now report this combination.
                let mut set_id_parts = vec![format!("req:{}", request_idx)];
                let mut total_length = 0;
                
                for (set_idx, &option_idx) in selected_option_indices.iter().enumerate() {
                    let option = &credential_sets[set_idx][option_idx];
                    if !option.set_id.is_empty() {
                        set_id_parts.push(format!("set:{};option:{}", option.set_id, option.option_id));
                    }
                    total_length += option.matched_credential_ids.len();
                }
                
                // Preserve the "req:N;null" format for implicit sets (no explicit sets matched).
                let set_id_str = if set_id_parts.len() == 1 {
                    format!("req:{};null", request_idx)
                } else {
                    set_id_parts.join(";")
                };
                
                if wasm_version > 1 {
                    credman.add_entry_set(&set_id_str, total_length as i32);
                }
                
                let mut document_index = 0;
                for (set_idx, &option_idx) in selected_option_indices.iter().enumerate() {
                    let option = &credential_sets[set_idx][option_idx];
                    for matched_credential_id in &option.matched_credential_ids {
                        let Some(doc) = candidate_matched_credentials.get(*matched_credential_id) else {
                            continue;
                        };
                        report_matched_credential(
                            credman,
                            wasm_version,
                            doc,
                            matched_credential_id,
                            document_index,
                            request_idx,
                            &set_id_str,
                            Some(&option.set_id),
                            Some(&option.option_id),
                            credentials_blob,
                            transaction_info,
                        )?;
                        document_index += 1;
                    }
                }
                return Ok(());
            }
            
            // Recurse to pick options for the next set.
            let next_set_idx = selected_option_indices.len();
            for option_idx in 0..credential_sets[next_set_idx].len() {
                selected_option_indices.push(option_idx);
                report_combinations(
                    credman,
                    wasm_version,
                    request_idx,
                    credential_sets,
                    selected_option_indices,
                    candidate_matched_credentials,
                    credentials_blob,
                    transaction_info,
                )?;
                selected_option_indices.pop();
            }
            
            Ok(())
        }
        
        let mut selected_option_indices = Vec::new();
        report_combinations(
            credman,
            wasm_version,
            request_idx,
            &match_result.matched_credential_sets,
            &mut selected_option_indices,
            &match_result.matched_credentials,
            credentials_blob,
            &transaction_info,
        )?;
    }

    if let Some(inline) = &match_result.inline_issuance {
        log::info!("Reporting inline issuance entry: {}", inline.id);
        let icon_bytes = inline
            .icon
            .as_ref()
            .map_or(&[][..], |icon| &credentials_blob[icon.start..icon.start + icon.length]);

        credman.add_inline_issuance_entry(&inline.id, icon_bytes, &inline.title, &inline.subtitle);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;
    
    #[test]
    fn test_report_match_result_empty() {
        let mut credman = FakeCredman::new();
        let match_result = DcqlMatchResult {
            matched_credential_sets: vec![],
            matched_credentials: DeterministicMap::new(),
            inline_issuance: None,
        };
        let openid4vp_data = OpenId4VpData::default();
        let credentials_blob = vec![];
        
        report_match_result(&mut credman, &match_result, 0, &openid4vp_data, &credentials_blob).unwrap();
        
        assert!(credman.entry_sets.is_empty());
        assert!(credman.standalone_entries.is_empty());
    }
    
    #[test]
    fn test_report_standard_verification_entry() {
        let mut credman = FakeCredman::new();
        credman.add_entry_set("test_set", 1);
        
        let display = RegistryDisplay::default();
        let matched_credential = MatchedCredential {
            id: "test_cred",
            display: &display,
            matched_claim_names: vec![],
            matched_claim_metadata: vec![],
        };
        
        report_standard_verification_entry(
            &mut credman,
            1,
            &matched_credential,
            0,
            "test_set",
            "{}",
            &[],
        ).unwrap();
        
        let entry_set = credman.entry_sets.get("test_set").unwrap();
        let entries = entry_set.entries.get("0").unwrap();
        let entry = entries.get("test_cred").unwrap();
        assert_eq!(entry.cred_id, "test_cred");
    }
}
