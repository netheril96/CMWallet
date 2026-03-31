use crate::openid4vp::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MatchedClaim {
    pub display: ClaimDisplayProperties,
    pub path: Vec<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MatchedEntry {
    pub id: String, // Registry entry ID
    pub display: DisplayProperties,
    pub matched_claims: Vec<MatchedClaim>,
}

#[derive(Debug, Clone)]
pub struct MatchedCredentialSet {
    pub id: String, // DCQL credential ID
    pub matched: Vec<MatchedEntry>,
}

#[derive(Debug, Clone)]
pub struct MatchedCredentialSetInfo {
    pub set_id: String,
    pub option_id: String,
    pub matched_credential_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DcqlMatchResult {
    pub matched_credentials: HashMap<String, MatchedCredentialSet>,
    pub matched_credential_sets: Vec<Vec<MatchedCredentialSetInfo>>,
    pub inline_issuance: Option<InlineIssuanceEntry>,
}

pub fn dcql_query(query: &DcqlQuery, registry: &RegistryCredentials) -> DcqlMatchResult {
    log::info!("Starting DCQL query with {} credentials", query.credentials.len());
    let mut result = DcqlMatchResult::default();
    let mut candidate_inline_issuance = HashMap::new();

    for dcql_cred in &query.credentials {
        log::debug!("Processing DCQL credential ID: {}, format: {}", dcql_cred.id, dcql_cred.format);
        let (matched_entries, inline_issuance) = match_credential(dcql_cred, registry);
        if !matched_entries.is_empty() {
            log::info!("Found {} matches for credential ID: {}", matched_entries.len(), dcql_cred.id);
            result.matched_credentials.insert(
                dcql_cred.id.clone(),
                MatchedCredentialSet {
                    id: dcql_cred.id.clone(),
                    matched: matched_entries,
                },
            );
        } else {
            log::debug!("No matches found for credential ID: {}", dcql_cred.id);
        }
        if let Some(inline) = inline_issuance {
            log::info!("Found inline issuance candidate for {}: {}", dcql_cred.id, inline.id);
            candidate_inline_issuance.insert(dcql_cred.id.clone(), inline);
        }
    }

    if let Some(credential_sets) = &query.credential_sets {
        log::debug!("Evaluating {} credential sets", credential_sets.len());
        let mut all_sets_matched = true;
        for (set_idx, dcql_set) in credential_sets.iter().enumerate() {
            let is_required = dcql_set.required.unwrap_or(true);
            log::debug!("Evaluating set index {} (required: {})", set_idx, is_required);
            if !is_required {
                log::debug!("Skipping optional set {}", set_idx);
                continue;
            }
            let mut curr_matched_options = Vec::new();
            for (option_idx, option) in dcql_set.options.iter().enumerate() {
                log::trace!("Evaluating option {} for set {}: {:?}", option_idx, set_idx, option);
                let mut option_matched = true;
                let mut matched_cred_ids = Vec::new();
                for cred_id in option {
                    if !result.matched_credentials.contains_key(cred_id) {
                        log::trace!("Option {} failed: missing credential ID {}", option_idx, cred_id);
                        option_matched = false;
                        break;
                    }
                    matched_cred_ids.push(cred_id.clone());
                }
                if option_matched {
                    log::debug!("Option {} for set {} matched", option_idx, set_idx);
                    curr_matched_options.push(MatchedCredentialSetInfo {
                        set_id: set_idx.to_string(),
                        option_id: option_idx.to_string(),
                        matched_credential_ids: matched_cred_ids,
                    });
                }
            }
            if curr_matched_options.is_empty() {
                log::warn!("Required credential set {} could not be satisfied", set_idx);
                all_sets_matched = false;
                break;
            }
            result.matched_credential_sets.push(curr_matched_options);
        }
        if !all_sets_matched {
            log::error!("DCQL query failed: one or more required credential sets were not matched");
            return DcqlMatchResult::default();
        }
    } else {
        log::debug!("No credential_sets defined. Requiring all credentials to match.");
        // No credential_sets: all requested credentials must be present
        if result.matched_credentials.len() == query.credentials.len() {
            let matched_cred_ids: Vec<String> = query.credentials.iter().map(|c| c.id.clone()).collect();
            log::info!("All {} credentials matched successfully", query.credentials.len());
            result.matched_credential_sets.push(vec![MatchedCredentialSetInfo {
                set_id: "default_set".to_string(),
                option_id: "default_option".to_string(),
                matched_credential_ids: matched_cred_ids,
            }]);
        } else {
            log::warn!("Missing {} credentials for implicit 'all' requirement", query.credentials.len() - result.matched_credentials.len());
        }
        if candidate_inline_issuance.len() == query.credentials.len() {
            result.inline_issuance = candidate_inline_issuance.into_values().next();
            if let Some(inline) = &result.inline_issuance {
                 log::info!("Selected inline issuance: {}", inline.id);
            }
        }
    }

    log::info!("DCQL query completed with {} matched sets", result.matched_credential_sets.len());
    result
}

fn match_credential(
    dcql_cred: &DcqlCredential,
    registry: &RegistryCredentials,
) -> (Vec<MatchedEntry>, Option<InlineIssuanceEntry>) {
    let format = &dcql_cred.format;
    let mut matched_entries = Vec::new();
    let mut inline_issuance = None;

    log::trace!("Matching credential ID: {} format: {}", dcql_cred.id, format);

    // 1. Filter candidates by meta
    let candidates: Option<Vec<&CredentialEntry>> = if format == MSO_MDOC {
        if let Some(meta) = &dcql_cred.meta {
            if let Some(doctype) = &meta.doctype_value {
                log::trace!("Filtering mso_mdoc by doctype: {}", doctype);
                // Inline issuance check
                for entry in &registry.issuance.mso_mdoc {
                    if entry.supported.contains(doctype) {
                        log::debug!("Found inline issuance for mDL doctype {}: {}", doctype, entry.id);
                        inline_issuance = Some(entry.clone());
                        break;
                    }
                }
                registry.mso_mdoc.get(doctype).map(|v| v.iter().collect())
            } else {
                log::warn!("mso_mdoc request missing doctype_value");
                None
            }
        } else {
            log::warn!("mso_mdoc request missing meta");
            None
        }
    } else if format == DC_SD_JWT {
        if let Some(meta) = &dcql_cred.meta {
            if let Some(vct_values) = &meta.vct_values {
                log::trace!("Filtering dc+sd-jwt by VCTs: {:?}", vct_values);
                let mut vct_candidates = Vec::new();
                for vct in vct_values {
                    // Inline issuance check
                    if inline_issuance.is_none() {
                        for entry in &registry.issuance.dc_sd_jwt {
                            if entry.supported.contains(vct) {
                                log::debug!("Found inline issuance for SD-JWT VCT {}: {}", vct, entry.id);
                                inline_issuance = Some(entry.clone());
                                break;
                            }
                        }
                    }
                    if let Some(list) = registry.dc_sd_jwt.get(vct) {
                        log::trace!("Found {} registered credentials for VCT {}", list.len(), vct);
                        vct_candidates.extend(list.iter());
                    }
                }
                if vct_candidates.is_empty() {
                    log::debug!("No registered credentials matched any of the requested VCTs");
                    None
                } else {
                    Some(vct_candidates)
                }
            } else {
                log::warn!("dc+sd-jwt request missing vct_values");
                None
            }
        } else {
            log::warn!("dc+sd-jwt request missing meta");
            None
        }
    } else {
        log::error!("Unsupported credential format: {}", format);
        None
    };

    let Some(candidate_list) = candidates else {
        log::debug!("No candidates found after format/meta filtering for {}", dcql_cred.id);
        return (Vec::new(), inline_issuance);
    };

    log::debug!("Evaluating {} candidates for credential ID {}", candidate_list.len(), dcql_cred.id);

    // 2. Match claims
    for candidate in candidate_list {
        log::trace!("Evaluating candidate ID: {}", candidate.id);
        let mut matched_claims = Vec::new();
        let mut matched_claim_ids = HashMap::new();

        if let Some(dcql_claims) = &dcql_cred.claims {
            let mut all_claims_found = true;
            for dcql_claim in dcql_claims {
                if let Some(matched_field) = find_claim(candidate, &dcql_claim.path) {
                    log::trace!("  Claim path {:?} found in candidate {}", dcql_claim.path, candidate.id);
                    // Check values if present
                    let mut value_matched = true;
                    if let Some(allowed_values) = &dcql_claim.values {
                        if let Some(field_value) = &matched_field.value {
                            if !allowed_values.contains(field_value) {
                                log::trace!("    Value mismatch: expected one of {:?}, got {:?}", allowed_values, field_value);
                                value_matched = false;
                            }
                        } else {
                            log::trace!("    Value mismatch: expected one of {:?}, but field value is missing", allowed_values);
                            value_matched = false;
                        }
                    }

                    if value_matched {
                        if let Some(display) = &matched_field.display {
                            let mc = MatchedClaim {
                                display: display.clone(),
                                path: dcql_claim.path.clone(),
                                value: matched_field.value.clone(),
                            };
                            if let Some(claim_id) = &dcql_claim.id {
                                matched_claim_ids.insert(claim_id.clone(), mc);
                            } else {
                                matched_claims.push(mc);
                            }
                        } else {
                            log::warn!("    Field matched but missing display properties: {:?}", dcql_claim.path);
                            all_claims_found = false;
                            break;
                        }
                    } else {
                        all_claims_found = false;
                        break;
                    }
                } else {
                    log::trace!("    Claim path {:?} NOT found in candidate {}", dcql_claim.path, candidate.id);
                    all_claims_found = false;
                    break;
                }
            }

            // 3. Handle claim_sets
            if let Some(claim_sets) = &dcql_cred.claim_sets {
                log::trace!("  Evaluating {} claim sets", claim_sets.len());
                let mut set_satisfied = false;
                for (idx, set) in claim_sets.iter().enumerate() {
                    let mut current_set_claims = Vec::new();
                    let mut all_in_set_matched = true;
                    for claim_id in set {
                        if let Some(mc) = matched_claim_ids.get(claim_id) {
                            current_set_claims.push(mc.clone());
                        } else {
                            all_in_set_matched = false;
                            break;
                        }
                    }
                    if all_in_set_matched {
                        log::debug!("  Claim set {} satisfied for candidate {}", idx, candidate.id);
                        matched_claims = current_set_claims;
                        set_satisfied = true;
                        break;
                    }
                }
                if !set_satisfied {
                    log::debug!("  No claim sets satisfied for candidate {}", candidate.id);
                    continue; // This candidate doesn't match this dcql_cred
                }
            } else {
                // If no claim_sets, all specified claims MUST match
                if !all_claims_found || (matched_claims.len() + matched_claim_ids.len() < dcql_claims.len()) {
                    log::trace!("  Not all required claims matched for candidate {}", candidate.id);
                    continue;
                }
                log::debug!("  All required claims matched for candidate {}", candidate.id);
                // Add matched_claim_ids to matched_claims
                for (_, mc) in matched_claim_ids {
                    matched_claims.push(mc);
                }
            }
        } else {
            log::debug!("  No claims requested, matching all claims for candidate {}", candidate.id);
            // No claims requested: match every candidate
            // Add all claims from the candidate
            for (ns, ns_map) in &candidate.paths {
                for (id, field) in ns_map {
                    if let Some(display) = &field.display {
                        matched_claims.push(MatchedClaim {
                            display: display.clone(),
                            path: if ns.is_empty() { vec![id.clone()] } else { vec![ns.clone(), id.clone()] },
                            value: field.value.clone(),
                        });
                    }
                }
            }
        }

        log::info!("Candidate {} matched successfully", candidate.id);
        matched_entries.push(MatchedEntry {
            id: candidate.id.clone(),
            display: candidate.display.clone(),
            matched_claims,
        });
    }

    (matched_entries, inline_issuance)
}

fn find_claim<'a>(candidate: &'a CredentialEntry, path: &[String]) -> Option<&'a RegistryField> {
    if path.is_empty() {
        return None;
    }
    if path.len() == 2 {
        candidate.paths.get(&path[0])?.get(&path[1])
    } else if path.len() == 1 {
        candidate.paths.get("")?.get(&path[0])
    } else {
        None
    }
}
