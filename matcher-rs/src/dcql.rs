use crate::json_value::{JsonValue, DeterministicMap};
pub use crate::openid4vp_models::*;

pub fn add_all_claims(matched_claim_names: &mut Vec<JsonValue>, candidate_paths: &DeterministicMap<String, JsonValue>) {
    for value in candidate_paths.values() {
        match value {
            JsonValue::Object(obj) => {
                if let Some(display) = obj.get("display") {
                    matched_claim_names.push(display.clone());
                } else {
                    // Recurse
                    add_all_claims_from_json(matched_claim_names, value);
                }
            }
            _ => {}
        }
    }
}

fn add_all_claims_from_json(matched_claim_names: &mut Vec<JsonValue>, json: &JsonValue) {
    match json {
        JsonValue::Object(obj) => {
            if let Some(display) = obj.get("display") {
                matched_claim_names.push(display.clone());
            } else {
                for v in obj.values() {
                    add_all_claims_from_json(matched_claim_names, v);
                }
            }
        }
        JsonValue::Array(arr) => {
            for v in arr {
                add_all_claims_from_json(matched_claim_names, v);
            }
        }
        _ => {}
    }
}

fn get_format_candidates<'a>(
    format: &str,
    registry: &'a Registry,
) -> (Option<&'a DeterministicMap<String, Vec<RegistryCredential>>>, Option<&'a Vec<RegistryIssuanceEntry>>) {
    if format == "mso_mdoc" {
        (
            registry.credentials.mso_mdoc.as_ref(),
            registry.credentials.issuance.as_ref().map(|i| &i.mso_mdoc),
        )
    } else if format == "dc+sd-jwt" {
        (
            registry.credentials.sd_jwt.as_ref(),
            registry.credentials.issuance.as_ref().map(|i| &i.sd_jwt),
        )
    } else {
        log::warn!("Unsupported format: {}", format);
        (None, None)
    }
}

fn filter_candidates_by_meta<'a>(
    format: &str,
    meta: &Option<DcqlMeta>,
    candidates: Option<&'a DeterministicMap<String, Vec<RegistryCredential>>>,
    inline_issuance_candidates: Option<&'a Vec<RegistryIssuanceEntry>>,
) -> (Vec<&'a RegistryCredential>, Option<RegistryIssuanceEntry>) {
    let mut inline_issuance = None;
    let filtered_candidates = if let Some(meta) = meta {
        if format == "mso_mdoc" {
            if let Some(doctype) = &meta.doctype_value {
                log::trace!("Filtering mso_mdoc candidates by doctype: {}", doctype);
                if let Some(inline_cands) = inline_issuance_candidates {
                    for cand in inline_cands {
                        if cand.supported.contains(doctype) {
                            log::debug!("Found matching inline issuance for doctype {}: {}", doctype, cand.id);
                            inline_issuance = Some(cand.clone());
                            break;
                        }
                    }
                }
                candidates.and_then(|c| c.get(doctype)).map(|v| v.iter().collect()).unwrap_or_default()
            } else {
                log::trace!("mso_mdoc requested but no doctype_value in meta");
                Vec::new()
            }
        } else if format == "dc+sd-jwt" {
            let mut v = Vec::new();
            if !meta.vct_values.is_empty() {
                log::trace!("Filtering dc+sd-jwt candidates by vcts: {:?}", meta.vct_values);
                for vct in &meta.vct_values {
                    if let Some(inline_cands) = inline_issuance_candidates {
                        for cand in inline_cands {
                            if cand.supported.contains(vct) {
                                log::debug!("Found matching inline issuance for vct {}: {}", vct, cand.id);
                                inline_issuance = Some(cand.clone());
                                break;
                            }
                        }
                    }
                    if let Some(cands) = candidates.and_then(|c| c.get(vct)) {
                        v.extend(cands.iter());
                    }
                }
            }
            v
        } else {
            Vec::new()
        }
    } else {
        log::trace!("No meta provided, collecting all candidates for format {}", format);
        let mut v = Vec::new();
        if let Some(c) = candidates {
            for cands in c.values() {
                v.extend(cands.iter());
            }
        }
        v
    };
    (filtered_candidates, inline_issuance)
}

fn match_candidate_claims(
    candidate: &RegistryCredential,
    claims_req: &Vec<DcqlClaim>,
    claim_sets_req: &Vec<Vec<String>>,
) -> Option<MatchedCredential> {
    let mut matched_claim_names = Vec::new();
    let mut matched_claim_metadata = Vec::new();

    if !claims_req.is_empty() {
        if !claim_sets_req.is_empty() {
            log::trace!("Candidate {}: matching against claim_sets", candidate.id);
            let mut matched_claim_ids = DeterministicMap::new();
            for claim in claims_req {
                if let Some(claim_id) = &claim.id {
                    if let Some(matched_info) = match_claim(claim, &candidate.paths) {
                        log::trace!("Candidate {}: claim {} matched", candidate.id, claim_id);
                        matched_claim_ids.insert(claim_id.clone(), matched_info);
                    }
                }
            }

            for (idx, claim_set) in claim_sets_req.iter().enumerate() {
                let mut current_set_names = Vec::new();
                let mut current_set_metadata = Vec::new();
                let mut all_matched = true;
                for claim_id in claim_set {
                    if let Some(info) = matched_claim_ids.get(claim_id) {
                        current_set_names.push(info.display.clone());
                        current_set_metadata.push(info.path.clone());
                    } else {
                        log::trace!("Candidate {}: claim set index {} failed because claim {} did not match", candidate.id, idx, claim_id);
                        all_matched = false;
                        break;
                    }
                }
                if all_matched {
                    log::debug!("Candidate {}: matched claim set index {}", candidate.id, idx);
                    return Some(MatchedCredential {
                        id: candidate.id.clone(),
                        display: candidate.display.clone(),
                        matched_claim_names: current_set_names,
                        matched_claim_metadata: current_set_metadata,
                    });
                }
            }
            log::debug!("Candidate {}: no claim sets matched", candidate.id);
            None
        } else {
            log::trace!("Candidate {}: matching all {} requested claims", candidate.id, claims_req.len());
            let mut all_matched = true;
            for claim in claims_req {
                if let Some(info) = match_claim(claim, &candidate.paths) {
                    matched_claim_names.push(info.display);
                    matched_claim_metadata.push(info.path);
                } else {
                    log::trace!("Candidate {}: claim path {:?} failed to match", candidate.id, claim.path);
                    all_matched = false;
                    break;
                }
            }
            if all_matched {
                log::debug!("Candidate {}: all claims matched", candidate.id);
                Some(MatchedCredential {
                    id: candidate.id.clone(),
                    display: candidate.display.clone(),
                    matched_claim_names,
                    matched_claim_metadata,
                })
            } else {
                None
            }
        }
    } else {
        log::debug!("Candidate {}: no specific claims requested, matching all available claims", candidate.id);
        add_all_claims(&mut matched_claim_names, &candidate.paths);
        Some(MatchedCredential {
            id: candidate.id.clone(),
            display: candidate.display.clone(),
            matched_claim_names,
            matched_claim_metadata: Vec::new(),
        })
    }
}

pub fn match_credential(credential: &DcqlCredential, registry: &Registry) -> MatchCredentialResult {
    log::debug!("Matching credential req id: {}, format: {}", credential.id, credential.format);
    let (candidates, inline_issuance_candidates) = get_format_candidates(&credential.format, registry);
    let (filtered_candidates, inline_issuance) = filter_candidates_by_meta(&credential.format, &credential.meta, candidates, inline_issuance_candidates);

    log::debug!("Found {} potential candidates after meta filtering", filtered_candidates.len());
    let mut matched_creds = Vec::new();

    for candidate in filtered_candidates {
        if let Some(matched) = match_candidate_claims(candidate, &credential.claims, &credential.claim_sets) {
            matched_creds.push(matched);
        }
    }

    MatchCredentialResult {
        matched_creds,
        inline_issuance,
    }
}

fn match_claim(claim: &DcqlClaim, candidate_paths: &DeterministicMap<String, JsonValue>) -> Option<MatchedClaim> {
    log::trace!("Matching claim path: {:?}", claim.path);
    let mut curr_val = None;
    for (i, p) in claim.path.iter().enumerate() {
        if i == 0 {
            curr_val = candidate_paths.get(p);
        } else {
            if let Some(JsonValue::Object(obj)) = curr_val {
                curr_val = obj.get(p);
            } else {
                log::trace!("Claim path match failed at step {}: key {} not found or not an object", i, p);
                return None;
            }
        }
        if curr_val.is_none() {
            log::trace!("Claim path match failed at step {}: key {} not found", i, p);
            return None;
        }
    }

    if let Some(JsonValue::Object(obj)) = curr_val {
        if let Some(display) = obj.get("display") {
            let actual_value = obj.get("value");
            if !claim.values.is_empty() {
                if let Some(actual) = actual_value {
                    if claim.values.iter().any(|v| v == actual) {
                        log::trace!("Claim matched with value: {:?}", actual);
                        return Some(MatchedClaim {
                            display: display.clone(),
                            path: claim.path.clone(),
                        });
                    } else {
                        log::trace!("Claim value mismatch at {:?}. Expected one of {:?}, found {:?}", claim.path, claim.values, actual);
                    }
                } else {
                    log::trace!("Claim value missing at {:?}, but values constraint is present", claim.path);
                }
                return None;
            } else {
                log::trace!("Claim path matched successfully (no value constraint)");
                return Some(MatchedClaim {
                    display: display.clone(),
                    path: claim.path.clone(),
                });
            }
        } else {
            log::trace!("Claim matched path but missing 'display' field at {:?}", claim.path);
        }
    } else {
        log::trace!("Claim matched path but final node is not an object at {:?}", claim.path);
    }
    None
}

fn evaluate_explicit_credential_sets(
    credential_sets: &[DcqlCredentialSet],
    candidate_matched_credentials: &DeterministicMap<String, DcqlMatchedCredentialEntry>,
) -> (bool, Vec<Vec<MatchedCredentialSetInfo>>) {
    let mut matched_credential_sets = Vec::new();
    let mut overall_matched = true;
    for (set_idx, set) in credential_sets.iter().enumerate() {
        let is_required = set.required.unwrap_or(true);
        if !is_required {
            log::trace!("Skipping optional credential_set index {}", set_idx);
            continue;
        }
        log::debug!("Evaluating required credential_set index {} with {} options", set_idx, set.options.len());
        let mut curr_matched_options = Vec::new();
        for (opt_idx, option) in set.options.iter().enumerate() {
            let mut option_matched = true;
            let mut matched_cred_ids = Vec::new();
            for cred_id in option {
                if candidate_matched_credentials.contains_key(cred_id) {
                    matched_cred_ids.push(cred_id.clone());
                } else {
                    log::trace!("Option {} in set {} failed because {} did not match", opt_idx, set_idx, cred_id);
                    option_matched = false;
                    break;
                }
            }
            if option_matched {
                log::debug!("Option {} in set {} is satisfied", opt_idx, set_idx);
                curr_matched_options.push(MatchedCredentialSetInfo {
                    set_id: set_idx.to_string(),
                    option_id: opt_idx.to_string(),
                    matched_credential_ids: matched_cred_ids,
                });
            }
        }
        if curr_matched_options.is_empty() {
            log::info!("Required credential_set index {} failed to match any options", set_idx);
            overall_matched = false;
            break;
        } else {
            log::info!("Required credential_set index {} matched {} options", set_idx, curr_matched_options.len());
            matched_credential_sets.push(curr_matched_options);
        }
    }
    (overall_matched, matched_credential_sets)
}

fn evaluate_implicit_credential_sets(
    credentials_req: &[DcqlCredential],
    candidate_matched_credentials: &DeterministicMap<String, DcqlMatchedCredentialEntry>,
) -> Vec<Vec<MatchedCredentialSetInfo>> {
    let mut matched_credential_sets = Vec::new();
    if credentials_req.len() == candidate_matched_credentials.len() {
        log::info!("All {} credential requirements satisfied", credentials_req.len());
        let matched_cred_ids: Vec<String> = credentials_req.iter().map(|c| c.id.clone()).collect();
        let single_set_info = MatchedCredentialSetInfo {
            set_id: "".to_string(),
            option_id: "".to_string(),
            matched_credential_ids: matched_cred_ids,
        };
        matched_credential_sets.push(vec![single_set_info]);
    } else {
        log::info!("Implicit credential requirements failed: {} of {} satisfied", candidate_matched_credentials.len(), credentials_req.len());
        for req in credentials_req {
            if !candidate_matched_credentials.contains_key(&req.id) {
                log::info!("Missing credential: {}", req.id);
            }
        }
    }
    matched_credential_sets
}

pub fn dcql_query(query: &DcqlQuery, registry: &Registry) -> DcqlMatchResult {
    log::info!("Starting DCQL query with {} credential requirements", query.credentials.len());
    let mut candidate_matched_credentials = DeterministicMap::new();
    let mut candidate_inline_issuance_credentials = DeterministicMap::new();

    for cred_req in &query.credentials {
        let res = match_credential(cred_req, registry);
        if !res.matched_creds.is_empty() {
            log::info!("Credential requirement {} matched {} candidates", cred_req.id, res.matched_creds.len());
            candidate_matched_credentials.insert(
                cred_req.id.clone(),
                DcqlMatchedCredentialEntry {
                    id: cred_req.id.clone(),
                    matched: res.matched_creds,
                },
            );
        } else {
            log::info!("Credential requirement {} matched 0 candidates", cred_req.id);
        }
        if let Some(inline) = res.inline_issuance {
            log::info!("Credential requirement {} has inline issuance available: {}", cred_req.id, inline.id);
            candidate_inline_issuance_credentials.insert(cred_req.id.clone(), inline);
        }
    }

    let (matched_credential_sets, overall_matched, inline_issuance) = if !query.credential_sets.is_empty() {
        let (overall_matched, sets) = evaluate_explicit_credential_sets(&query.credential_sets, &candidate_matched_credentials);
        (sets, overall_matched, None)
    } else {
        let sets = evaluate_implicit_credential_sets(&query.credentials, &candidate_matched_credentials);
        
        let mut inline_issuance = None;
        if query.credentials.len() == candidate_inline_issuance_credentials.len() && !candidate_inline_issuance_credentials.is_empty() {
            log::info!("All requirements could be satisfied by inline issuance");
            inline_issuance = candidate_inline_issuance_credentials.values().next().cloned();
        }
        let overall_matched = !sets.is_empty() || inline_issuance.is_some();
        (sets, overall_matched, inline_issuance)
    };

    if overall_matched {
        log::info!("Overall DCQL query matched");
        DcqlMatchResult {
            matched_credential_sets,
            matched_credentials: candidate_matched_credentials,
            inline_issuance,
        }
    } else {
        log::info!("Overall DCQL query failed");
        DcqlMatchResult {
            matched_credential_sets: Vec::new(),
            matched_credentials: DeterministicMap::new(),
            inline_issuance: None,
        }
    }
}
