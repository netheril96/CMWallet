use crate::json_value::{DeterministicMap, JsonValue};
pub use crate::openid4vp_models::*;

pub fn add_all_claims(
    matched_claim_names: &mut Vec<JsonValue>,
    candidate_paths: &DeterministicMap<String, JsonValue>,
) {
    candidate_paths
        .values()
        .filter_map(|v| match v {
            JsonValue::Object(obj) => Some((v, obj)),
            _ => None,
        })
        .for_each(|(v, obj)| {
            if let Some(display) = obj.get("display") {
                matched_claim_names.push(display.clone());
            } else {
                add_all_claims_from_json(matched_claim_names, v);
            }
        });
}

fn add_all_claims_from_json(matched_claim_names: &mut Vec<JsonValue>, json: &JsonValue) {
    match json {
        JsonValue::Object(obj) => {
            if let Some(display) = obj.get("display") {
                matched_claim_names.push(display.clone());
            } else {
                obj.values()
                    .for_each(|v| add_all_claims_from_json(matched_claim_names, v));
            }
        }
        JsonValue::Array(arr) => {
            arr.iter()
                .for_each(|v| add_all_claims_from_json(matched_claim_names, v));
        }
        _ => {}
    }
}

fn get_format_candidates<'a>(
    format: &str,
    registry: &'a Registry,
) -> (
    Option<&'a DeterministicMap<String, Vec<RegistryCredential>>>,
    Option<&'a Vec<RegistryIssuanceEntry>>,
) {
    match format {
        "mso_mdoc" => (
            registry.credentials.mso_mdoc.as_ref(),
            registry.credentials.issuance.as_ref().map(|i| &i.mso_mdoc),
        ),
        "dc+sd-jwt" => (
            registry.credentials.sd_jwt.as_ref(),
            registry.credentials.issuance.as_ref().map(|i| &i.sd_jwt),
        ),
        _ => {
            log::warn!("Unsupported format: {}", format);
            (None, None)
        }
    }
}

fn filter_candidates_by_meta<'a>(
    format: &str,
    meta: &Option<DcqlMeta>,
    candidates: Option<&'a DeterministicMap<String, Vec<RegistryCredential>>>,
    inline_issuance_candidates: Option<&'a Vec<RegistryIssuanceEntry>>,
) -> (Vec<&'a RegistryCredential>, Option<RegistryIssuanceEntry>) {
    let Some(meta) = meta else {
        log::trace!(
            "No meta provided, collecting all candidates for format {}",
            format
        );
        let v = candidates
            .map(|c| c.values().flatten().collect())
            .unwrap_or_default();
        return (v, None);
    };

    let mut inline_issuance = None;
    let filtered_candidates = match format {
        "mso_mdoc" => {
            if meta.doctype_value.is_empty() {
                log::trace!("mso_mdoc requested but no doctype_value in meta");
                return (Vec::new(), None);
            }

            log::trace!(
                "Filtering mso_mdoc candidates by doctype: {}",
                meta.doctype_value
            );
            inline_issuance = inline_issuance_candidates.and_then(|cands| {
                cands
                    .iter()
                    .find(|cand| cand.supported.contains(&meta.doctype_value))
                    .map(|cand| {
                        log::debug!(
                            "Found matching inline issuance for doctype {}: {}",
                            meta.doctype_value,
                            cand.id
                        );
                        cand.clone()
                    })
            });
            candidates
                .and_then(|c| c.get(&meta.doctype_value))
                .map(|v| v.iter().collect())
                .unwrap_or_default()
        }
        "dc+sd-jwt" => {
            if meta.vct_values.is_empty() {
                return (Vec::new(), None);
            }

            log::trace!(
                "Filtering dc+sd-jwt candidates by vcts: {:?}",
                meta.vct_values
            );
            inline_issuance = meta.vct_values.iter().find_map(|vct| {
                inline_issuance_candidates.and_then(|cands| {
                    cands
                        .iter()
                        .find(|cand| cand.supported.contains(vct))
                        .map(|cand| {
                            log::debug!(
                                "Found matching inline issuance for vct {}: {}",
                                vct,
                                cand.id
                            );
                            cand.clone()
                        })
                })
            });

            meta.vct_values
                .iter()
                .filter_map(|vct| candidates.and_then(|c| c.get(vct)))
                .flatten()
                .collect()
        }
        _ => Vec::new(),
    };

    (filtered_candidates, inline_issuance)
}

fn match_candidate_claims(
    candidate: &RegistryCredential,
    claims_req: &Vec<DcqlClaim>,
    claim_sets_req: &Vec<Vec<String>>,
) -> Option<MatchedCredential> {
    if claims_req.is_empty() {
        log::debug!(
            "Candidate {}: no specific claims requested, matching all available claims",
            candidate.id
        );
        let mut matched_claim_names = Vec::new();
        add_all_claims(&mut matched_claim_names, &candidate.paths);
        return Some(MatchedCredential {
            id: candidate.id.clone(),
            display: candidate.display.clone(),
            matched_claim_names,
            matched_claim_metadata: Vec::new(),
        });
    }

    if !claim_sets_req.is_empty() {
        log::trace!("Candidate {}: matching against claim_sets", candidate.id);
        let matched_claim_ids: DeterministicMap<String, MatchedClaim> = claims_req
            .iter()
            .filter(|claim| !claim.id.is_empty())
            .filter_map(|claim| {
                match_claim(claim, &candidate.paths).map(|info| {
                    log::trace!("Candidate {}: claim {} matched", candidate.id, claim.id);
                    (claim.id.clone(), info)
                })
            })
            .collect();

        return claim_sets_req
            .iter()
            .enumerate()
            .find_map(|(idx, claim_set)| {
                let mut current_set_names = Vec::new();
                let mut current_set_metadata = Vec::new();

                let all_matched = claim_set.iter().all(|claim_id| {
                    let Some(info) = matched_claim_ids.get(claim_id) else {
                        log::trace!(
                            "Candidate {}: claim set index {} failed because claim {} did not match",
                            candidate.id,
                            idx,
                            claim_id
                        );
                        return false;
                    };
                    current_set_names.push(info.display.clone());
                    current_set_metadata.push(info.path.clone());
                    true
                });

                if !all_matched {
                    return None;
                }

                log::debug!(
                    "Candidate {}: matched claim set index {}",
                    candidate.id,
                    idx
                );
                Some(MatchedCredential {
                    id: candidate.id.clone(),
                    display: candidate.display.clone(),
                    matched_claim_names: current_set_names,
                    matched_claim_metadata: current_set_metadata,
                })
            })
            .or_else(|| {
                log::debug!("Candidate {}: no claim sets matched", candidate.id);
                None
            });
    }

    log::trace!(
        "Candidate {}: matching all {} requested claims",
        candidate.id,
        claims_req.len()
    );
    let mut matched_claim_names = Vec::new();
    let mut matched_claim_metadata = Vec::new();

    let all_matched = claims_req.iter().all(|claim| {
        let Some(info) = match_claim(claim, &candidate.paths) else {
            log::trace!(
                "Candidate {}: claim path {:?} failed to match",
                candidate.id,
                claim.path
            );
            return false;
        };
        matched_claim_names.push(info.display);
        matched_claim_metadata.push(info.path);
        true
    });

    if !all_matched {
        return None;
    }

    log::debug!("Candidate {}: all claims matched", candidate.id);
    Some(MatchedCredential {
        id: candidate.id.clone(),
        display: candidate.display.clone(),
        matched_claim_names,
        matched_claim_metadata,
    })
}

pub fn match_credential(credential: &DcqlCredential, registry: &Registry) -> MatchCredentialResult {
    log::debug!(
        "Matching credential req id: {}, format: {}",
        credential.id,
        credential.format
    );
    let (candidates, inline_issuance_candidates) =
        get_format_candidates(&credential.format, registry);
    let (filtered_candidates, inline_issuance) = filter_candidates_by_meta(
        &credential.format,
        &credential.meta,
        candidates,
        inline_issuance_candidates,
    );

    log::debug!(
        "Found {} potential candidates after meta filtering",
        filtered_candidates.len()
    );
    let matched_creds = filtered_candidates
        .into_iter()
        .filter_map(|candidate| {
            match_candidate_claims(candidate, &credential.claims, &credential.claim_sets)
        })
        .collect();

    MatchCredentialResult {
        matched_creds,
        inline_issuance,
    }
}

fn match_claim(
    claim: &DcqlClaim,
    candidate_paths: &DeterministicMap<String, JsonValue>,
) -> Option<MatchedClaim> {
    log::trace!("Matching claim path: {:?}", claim.path);

    let final_val =
        claim
            .path
            .iter()
            .enumerate()
            .try_fold(None, |curr_val: Option<&JsonValue>, (i, p)| {
                let next_val = if i == 0 {
                    candidate_paths.get(p)
                } else if let Some(JsonValue::Object(obj)) = curr_val {
                    obj.get(p)
                } else {
                    log::trace!(
                        "Claim path match failed at step {}: key {} not found or not an object",
                        i,
                        p
                    );
                    return Err(());
                };

                match next_val {
                    Some(v) => Ok(Some(v)),
                    None => {
                        log::trace!("Claim path match failed at step {}: key {} not found", i, p);
                        Err(())
                    }
                }
            });

    let curr_val = final_val.ok()??;

    let JsonValue::Object(obj) = curr_val else {
        log::trace!(
            "Claim matched path but final node is not an object at {:?}",
            claim.path
        );
        return None;
    };

    let Some(display) = obj.get("display") else {
        log::trace!(
            "Claim matched path but missing 'display' field at {:?}",
            claim.path
        );
        return None;
    };

    let actual_value = obj.get("value");
    if claim.values.is_empty() {
        log::trace!("Claim path matched successfully (no value constraint)");
        return Some(MatchedClaim {
            display: display.clone(),
            path: claim.path.clone(),
        });
    }

    let Some(actual) = actual_value else {
        log::trace!(
            "Claim value missing at {:?}, but values constraint is present",
            claim.path
        );
        return None;
    };

    if !claim.values.iter().any(|v| v == actual) {
        log::trace!(
            "Claim value mismatch at {:?}. Expected one of {:?}, found {:?}",
            claim.path,
            claim.values,
            actual
        );
        return None;
    }

    log::trace!("Claim matched with value: {:?}", actual);
    Some(MatchedClaim {
        display: display.clone(),
        path: claim.path.clone(),
    })
}

fn evaluate_explicit_credential_sets(
    credential_sets: &[DcqlCredentialSet],
    candidate_matched_credentials: &DeterministicMap<String, DcqlMatchedCredentialEntry>,
) -> (bool, Vec<Vec<MatchedCredentialSetInfo>>) {
    let mut matched_credential_sets = Vec::new();

    let all_required_matched = credential_sets
        .iter()
        .enumerate()
        .filter(|(_, set)| set.required.unwrap_or(true))
        .all(|(set_idx, set)| {
            log::debug!(
                "Evaluating required credential_set index {} with {} options",
                set_idx,
                set.options.len()
            );

            let curr_matched_options: Vec<MatchedCredentialSetInfo> = set
                .options
                .iter()
                .enumerate()
                .filter_map(|(opt_idx, option)| {
                    let mut matched_cred_ids = Vec::new();
                    let option_matched = option.iter().all(|cred_id| {
                        if !candidate_matched_credentials.contains_key(cred_id) {
                            log::trace!(
                                "Option {} in set {} failed because {} did not match",
                                opt_idx,
                                set_idx,
                                cred_id
                            );
                            return false;
                        }
                        matched_cred_ids.push(cred_id.clone());
                        true
                    });

                    if !option_matched {
                        return None;
                    }

                    log::debug!("Option {} in set {} is satisfied", opt_idx, set_idx);
                    Some(MatchedCredentialSetInfo {
                        set_id: set_idx.to_string(),
                        option_id: opt_idx.to_string(),
                        matched_credential_ids: matched_cred_ids,
                    })
                })
                .collect();

            if curr_matched_options.is_empty() {
                log::info!(
                    "Required credential_set index {} failed to match any options",
                    set_idx
                );
                return false;
            }

            log::info!(
                "Required credential_set index {} matched {} options",
                set_idx,
                curr_matched_options.len()
            );
            matched_credential_sets.push(curr_matched_options);
            true
        });

    (all_required_matched, matched_credential_sets)
}

fn evaluate_implicit_credential_sets(
    credentials_req: &[DcqlCredential],
    candidate_matched_credentials: &DeterministicMap<String, DcqlMatchedCredentialEntry>,
) -> Vec<Vec<MatchedCredentialSetInfo>> {
    if credentials_req.len() == candidate_matched_credentials.len() {
        log::info!(
            "All {} credential requirements satisfied",
            credentials_req.len()
        );
        let matched_cred_ids: Vec<String> = credentials_req.iter().map(|c| c.id.clone()).collect();
        let single_set_info = MatchedCredentialSetInfo {
            set_id: "".to_string(),
            option_id: "".to_string(),
            matched_credential_ids: matched_cred_ids,
        };
        return vec![vec![single_set_info]];
    }

    log::info!(
        "Implicit credential requirements failed: {} of {} satisfied",
        candidate_matched_credentials.len(),
        credentials_req.len()
    );
    Vec::new()
}

pub fn dcql_query(query: &DcqlQuery, registry: &Registry) -> DcqlMatchResult {
    log::info!(
        "Starting DCQL query with {} credential requirements",
        query.credentials.len()
    );
    let mut candidate_matched_credentials = DeterministicMap::new();
    let mut candidate_inline_issuance_credentials = DeterministicMap::new();

    for cred_req in &query.credentials {
        let res = match_credential(cred_req, registry);
        if !res.matched_creds.is_empty() {
            log::info!(
                "Credential requirement {} matched {} candidates",
                cred_req.id,
                res.matched_creds.len()
            );
            candidate_matched_credentials.insert(
                cred_req.id.clone(),
                DcqlMatchedCredentialEntry {
                    id: cred_req.id.clone(),
                    matched: res.matched_creds,
                },
            );
        } else {
            log::info!(
                "Credential requirement {} matched 0 candidates",
                cred_req.id
            );
        }
        if let Some(inline) = res.inline_issuance {
            log::info!(
                "Credential requirement {} has inline issuance available: {}",
                cred_req.id,
                inline.id
            );
            candidate_inline_issuance_credentials.insert(cred_req.id.clone(), inline);
        }
    }

    let (matched_credential_sets, overall_matched, inline_issuance) = if !query
        .credential_sets
        .is_empty()
    {
        let (overall_matched, sets) = evaluate_explicit_credential_sets(
            &query.credential_sets,
            &candidate_matched_credentials,
        );
        (sets, overall_matched, None)
    } else {
        let sets =
            evaluate_implicit_credential_sets(&query.credentials, &candidate_matched_credentials);

        let mut inline_issuance = None;
        let all_satisfied = query.credentials.len() == candidate_inline_issuance_credentials.len()
            && !candidate_inline_issuance_credentials.is_empty();

        if all_satisfied {
            log::info!("All requirements could be satisfied by inline issuance");
            inline_issuance = candidate_inline_issuance_credentials
                .values()
                .next()
                .cloned();
        }
        let overall_matched = !sets.is_empty() || inline_issuance.is_some();
        (sets, overall_matched, inline_issuance)
    };

    if !overall_matched {
        log::info!("Overall DCQL query failed");
        return DcqlMatchResult {
            matched_credential_sets: Vec::new(),
            matched_credentials: DeterministicMap::new(),
            inline_issuance: None,
        };
    }

    log::info!("Overall DCQL query matched");
    DcqlMatchResult {
        matched_credential_sets,
        matched_credentials: candidate_matched_credentials,
        inline_issuance,
    }
}
