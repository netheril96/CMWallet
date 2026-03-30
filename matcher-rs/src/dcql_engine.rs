use crate::dcql::*;
use log::debug;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct MatchedCredentialInfo {
    pub id: String,
    pub display: RegistryEntryDisplay,
    pub matched_claim_names: Vec<VerificationFieldDisplay>,
    pub matched_claim_metadata: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct MatchedQueryCredential {
    pub id: String, // dcql query id
    pub matched: Vec<MatchedCredentialInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct MatchedOption {
    pub set_id: String,
    pub option_id: String,
    pub matched_credential_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MatchResult {
    pub matched_credential_sets: Vec<Vec<MatchedOption>>,
    pub matched_credentials: HashMap<String, MatchedQueryCredential>,
    pub inline_issuance: Option<RegistryIssuanceEntry>,
}

impl RegistryPathNode {
    pub fn resolve(&self, path: &[String]) -> Option<&RegistryPathNode> {
        let mut curr = self;
        for part in path {
            curr = curr.children.get(part)?;
        }
        Some(curr)
    }

    pub fn add_all_claims(&self, names: &mut Vec<VerificationFieldDisplay>) {
        if !self.display.verification.display_name.is_empty() {
            names.push(self.display.verification.clone());
        }
        for child in self.children.values() {
            child.add_all_claims(names);
        }
    }
}

pub fn match_credential(
    query_cred: &CredentialQuery,
    store: &RegistryFormatCollection,
) -> (Vec<MatchedCredentialInfo>, Option<RegistryIssuanceEntry>) {
    debug!("Matching query credential: id={}, format={}", query_cred.id, query_cred.format);
    let mut matched_infos = Vec::new();
    let mut inline_issuance = None;

    let format_candidates: Option<Vec<&RegistryCredential>> = match query_cred.format.as_str() {
        "mso_mdoc" => {
            debug!("Filtering mso_mdoc candidates by doctype: {}", query_cred.meta.doctype_value);
            store
                .mso_mdoc
                .get(&query_cred.meta.doctype_value)
                .map(|v| v.iter().collect())
        }
        "dc+sd-jwt" => {
            debug!("Filtering dc+sd-jwt candidates by vct values: {:?}", query_cred.meta.vct_values);
            let mut all = Vec::new();
            for vct in &query_cred.meta.vct_values {
                if let Some(c) = store.dc_sd_jwt.get(vct) {
                    all.extend(c.iter());
                }
            }
            if all.is_empty() {
                None
            } else {
                Some(all)
            }
        }
        _ => {
            debug!("Unsupported format: {}", query_cred.format);
            None
        },
    };

    // Inline issuance
    match query_cred.format.as_str() {
        "mso_mdoc" => {
            for entry in &store.issuance.mso_mdoc {
                if entry.supported.contains(&query_cred.meta.doctype_value) {
                    debug!("Found matching mso_mdoc inline issuance entry: {}", entry.id);
                    inline_issuance = Some(entry.clone());
                    break;
                }
            }
        }
        "dc+sd-jwt" => {
            for entry in &store.issuance.dc_sd_jwt {
                if query_cred
                    .meta
                    .vct_values
                    .iter()
                    .any(|vct| entry.supported.contains(vct))
                {
                    debug!("Found matching dc+sd-jwt inline issuance entry: {}", entry.id);
                    inline_issuance = Some(entry.clone());
                    break;
                }
            }
        }
        _ => {}
    }

    if let Some(candidates) = format_candidates {
        debug!("Evaluating {} candidates", candidates.len());
        for candidate in candidates {
            let mut matched_info = MatchedCredentialInfo {
                id: candidate.id.clone(),
                display: candidate.display.clone(),
                ..Default::default()
            };

            if query_cred.claims.is_empty() {
                debug!("No claims in query, auto-matching candidate: {}", candidate.id);
                candidate
                    .paths
                    .add_all_claims(&mut matched_info.matched_claim_names);
                matched_infos.push(matched_info);
            } else {
                debug!("Evaluating claims for candidate: {}", candidate.id);
                let mut matched_claim_ids = HashMap::new(); // ID -> (display, path)
                for claim_query in &query_cred.claims {
                    if let Some(node) = candidate.paths.resolve(&claim_query.path) {
                        if !node.display.verification.display_name.is_empty() {
                            let mut matched = false;
                            if claim_query.values.is_empty() {
                                matched = true;
                            } else {
                                for val in &claim_query.values {
                                    if *val == node.value {
                                        matched = true;
                                        break;
                                    }
                                }
                            }
                            if matched {
                                matched_claim_ids.insert(
                                    claim_query.id.clone(),
                                    (node.display.verification.clone(), claim_query.path.clone()),
                                );
                            }
                        }
                    }
                }

                if query_cred.claim_sets.is_empty() {
                    if matched_claim_ids.len() == query_cred.claims.len() {
                        for q in &query_cred.claims {
                            let (display, path) = matched_claim_ids.get(&q.id).unwrap();
                            matched_info.matched_claim_names.push(display.clone());
                            matched_info.matched_claim_metadata.push(path.clone());
                        }
                        matched_infos.push(matched_info);
                    }
                } else {
                    for claim_set in &query_cred.claim_sets {
                        let mut set_names = Vec::new();
                        let mut set_paths = Vec::new();
                        let mut all_matched = true;
                        for claim_id in claim_set {
                            if let Some((display, path)) = matched_claim_ids.get(claim_id) {
                                set_names.push(display.clone());
                                set_paths.push(path.clone());
                            } else {
                                all_matched = false;
                                break;
                            }
                        }
                        if all_matched {
                            matched_info.matched_claim_names = set_names;
                            matched_info.matched_claim_metadata = set_paths;
                            matched_infos.push(matched_info);
                            break;
                        }
                    }
                }
            }
        }
    }

    (matched_infos, inline_issuance)
}

pub fn dcql_query(query: &DcqQuery, store: &RegistryFormatCollection) -> MatchResult {
    debug!("Starting DCQL query with {} query credentials", query.credentials.len());
    let mut result = MatchResult::default();

    for cred_query in &query.credentials {
        let (matched, inline) = match_credential(cred_query, store);
        if !matched.is_empty() {
            debug!("Query credential {} matched {} local credentials", cred_query.id, matched.len());
            result.matched_credentials.insert(
                cred_query.id.clone(),
                MatchedQueryCredential {
                    id: cred_query.id.clone(),
                    matched,
                },
            );
        }
        if result.inline_issuance.is_none() {
            result.inline_issuance = inline;
        }
    }

    if query.credential_sets.is_empty() {
        debug!("No credential sets in query, checking if all query credentials matched");
        if result.matched_credentials.len() == query.credentials.len() {
            let mut set_info = MatchedOption {
                ..Default::default()
            };
            for q in &query.credentials {
                set_info.matched_credential_ids.push(q.id.clone());
            }
            debug!("Implicit credential set matched with {} credentials", set_info.matched_credential_ids.len());
            result.matched_credential_sets.push(vec![set_info]);
        }
    } else {
        debug!("Evaluating {} credential sets", query.credential_sets.len());
        let mut all_sets_matched = true;
        for (set_idx, set_query) in query.credential_sets.iter().enumerate() {
            if !set_query.required {
                debug!("Skipping optional credential set index {}", set_idx);
                continue;
            }

            let mut curr_set_options = Vec::new();
            for (opt_idx, option) in set_query.options.iter().enumerate() {
                let mut option_matched = true;
                for q_id in option {
                    if !result.matched_credentials.contains_key(q_id) {
                        option_matched = false;
                        break;
                    }
                }
                if option_matched {
                    debug!("Found matching option {} for set index {}", opt_idx, set_idx);
                    curr_set_options.push(MatchedOption {
                        set_id: set_idx.to_string(),
                        option_id: opt_idx.to_string(),
                        matched_credential_ids: option.clone(),
                    });
                }
            }

            if curr_set_options.is_empty() {
                debug!("No matching options for required set index {}, DCQL query failed", set_idx);
                all_sets_matched = false;
                break;
            } else {
                result.matched_credential_sets.push(curr_set_options);
            }
        }
        if !all_sets_matched {
            result.matched_credential_sets.clear();
        }
    }

    result
}
