use nanoserde::DeJson;
use std::collections::HashMap;

#[derive(DeJson, Debug, Clone)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredential>,
    pub credential_sets: Option<Vec<DcqlCredentialSet>>,
}

#[derive(DeJson, Debug, Clone)]
pub struct DcqlCredential {
    pub id: String,
    pub format: String,
    pub meta: Option<DcqlMeta>,
    pub claims: Option<Vec<DcqlClaim>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
}

#[derive(DeJson, Debug, Clone)]
pub struct DcqlMeta {
    pub doctype_value: Option<String>,
    pub vct_values: Option<Vec<String>>,
}

#[derive(DeJson, Debug, Clone)]
pub struct DcqlClaim {
    pub id: Option<String>,
    pub path: Vec<String>,
    pub values: Option<Vec<JsonValue>>,
}

#[derive(DeJson, Debug, Clone)]
pub struct DcqlCredentialSet {
    pub options: Vec<Vec<String>>,
    pub required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

// Since nanoserde doesn't have a Value type, we'll implement DeJson for JsonValue.
// This is a bit tedious but necessary.
// Actually, let's see if we can just skip it for now and use specific types if we know them.
// But we don't.
// Let's implement a minimal DeJson for JsonValue if possible.
// Actually, nanoserde::DeJson is a trait.

impl DeJson for JsonValue {
    fn de_json(
        state: &mut nanoserde::DeJsonState,
        input: &mut std::str::Chars,
    ) -> Result<Self, nanoserde::DeJsonErr> {
        match state.tok {
            nanoserde::DeJsonTok::Str => {
                let s = state.strbuf.clone();
                state.next_tok(input)?;
                Ok(JsonValue::String(s))
            }
            nanoserde::DeJsonTok::F64(n) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(n))
            }
            nanoserde::DeJsonTok::U64(n) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(n as f64))
            }
            nanoserde::DeJsonTok::I64(n) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(n as f64))
            }
            nanoserde::DeJsonTok::Bool(b) => {
                state.next_tok(input)?;
                Ok(JsonValue::Bool(b))
            }
            nanoserde::DeJsonTok::Null => {
                state.next_tok(input)?;
                Ok(JsonValue::Null)
            }
            nanoserde::DeJsonTok::BlockOpen => {
                state.next_tok(input)?;
                let mut arr = Vec::new();
                while state.tok != nanoserde::DeJsonTok::BlockClose {
                    arr.push(JsonValue::de_json(state, input)?);
                    if state.tok == nanoserde::DeJsonTok::Comma {
                        state.next_tok(input)?;
                    }
                }
                state.next_tok(input)?;
                Ok(JsonValue::Array(arr))
            }
            nanoserde::DeJsonTok::CurlyOpen => {
                state.next_tok(input)?;
                let mut obj = HashMap::new();
                while state.tok != nanoserde::DeJsonTok::CurlyClose {
                    if state.tok == nanoserde::DeJsonTok::Str {
                        let key = state.strbuf.clone();
                        state.next_tok(input)?;
                        if state.tok != nanoserde::DeJsonTok::Colon {
                            return Err(state.err_exp("Colon"));
                        }
                        state.next_tok(input)?;
                        obj.insert(key, JsonValue::de_json(state, input)?);
                        if state.tok == nanoserde::DeJsonTok::Comma {
                            state.next_tok(input)?;
                        }
                    } else {
                        return Err(state.err_exp("String key"));
                    }
                }
                state.next_tok(input)?;
                Ok(JsonValue::Object(obj))
            }
            _ => Err(state.err_exp("JsonValue")),
        }
    }
}

// Registry Structures
#[derive(DeJson, Debug, Clone)]
pub struct Registry {
    pub credentials: RegistryCredentials,
}

#[derive(DeJson, Debug, Clone)]
pub struct RegistryCredentials {
    #[nserde(rename = "mso_mdoc")]
    pub mso_mdoc: Option<HashMap<String, Vec<RegistryCredential>>>,
    #[nserde(rename = "dc+sd-jwt")]
    pub sd_jwt: Option<HashMap<String, Vec<RegistryCredential>>>,
    pub issuance: Option<RegistryIssuance>,
}

#[derive(DeJson, Debug, Clone)]
pub struct RegistryCredential {
    pub id: String,
    pub display: RegistryDisplay,
    pub paths: HashMap<String, JsonValue>, // Recursive structure
}

#[derive(DeJson, Debug, Clone)]
pub struct RegistryDisplay {
    pub verification: RegistryVerification,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct RegistryVerification {
    pub title: String,
    pub subtitle: Option<String>,
    pub explainer: Option<String>,
    pub warning: Option<String>,
    pub metadata_display_text: Option<String>,
    pub icon: Option<RegistryIcon>,
}

#[derive(DeJson, Debug, Clone)]
pub struct RegistryIcon {
    pub start: usize,
    pub length: usize,
}

#[derive(DeJson, Debug, Clone)]
pub struct RegistryIssuance {
    #[nserde(rename = "mso_mdoc")]
    pub mso_mdoc: Option<Vec<RegistryIssuanceEntry>>,
    #[nserde(rename = "dc+sd-jwt")]
    pub sd_jwt: Option<Vec<RegistryIssuanceEntry>>,
}

#[derive(DeJson, Debug, Clone)]
pub struct RegistryIssuanceEntry {
    pub id: String,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub icon: Option<RegistryIcon>,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MatchedClaim {
    pub display: JsonValue, // RegistryClaimDisplay
    pub path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MatchedCredential {
    pub id: String,
    pub display: RegistryDisplay,
    pub matched_claim_names: Vec<JsonValue>, // RegistryClaimDisplay
    pub matched_claim_metadata: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct MatchCredentialResult {
    pub matched_creds: Vec<MatchedCredential>,
    pub inline_issuance: Option<RegistryIssuanceEntry>,
}

#[derive(Debug, Clone)]
pub struct DcqlMatchResult {
    pub matched_credential_sets: Vec<Vec<MatchedCredentialSetInfo>>,
    pub matched_credentials: HashMap<String, DcqlMatchedCredentialEntry>,
    pub inline_issuance: Option<RegistryIssuanceEntry>,
}

#[derive(Debug, Clone)]
pub struct MatchedCredentialSetInfo {
    pub set_id: String,
    pub option_id: String,
    pub matched_credential_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DcqlMatchedCredentialEntry {
    pub id: String,
    pub matched: Vec<MatchedCredential>,
}

pub fn add_all_claims(matched_claim_names: &mut Vec<JsonValue>, candidate_paths: &HashMap<String, JsonValue>) {
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

pub fn match_credential(credential: &DcqlCredential, registry: &Registry) -> MatchCredentialResult {
    log::debug!("Matching credential req id: {}, format: {}", credential.id, credential.format);
    let mut matched_creds = Vec::new();
    let mut inline_issuance = None;

    let format = &credential.format;
    let meta = &credential.meta;
    let claims = &credential.claims;
    let claim_sets = &credential.claim_sets;

    let (candidates, inline_issuance_candidates) = if format == "mso_mdoc" {
        (registry.credentials.mso_mdoc.as_ref(), registry.credentials.issuance.as_ref().and_then(|i| i.mso_mdoc.as_ref()))
    } else if format == "dc+sd-jwt" {
        (registry.credentials.sd_jwt.as_ref(), registry.credentials.issuance.as_ref().and_then(|i| i.sd_jwt.as_ref()))
    } else {
        log::warn!("Unsupported format: {}", format);
        (None, None)
    };

    let filtered_candidates: Vec<&RegistryCredential> = if let Some(meta) = meta {
        if format == "mso_mdoc" {
            if let Some(doctype) = &meta.doctype_value {
                log::trace!("Filtering mso_mdoc candidates by doctype: {}", doctype);
                // Find inline issuance
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
            if let Some(vct_values) = &meta.vct_values {
                log::trace!("Filtering dc+sd-jwt candidates by vcts: {:?}", vct_values);
                for vct in vct_values {
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

    log::debug!("Found {} potential candidates after meta filtering", filtered_candidates.len());

    for candidate in filtered_candidates {
        log::trace!("Checking candidate: {}", candidate.id);
        let mut matched_claim_names = Vec::new();
        let mut matched_claim_metadata = Vec::new();

        if let Some(claims) = claims {
            if let Some(claim_sets) = claim_sets {
                log::trace!("Candidate {}: matching against claim_sets", candidate.id);
                let mut matched_claim_ids = HashMap::new();
                for claim in claims {
                    if let Some(claim_id) = &claim.id {
                        if let Some(matched_info) = match_claim(claim, &candidate.paths) {
                            log::trace!("Candidate {}: claim {} matched", candidate.id, claim_id);
                            matched_claim_ids.insert(claim_id.clone(), matched_info);
                        }
                    }
                }

                for (idx, claim_set) in claim_sets.iter().enumerate() {
                    let mut current_set_names = Vec::new();
                    let mut current_set_metadata = Vec::new();
                    let mut all_matched = true;
                    for claim_id in claim_set {
                        if let Some(info) = matched_claim_ids.get(claim_id) {
                            current_set_names.push(info.display.clone());
                            current_set_metadata.push(info.path.clone());
                        } else {
                            all_matched = false;
                            break;
                        }
                    }
                    if all_matched {
                        log::debug!("Candidate {}: matched claim set index {}", candidate.id, idx);
                        matched_creds.push(MatchedCredential {
                            id: candidate.id.clone(),
                            display: candidate.display.clone(),
                            matched_claim_names: current_set_names,
                            matched_claim_metadata: current_set_metadata,
                        });
                        break; 
                    }
                }
            } else {
                log::trace!("Candidate {}: matching all {} requested claims", candidate.id, claims.len());
                let mut all_matched = true;
                for claim in claims {
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
                    matched_creds.push(MatchedCredential {
                        id: candidate.id.clone(),
                        display: candidate.display.clone(),
                        matched_claim_names,
                        matched_claim_metadata,
                    });
                }
            }
        } else {
            log::debug!("Candidate {}: no specific claims requested, matching all available claims", candidate.id);
            add_all_claims(&mut matched_claim_names, &candidate.paths);
            matched_creds.push(MatchedCredential {
                id: candidate.id.clone(),
                display: candidate.display.clone(),
                matched_claim_names,
                matched_claim_metadata: Vec::new(),
            });
        }
    }

    MatchCredentialResult {
        matched_creds,
        inline_issuance,
    }
}

fn match_claim(claim: &DcqlClaim, candidate_paths: &HashMap<String, JsonValue>) -> Option<MatchedClaim> {
    let mut curr_val = None;
    for (i, p) in claim.path.iter().enumerate() {
        if i == 0 {
            curr_val = candidate_paths.get(p);
        } else {
            if let Some(JsonValue::Object(obj)) = curr_val {
                curr_val = obj.get(p);
            } else {
                return None;
            }
        }
    }

    if let Some(JsonValue::Object(obj)) = curr_val {
        if let Some(display) = obj.get("display") {
            let actual_value = obj.get("value");
            if let Some(required_values) = &claim.values {
                if let Some(actual) = actual_value {
                    if required_values.iter().any(|v| v == actual) {
                        return Some(MatchedClaim {
                            display: display.clone(),
                            path: claim.path.clone(),
                        });
                    } else {
                        log::trace!("Claim value mismatch at {:?}. Expected one of {:?}, found {:?}", claim.path, required_values, actual);
                    }
                }
                return None;
            } else {
                return Some(MatchedClaim {
                    display: display.clone(),
                    path: claim.path.clone(),
                });
            }
        }
    }
    None
}

pub fn dcql_query(query: &DcqlQuery, registry: &Registry) -> DcqlMatchResult {
    log::info!("Starting DCQL query with {} credential requirements", query.credentials.len());
    let mut candidate_matched_credentials = HashMap::new();
    let mut candidate_inline_issuance_credentials = HashMap::new();

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

    let mut matched_credential_sets = Vec::new();

    if let Some(credential_sets) = &query.credential_sets {
        log::debug!("Evaluating {} credential_sets", credential_sets.len());
        let mut overall_matched = true;
        for (set_idx, set) in credential_sets.iter().enumerate() {
            let is_required = set.required.unwrap_or(true);
            if !is_required {
                log::trace!("Skipping optional credential_set index {}", set_idx);
                continue;
            }
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
                matched_credential_sets.push(curr_matched_options);
            }
        }
        if overall_matched {
            log::info!("Overall DCQL query matched with explicit credential_sets");
            DcqlMatchResult {
                matched_credential_sets,
                matched_credentials: candidate_matched_credentials,
                inline_issuance: None,
            }
        } else {
            log::info!("Overall DCQL query failed (required set mismatch)");
            DcqlMatchResult {
                matched_credential_sets: Vec::new(),
                matched_credentials: HashMap::new(),
                inline_issuance: None,
            }
        }
    } else {
        log::debug!("No explicit credential_sets, checking if all requirements are met");
        if query.credentials.len() == candidate_matched_credentials.len() {
            log::info!("All {} credential requirements satisfied", query.credentials.len());
            let matched_cred_ids: Vec<String> = query.credentials.iter().map(|c| c.id.clone()).collect();
            let single_set_info = MatchedCredentialSetInfo {
                set_id: "".to_string(),
                option_id: "".to_string(),
                matched_credential_ids: matched_cred_ids,
            };
            matched_credential_sets.push(vec![single_set_info]);
        }
        
        let mut inline_issuance = None;
        if query.credentials.len() == candidate_inline_issuance_credentials.len() && !candidate_inline_issuance_credentials.is_empty() {
            log::info!("All requirements could be satisfied by inline issuance");
            inline_issuance = candidate_inline_issuance_credentials.values().next().cloned();
        }

        if !matched_credential_sets.is_empty() || inline_issuance.is_some() {
            DcqlMatchResult {
                matched_credential_sets,
                matched_credentials: candidate_matched_credentials,
                inline_issuance,
            }
        } else {
            log::info!("DCQL query failed to satisfy all requirements");
            DcqlMatchResult {
                matched_credential_sets: Vec::new(),
                matched_credentials: HashMap::new(),
                inline_issuance: None,
            }
        }
    }
}
