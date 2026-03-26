use std::collections::HashMap;
use nanoserde::{DeJson, DeJsonErr, DeJsonState, DeJsonTok, SerJson};

#[derive(DeJson, Debug, Default, Clone)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredentialQuery>,
    pub credential_sets: Option<Vec<DcqlCredentialSet>>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct DcqlCredentialQuery {
    pub id: String,
    pub format: String,
    pub meta: Option<DcqlMeta>,
    pub claims: Option<Vec<DcqlClaimQuery>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct DcqlMeta {
    pub doctype_value: Option<String>,
    pub vct_values: Option<Vec<String>>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct DcqlClaimQuery {
    pub id: Option<String>,
    pub path: Vec<String>,
    pub values: Option<Vec<SimpleJson>>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct DcqlCredentialSet {
    pub required: Option<bool>,
    pub options: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SimpleJson {
    String(String),
    Number(f64),
    Bool(bool),
    Array(Vec<SimpleJson>),
    Object(HashMap<String, SimpleJson>),
    Null,
}

impl Default for SimpleJson {
    fn default() -> Self {
        Self::Null
    }
}

impl DeJson for SimpleJson {
    fn de_json(s: &mut DeJsonState, i: &mut core::str::Chars) -> Result<Self, DeJsonErr> {
        match s.tok {
            DeJsonTok::Str => {
                let val = s.as_string()?;
                s.next_tok(i)?;
                Ok(Self::String(val))
            }
            DeJsonTok::U64(_) => {
                let val = s.as_f64()?;
                s.next_tok(i)?;
                Ok(Self::Number(val))
            }
            DeJsonTok::I64(_) => {
                let val = s.as_f64()?;
                s.next_tok(i)?;
                Ok(Self::Number(val))
            }
            DeJsonTok::F64(_) => {
                let val = s.as_f64()?;
                s.next_tok(i)?;
                Ok(Self::Number(val))
            }
            DeJsonTok::Bool(_) => {
                let val = s.as_bool()?;
                s.next_tok(i)?;
                Ok(Self::Bool(val))
            }
            DeJsonTok::Null => {
                s.next_tok(i)?;
                Ok(Self::Null)
            }
            DeJsonTok::BlockOpen => {
                let mut out = Vec::new();
                s.block_open(i)?;
                while s.tok != DeJsonTok::BlockClose {
                    out.push(DeJson::de_json(s, i)?);
                    s.eat_comma_block(i)?;
                }
                s.block_close(i)?;
                Ok(Self::Array(out))
            }
            DeJsonTok::CurlyOpen => {
                let mut h = HashMap::new();
                s.curly_open(i)?;
                while s.tok != DeJsonTok::CurlyClose {
                    let k = DeJson::de_json(s, i)?;
                    s.colon(i)?;
                    let v = DeJson::de_json(s, i)?;
                    s.eat_comma_curly(i)?;
                    h.insert(k, v);
                }
                s.curly_close(i)?;
                Ok(Self::Object(h))
            }
            _ => Err(s.err_token("json value")),
        }
    }
}

impl SimpleJson {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&SimpleJson> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct CredentialStore {
    pub credentials: HashMap<String, SimpleJson>,
    pub issuance: Option<HashMap<String, Vec<InlineIssuanceCredential>>>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct InlineIssuanceCredential {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub icon: Option<StoredIcon>,
    pub supported: Vec<String>,
}

#[derive(DeJson, Debug, Default, Clone, SerJson)]
pub struct StoredIcon {
    pub start: usize,
    pub length: usize,
}

#[derive(DeJson, Debug, Default, Clone, SerJson)]
pub struct StoredDisplay {
    pub verification: Option<VerificationDisplay>,
}

#[derive(DeJson, Debug, Default, Clone, SerJson)]
pub struct VerificationDisplay {
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub explainer: Option<String>,
    pub metadata_display_text: Option<String>,
    pub icon: Option<StoredIcon>,
}

pub struct MatchResult {
    pub matched_credential_sets: Vec<Vec<MatchedOption>>,
    pub matched_credentials: HashMap<String, MatchedCredentialInfo>,
    pub inline_issuance: Option<InlineIssuanceInfo>,
}

pub struct MatchedOption {
    pub set_id: String,
    pub option_id: String,
    pub matched_credential_ids: Vec<String>,
}

pub struct MatchedCredentialInfo {
    pub id: String,
    pub matched: Vec<MatchedCredential>,
}

#[derive(SerJson, Clone)]
pub struct MatchedCredential {
    pub id: String,
    pub display: Option<StoredDisplay>,
    pub matched_claim_names: Vec<ClaimDisplayInfo>,
    pub matched_claim_metadata: Vec<Vec<String>>,
}

#[derive(SerJson, Clone)]
pub struct ClaimDisplayInfo {
    pub display: String,
    pub display_value: String,
}

pub struct InlineIssuanceInfo {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub icon: Option<StoredIcon>,
}

pub fn dcql_query(query: &DcqlQuery, store: &CredentialStore) -> MatchResult {
    let mut candidate_matched_credentials = HashMap::new();
    let mut candidate_inline_issuance_credentials = HashMap::new();

    for cred_query in &query.credentials {
        let (matched, inline) = match_credential(cred_query, store);
        if !matched.is_empty() {
            candidate_matched_credentials.insert(
                cred_query.id.clone(),
                MatchedCredentialInfo {
                    id: cred_query.id.clone(),
                    matched,
                },
            );
        }
        if let Some(i) = inline {
            candidate_inline_issuance_credentials.insert(cred_query.id.clone(), i);
        }
    }

    let mut matched_credential_sets = Vec::new();
    let mut final_matched_credentials = HashMap::new();

    if let Some(credential_sets) = &query.credential_sets {
        let mut all_sets_matched = true;
        for (set_idx, set) in credential_sets.iter().enumerate() {
            if set.required == Some(false) {
                continue;
            }
            let mut curr_matched_options = Vec::new();
            for (option_idx, option) in set.options.iter().enumerate() {
                let mut option_matched = true;
                let mut matched_cred_ids = Vec::new();
                for cred_id in option {
                    if !candidate_matched_credentials.contains_key(cred_id) {
                        option_matched = false;
                        break;
                    }
                    matched_cred_ids.push(cred_id.clone());
                    if !final_matched_credentials.contains_key(cred_id) {
                        final_matched_credentials.insert(
                            cred_id.clone(),
                            candidate_matched_credentials.get(cred_id).unwrap().matched.clone()
                        );
                    }
                }
                if option_matched {
                    curr_matched_options.push(MatchedOption {
                        set_id: set_idx.to_string(),
                        option_id: option_idx.to_string(),
                        matched_credential_ids: matched_cred_ids,
                    });
                }
            }
            if curr_matched_options.is_empty() {
                all_sets_matched = false;
                break;
            }
            matched_credential_sets.push(curr_matched_options);
        }
        if !all_sets_matched {
            matched_credential_sets.clear();
            final_matched_credentials.clear();
        }
    } else {
        if query.credentials.len() == candidate_matched_credentials.len() {
            let mut matched_cred_ids = Vec::new();
            for cred_query in &query.credentials {
                matched_cred_ids.push(cred_query.id.clone());
                final_matched_credentials.insert(
                    cred_query.id.clone(),
                    candidate_matched_credentials.get(&cred_query.id).unwrap().matched.clone(),
                );
            }
            matched_credential_sets.push(vec![MatchedOption {
                set_id: "null".to_string(),
                option_id: "null".to_string(),
                matched_credential_ids: matched_cred_ids,
            }]);
        }
    }

    let mut inline_issuance = None;
    if final_matched_credentials.is_empty() {
        if query.credentials.len() == candidate_inline_issuance_credentials.len() {
            for (_, info) in candidate_inline_issuance_credentials {
                inline_issuance = Some(info);
                break;
            }
        }
    }

    let mut final_map = HashMap::new();
    for (k, v) in final_matched_credentials {
        final_map.insert(k.clone(), MatchedCredentialInfo { id: k, matched: v });
    }

    MatchResult {
        matched_credential_sets,
        matched_credentials: final_map,
        inline_issuance,
    }
}

fn match_credential(
    query: &DcqlCredentialQuery,
    store: &CredentialStore,
) -> (Vec<MatchedCredential>, Option<InlineIssuanceInfo>) {
    let mut matched_creds = Vec::new();
    let mut inline_issuance = None;

    let format_candidates = store.credentials.get(&query.format);
    
    if let Some(issuance_map) = &store.issuance {
        if let Some(candidates) = issuance_map.get(&query.format) {
            for candidate in candidates {
                if let Some(meta) = &query.meta {
                    if let Some(doctype) = &meta.doctype_value {
                        if candidate.supported.contains(doctype) {
                            inline_issuance = Some(InlineIssuanceInfo {
                                id: candidate.id.clone(),
                                title: candidate.title.clone(),
                                subtitle: candidate.subtitle.clone(),
                                icon: candidate.icon.clone(),
                            });
                            break;
                        }
                    }
                    if let Some(vcts) = &meta.vct_values {
                        for vct in vcts {
                            if candidate.supported.contains(vct) {
                                inline_issuance = Some(InlineIssuanceInfo {
                                    id: candidate.id.clone(),
                                    title: candidate.title.clone(),
                                    subtitle: candidate.subtitle.clone(),
                                    icon: candidate.icon.clone(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(candidates_json) = format_candidates {
        let mut candidates = Vec::new();
        if let Some(meta) = &query.meta {
            if query.format == "mso_mdoc" {
                if let Some(doctype) = &meta.doctype_value {
                    if let Some(list) = candidates_json.get(doctype) {
                        if let SimpleJson::Array(arr) = list {
                            candidates.extend(arr.iter().cloned());
                        }
                    }
                }
            } else if query.format == "dc+sd-jwt" {
                if let Some(vct_values) = &meta.vct_values {
                    for vct in vct_values {
                        if let Some(list) = candidates_json.get(vct) {
                            if let SimpleJson::Array(arr) = list {
                                candidates.extend(arr.iter().cloned());
                            }
                        }
                    }
                }
            }
        }

        for candidate in candidates {
            if let SimpleJson::Object(cand_obj) = &candidate {
                let mut matched_claim_names = Vec::new();
                let mut matched_claim_metadata = Vec::new();

                if let Some(claims_query) = &query.claims {
                    let mut all_claims_matched = true;
                    let mut matched_claim_ids = HashMap::new();

                    for claim_q in claims_query {
                        let mut curr = &candidate;
                        if let Some(paths_obj) = cand_obj.get("paths").or_else(|| cand_obj.get("namespaces")) {
                            curr = paths_obj;
                        }

                        let mut found = true;
                        for segment in &claim_q.path {
                            if let Some(next) = curr.get(segment) {
                                curr = next;
                            } else {
                                found = false;
                                break;
                            }
                        }

                        if found {
                            if let Some(SimpleJson::String(display_str)) = curr.get("display") {
                                let mut value_matched = true;
                                if let Some(allowed_values) = &claim_q.values {
                                    value_matched = false;
                                    if let Some(actual_val) = curr.get("value") {
                                        for v in allowed_values {
                                            if v == actual_val {
                                                value_matched = true;
                                                break;
                                            }
                                        }
                                    }
                                }

                                if value_matched {
                                    let display_value = curr.get("display_value")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    
                                    let info = ClaimDisplayInfo {
                                        display: display_str.clone(),
                                        display_value,
                                    };
                                    if let Some(id) = &claim_q.id {
                                        matched_claim_ids.insert(id.clone(), (info, claim_q.path.clone()));
                                    } else {
                                        matched_claim_names.push(info);
                                        matched_claim_metadata.push(claim_q.path.clone());
                                    }
                                } else {
                                    all_claims_matched = false;
                                }
                            } else {
                                all_claims_matched = false;
                            }
                        } else {
                            all_claims_matched = false;
                        }
                    }

                    if let Some(claim_sets) = &query.claim_sets {
                        let mut set_matched = false;
                        for set in claim_sets {
                            let mut all_in_set = true;
                            let mut set_names = Vec::new();
                            let mut set_meta = Vec::new();
                            for claim_id in set {
                                if let Some((info, path)) = matched_claim_ids.get(claim_id) {
                                    set_names.push(info.clone());
                                    set_meta.push(path.clone());
                                } else {
                                    all_in_set = false;
                                    break;
                                }
                            }
                            if all_in_set {
                                matched_claim_names = set_names;
                                matched_claim_metadata = set_meta;
                                set_matched = true;
                                break;
                            }
                        }
                        if !set_matched {
                            all_claims_matched = false;
                        }
                    } else {
                        if !matched_claim_ids.is_empty() && matched_claim_names.is_empty() {
                           for (_, (info, path)) in matched_claim_ids {
                               matched_claim_names.push(info);
                               matched_claim_metadata.push(path);
                           }
                        }
                    }

                    if all_claims_matched {
                        matched_creds.push(MatchedCredential {
                            id: cand_obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            display: parse_display(cand_obj.get("display")),
                            matched_claim_names,
                            matched_claim_metadata,
                        });
                    }
                } else {
                    let mut names = Vec::new();
                    let mut meta = Vec::new();
                    if let Some(paths) = cand_obj.get("paths").or_else(|| cand_obj.get("namespaces")) {
                        add_all_claims(paths, &mut Vec::new(), &mut names, &mut meta);
                    }

                    matched_creds.push(MatchedCredential {
                        id: cand_obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        display: parse_display(cand_obj.get("display")),
                        matched_claim_names: names,
                        matched_claim_metadata: meta,
                    });
                }
            }
        }
    }

    (matched_creds, inline_issuance)
}

fn add_all_claims(node: &SimpleJson, path: &mut Vec<String>, names: &mut Vec<ClaimDisplayInfo>, meta: &mut Vec<Vec<String>>) {
    match node {
        SimpleJson::Object(map) => {
            if let Some(SimpleJson::String(display)) = map.get("display") {
                let display_value = map.get("display_value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                names.push(ClaimDisplayInfo { display: display.clone(), display_value });
                meta.push(path.clone());
            } else {
                for (key, val) in map {
                    path.push(key.clone());
                    add_all_claims(val, path, names, meta);
                    path.pop();
                }
            }
        }
        _ => ()
    }
}

fn parse_display(display: Option<&SimpleJson>) -> Option<StoredDisplay> {
    if let Some(SimpleJson::Object(map)) = display {
        if let Some(SimpleJson::Object(ver_map)) = map.get("verification") {
            return Some(StoredDisplay {
                verification: Some(VerificationDisplay {
                    title: ver_map.get("title").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    subtitle: ver_map.get("subtitle").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    explainer: ver_map.get("explainer").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    metadata_display_text: ver_map.get("metadata_display_text").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    icon: ver_map.get("icon").and_then(|v| {
                        if let SimpleJson::Object(icon_map) = v {
                            Some(StoredIcon {
                                start: icon_map.get("start").and_then(|iv| match iv { SimpleJson::Number(n) => Some(*n as usize), _ => None }).unwrap_or(0),
                                length: icon_map.get("length").and_then(|iv| match iv { SimpleJson::Number(n) => Some(*n as usize), _ => None }).unwrap_or(0),
                            })
                        } else { None }
                    }),
                })
            });
        }
    }
    None
}
