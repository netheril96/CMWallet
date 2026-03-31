use nanoserde::{DeJson, DeJsonErr, DeJsonState, DeJsonTok, SerJson, SerJsonState};
use std::collections::HashMap;
use std::str::Chars;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

impl Default for JsonValue {
    fn default() -> Self {
        JsonValue::Null
    }
}

impl DeJson for JsonValue {
    fn de_json(state: &mut DeJsonState, input: &mut Chars) -> Result<Self, DeJsonErr> {
        match state.tok {
            DeJsonTok::Str => {
                let v = state.as_string()?;
                state.next_tok(input)?;
                Ok(JsonValue::String(v))
            }
            DeJsonTok::F64(v) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(v))
            }
            DeJsonTok::I64(v) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(v as f64))
            }
            DeJsonTok::U64(v) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(v as f64))
            }
            DeJsonTok::Bool(v) => {
                state.next_tok(input)?;
                Ok(JsonValue::Bool(v))
            }
            DeJsonTok::Null => {
                state.next_tok(input)?;
                Ok(JsonValue::Null)
            }
            DeJsonTok::BlockOpen => {
                state.next_tok(input)?;
                let mut res = Vec::new();
                while state.tok != DeJsonTok::BlockClose {
                    res.push(DeJson::de_json(state, input)?);
                    if state.tok == DeJsonTok::Comma {
                        state.next_tok(input)?;
                    }
                }
                state.next_tok(input)?;
                Ok(JsonValue::Array(res))
            }
            DeJsonTok::CurlyOpen => {
                state.next_tok(input)?;
                let mut res = HashMap::new();
                while state.tok != DeJsonTok::CurlyClose {
                    let key = state.as_string()?;
                    state.next_tok(input)?;
                    if state.tok != DeJsonTok::Colon {
                        return Err(state.err_exp(":"));
                    }
                    state.next_tok(input)?;
                    res.insert(key, DeJson::de_json(state, input)?);
                    if state.tok == DeJsonTok::Comma {
                        state.next_tok(input)?;
                    }
                }
                state.next_tok(input)?;
                Ok(JsonValue::Object(res))
            }
            _ => Err(state.err_exp("JSON value")),
        }
    }
}

impl SerJson for JsonValue {
    fn ser_json(&self, d: usize, s: &mut SerJsonState) {
        match self {
            JsonValue::String(v) => SerJson::ser_json(v, d, s),
            JsonValue::Number(v) => SerJson::ser_json(v, d, s),
            JsonValue::Bool(v) => SerJson::ser_json(v, d, s),
            JsonValue::Null => s.out.push_str("null"),
            JsonValue::Array(v) => SerJson::ser_json(v, d, s),
            JsonValue::Object(v) => SerJson::ser_json(v, d, s),
        }
    }
}

#[derive(DeJson, SerJson, Debug, Default)]
#[nserde(default)]
pub struct DCQLQuery {
    pub credentials: Vec<CredentialQuery>,
    pub credential_sets: Option<Vec<CredentialSet>>,
}

#[derive(DeJson, SerJson, Debug, Default)]
#[nserde(default)]
pub struct CredentialQuery {
    pub id: String,
    pub format: Option<String>,
    pub meta: Option<HashMap<String, JsonValue>>,
    pub claims: Option<Vec<ClaimQuery>>,
}

#[derive(DeJson, SerJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct ClaimQuery {
    pub id: Option<String>,
    pub path: Vec<String>,
    pub value: Option<JsonValue>,
}

#[derive(DeJson, SerJson, Debug, Default)]
#[nserde(default)]
pub struct CredentialSet {
    pub options: Vec<Vec<String>>,
    pub required: Option<bool>,
}

#[derive(DeJson, SerJson, Debug, Default)]
#[nserde(default)]
pub struct CredentialStore {
    pub credentials: HashMap<String, HashMap<String, Vec<CredentialEntry>>>,
    pub issuance: Option<HashMap<String, Vec<IssuanceEntry>>>,
}

#[derive(DeJson, SerJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct CredentialEntry {
    pub id: String,
    pub display: JsonValue,
    pub paths: HashMap<String, JsonValue>, // recursive
}

#[derive(DeJson, SerJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct IssuanceEntry {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub icon: Option<IconInfo>,
    pub supported: Vec<JsonValue>,
}

#[derive(DeJson, SerJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct IconInfo {
    pub start: u32,
    pub length: u32,
}

#[derive(SerJson, Debug)]
pub struct MatchedResult {
    pub matched_credential_sets: Vec<Vec<MatchedOption>>,
    pub matched_credentials: HashMap<String, MatchedCredentialQueryResults>,
    pub inline_issuance: Option<IssuanceEntry>,
}

#[derive(SerJson, Debug, Clone)]
pub struct MatchedOption {
    pub matched_credential_ids: Vec<String>,
    pub set_id: Option<String>,
    pub option_id: Option<String>,
}

#[derive(SerJson, Debug)]
pub struct MatchedCredentialQueryResults {
    pub id: String,
    pub matched: Vec<MatchedCredential>,
}

#[derive(SerJson, Debug, Clone)]
pub struct MatchedCredential {
    pub id: String,
    pub display: JsonValue,
    pub matched_claim_names: Vec<JsonValue>,
    pub matched_claim_metadata: Vec<Vec<String>>,
}

impl JsonValue {
    pub fn to_display_string(&self) -> String {
        match self {
            JsonValue::String(s) => s.clone(),
            JsonValue::Number(n) => n.to_string(),
            JsonValue::Bool(b) => b.to_string(),
            JsonValue::Null => "null".to_string(),
            JsonValue::Array(_) => "[...]".to_string(),
            JsonValue::Object(_) => "{...}".to_string(),
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }
}

pub fn matches_claims(query: &CredentialQuery, cred: &CredentialEntry) -> Option<MatchedCredential> {
    log::trace!("Checking claims for credential: {}", cred.id);
    let mut matched_claim_names = Vec::new();
    let mut matched_claim_metadata = Vec::new();

    if let Some(claims_query) = &query.claims {
        log::trace!("Query has {} claim requirements", claims_query.len());
        for cq in claims_query {
            log::trace!("Checking claim path: {:?}", cq.path);
            if let Some(leaf) = get_claim_leaf(&cred.paths, &cq.path) {
                if let JsonValue::Object(obj) = leaf {
                    let mut value_matched = true;
                    if let Some(val) = obj.get("value") {
                        if let Some(expected_val) = &cq.value {
                            if val != expected_val {
                                log::trace!("Claim value mismatch for {:?}. Expected {:?}, found {:?}", cq.path, expected_val, val);
                                value_matched = false;
                            }
                        }
                    } else if cq.value.is_some() {
                        log::trace!("Claim value missing for {:?} but expected {:?}", cq.path, cq.value);
                        value_matched = false;
                    }

                    if value_matched {
                        if let Some(display) = obj.get("display") {
                            log::trace!("Claim matched: {:?}", cq.path);
                            matched_claim_names.push(display.clone());
                            matched_claim_metadata.push(cq.path.clone());
                        } else {
                            log::trace!("Claim matched but missing 'display' object for {:?}", cq.path);
                            return None;
                        }
                    } else {
                        return None;
                    }
                } else {
                    log::trace!("Claim leaf is not an object for {:?}", cq.path);
                    return None;
                }
            } else {
                log::trace!("Claim path not found: {:?}", cq.path);
                return None;
            }
        }
    } else {
        log::trace!("No claims requested, adding all available claims");
        add_all_claims(&mut matched_claim_names, &cred.paths);
    }

    if let Some(claims_query) = &query.claims {
        if matched_claim_names.len() != claims_query.len() {
            log::trace!("Not all claims matched for credential {}. Matched {}, expected {}", cred.id, matched_claim_names.len(), claims_query.len());
            return None;
        }
    }

    log::debug!("Credential {} matched all {} required claims", cred.id, matched_claim_names.len());
    Some(MatchedCredential {
        id: cred.id.clone(),
        display: cred.display.clone(),
        matched_claim_names,
        matched_claim_metadata,
    })
}

fn add_all_claims(matched_claim_names: &mut Vec<JsonValue>, paths: &HashMap<String, JsonValue>) {
    for (key, val) in paths {
        match val {
            JsonValue::Object(obj) => {
                if let Some(display) = obj.get("display") {
                    log::trace!("Adding all-claims match: {}", key);
                    matched_claim_names.push(display.clone());
                } else {
                    add_all_claims(matched_claim_names, obj);
                }
            }
            _ => {}
        }
    }
}

pub fn get_claim_leaf<'a>(
    paths: &'a HashMap<String, JsonValue>,
    path: &[String],
) -> Option<&'a JsonValue> {
    if path.is_empty() {
        return None;
    }
    let mut current = paths.get(&path[0])?;
    for part in &path[1..] {
        match current {
            JsonValue::Object(obj) => {
                current = obj.get(part)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

pub fn dcql_query(query: &DCQLQuery, store: &CredentialStore) -> MatchedResult {
    log::debug!("Starting DCQL query execution with {} credential requirements", query.credentials.len());
    let mut candidate_matched_credentials = HashMap::new();

    for cq in &query.credentials {
        log::debug!("Evaluating candidates for query id: {}", cq.id);
        let mut matched = Vec::new();
        let format = cq.format.as_deref().unwrap_or("");
        if let Some(format_map) = store.credentials.get(format) {
            let mut candidates = Vec::new();
            if format == "mso_mdoc" {
                if let Some(doctype_val) = cq
                    .meta
                    .as_ref()
                    .and_then(|m| m.get("doctype_value"))
                    .and_then(|v| v.as_string())
                {
                    log::trace!("Filtering mso_mdoc by doctype: {}", doctype_val);
                    if let Some(creds) = format_map.get(doctype_val) {
                        candidates.extend(creds);
                    }
                } else {
                    log::trace!("mso_mdoc query missing doctype_value, checking all candidates");
                    for creds in format_map.values() {
                        candidates.extend(creds);
                    }
                }
            } else if format == "dc+sd-jwt" {
                if let Some(vct_values) = cq
                    .meta
                    .as_ref()
                    .and_then(|m| m.get("vct_values"))
                    .and_then(|v| v.as_array())
                {
                    log::trace!("Filtering dc+sd-jwt by {} VCT values", vct_values.len());
                    for vct_val in vct_values {
                        if let Some(vct_str) = vct_val.as_string() {
                            if let Some(creds) = format_map.get(vct_str) {
                                candidates.extend(creds);
                            }
                        }
                    }
                } else {
                    log::trace!("dc+sd-jwt query missing vct_values, checking all candidates");
                    for creds in format_map.values() {
                        candidates.extend(creds);
                    }
                }
            } else {
                log::trace!("Generic format {}, checking all candidates", format);
                for creds in format_map.values() {
                    candidates.extend(creds);
                }
            }

            log::trace!("Testing {} candidates for query {}", candidates.len(), cq.id);
            for cred in candidates {
                if let Some(mc) = matches_claims(cq, cred) {
                    matched.push(mc);
                }
            }
        } else {
            log::trace!("No credentials found for format: {}", format);
        }

        if !matched.is_empty() {
            log::debug!("Query {} satisfied by {} credentials", cq.id, matched.len());
            candidate_matched_credentials.insert(
                cq.id.clone(),
                MatchedCredentialQueryResults {
                    id: cq.id.clone(),
                    matched,
                },
            );
        } else {
            log::debug!("Query {} NOT satisfied by any available credentials", cq.id);
        }
    }

    let mut matched_credential_sets = Vec::new();
    let mut final_matched_credentials = HashMap::new();

    if let Some(credential_sets) = &query.credential_sets {
        log::debug!("Evaluating {} credential sets", credential_sets.len());
        let mut all_satisfied = true;
        for (set_idx, cs) in credential_sets.iter().enumerate() {
            if cs.required == Some(false) {
                log::trace!("Credential set {} is optional, skipping satisfaction check", set_idx);
                continue;
            }
            let mut curr_matched_options = Vec::new();
            for (opt_idx, option) in cs.options.iter().enumerate() {
                log::trace!("Checking option {} for set {}", opt_idx, set_idx);
                let mut option_satisfied = true;
                for cred_id in option {
                    if !candidate_matched_credentials.contains_key(cred_id) {
                        log::trace!("Option {} NOT satisfied: missing dependency {}", opt_idx, cred_id);
                        option_satisfied = false;
                        break;
                    }
                }
                if option_satisfied {
                    log::trace!("Option {} satisfied for set {}", opt_idx, set_idx);
                    curr_matched_options.push(MatchedOption {
                        matched_credential_ids: option.clone(),
                        set_id: Some(set_idx.to_string()),
                        option_id: Some(opt_idx.to_string()),
                    });
                    for cred_id in option {
                        if let Some(res) = candidate_matched_credentials.get(cred_id) {
                            final_matched_credentials.insert(cred_id.clone(), MatchedCredentialQueryResults {
                                id: res.id.clone(),
                                matched: res.matched.clone(),
                            });
                        }
                    }
                }
            }
            if curr_matched_options.is_empty() {
                log::debug!("Required credential set {} NOT satisfied by any option", set_idx);
                all_satisfied = false;
                break;
            } else {
                log::debug!("Credential set {} satisfied by {} options", set_idx, curr_matched_options.len());
                matched_credential_sets.push(curr_matched_options);
            }
        }
        if !all_satisfied {
            log::debug!("Not all required credential sets satisfied. Query failed.");
            matched_credential_sets.clear();
            final_matched_credentials.clear();
        }
    } else {
        log::debug!("No credential sets provided. All {} credential requirements must be satisfied.", query.credentials.len());
        if candidate_matched_credentials.len() == query.credentials.len() {
            log::debug!("All requirements satisfied.");
            let matched_ids: Vec<String> = query.credentials.iter().map(|c| c.id.clone()).collect();
            matched_credential_sets.push(vec![MatchedOption {
                matched_credential_ids: matched_ids,
                set_id: None,
                option_id: None,
            }]);
            final_matched_credentials = candidate_matched_credentials;
        } else {
            log::debug!("Only {} out of {} requirements satisfied. Query failed.", candidate_matched_credentials.len(), query.credentials.len());
        }
    }

    log::debug!("DCQL query result: {} matched sets, {} matched credentials", matched_credential_sets.len(), final_matched_credentials.len());
    MatchedResult {
        matched_credential_sets,
        matched_credentials: final_matched_credentials,
        inline_issuance: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_claims_success() {
        let query = CredentialQuery {
            id: "q1".into(),
            format: Some("mso_mdoc".into()),
            claims: Some(vec![ClaimQuery {
                id: None,
                path: vec!["given_name".into()],
                value: Some(JsonValue::String("John".into())),
            }]),
            ..Default::default()
        };

        let mut leaf = HashMap::new();
        leaf.insert("display".into(), JsonValue::String("Given Name".into()));
        leaf.insert("value".into(), JsonValue::String("John".into()));

        let mut paths = HashMap::new();
        paths.insert("given_name".into(), JsonValue::Object(leaf));

        let cred = CredentialEntry {
            id: "c1".into(),
            display: JsonValue::Null,
            paths,
        };
        assert!(matches_claims(&query, &cred).is_some());
    }

    #[test]
    fn test_matches_claims_fail_value() {
        let query = CredentialQuery {
            id: "q1".into(),
            format: Some("mso_mdoc".into()),
            claims: Some(vec![ClaimQuery {
                id: None,
                path: vec!["given_name".into()],
                value: Some(JsonValue::String("John".into())),
            }]),
            ..Default::default()
        };

        let mut leaf = HashMap::new();
        leaf.insert("display".into(), JsonValue::String("Given Name".into()));
        leaf.insert("value".into(), JsonValue::String("Jane".into()));

        let mut paths = HashMap::new();
        paths.insert("given_name".into(), JsonValue::Object(leaf));

        let cred = CredentialEntry {
            id: "c1".into(),
            display: JsonValue::Null,
            paths,
        };
        assert!(matches_claims(&query, &cred).is_none());
    }

    #[test]
    fn test_matches_claims_recursive() {
        let query = CredentialQuery {
            id: "q1".into(),
            claims: Some(vec![ClaimQuery {
                id: None,
                path: vec!["address".into(), "locality".into()],
                value: Some(JsonValue::String("London".into())),
            }]),
            ..Default::default()
        };

        let mut leaf = HashMap::new();
        leaf.insert("display".into(), JsonValue::String("Locality".into()));
        leaf.insert("value".into(), JsonValue::String("London".into()));

        let mut address = HashMap::new();
        address.insert("locality".into(), JsonValue::Object(leaf));

        let mut paths = HashMap::new();
        paths.insert("address".into(), JsonValue::Object(address));

        let cred = CredentialEntry {
            id: "c1".into(),
            display: JsonValue::Null,
            paths,
        };
        assert!(matches_claims(&query, &cred).is_some());
    }

    #[test]
    fn test_dcql_query_credential_sets_satisfied() {
        let query = DCQLQuery {
            credentials: vec![
                CredentialQuery { id: "q1".into(), ..Default::default() },
                CredentialQuery { id: "q2".into(), ..Default::default() },
            ],
            credential_sets: Some(vec![
                CredentialSet {
                    options: vec![vec!["q1".into()], vec!["q2".into()]],
                    ..Default::default()
                }
            ]),
        };

        let mut store = CredentialStore::default();
        let mut format_map = HashMap::new();
        let mut doctype_map = HashMap::new();
        doctype_map.insert("".into(), vec![
            CredentialEntry { id: "c1".into(), ..Default::default() },
            CredentialEntry { id: "c2".into(), ..Default::default() }
        ]);
        format_map.insert("".into(), doctype_map);
        store.credentials = format_map;

        let res = dcql_query(&query, &store);
        assert_eq!(res.matched_credential_sets.len(), 1);
        assert_eq!(res.matched_credential_sets[0].len(), 2); // Both q1 and q2 matched
        assert!(res.matched_credentials.contains_key("q1"));
        assert!(res.matched_credentials.contains_key("q2"));
    }

    #[test]
    fn test_dcql_query_credential_sets_not_satisfied() {
        let query = DCQLQuery {
            credentials: vec![
                CredentialQuery { id: "q1".into(), format: Some("f1".into()), ..Default::default() },
            ],
            credential_sets: Some(vec![
                CredentialSet {
                    options: vec![vec!["q1".into()]],
                    required: Some(true),
                }
            ]),
        };

        let store = CredentialStore::default(); // Empty store
        let res = dcql_query(&query, &store);
        assert!(res.matched_credential_sets.is_empty());
        assert!(res.matched_credentials.is_empty());
    }

    #[test]
    fn test_dcql_query_optional_set() {
        let query = DCQLQuery {
            credentials: vec![
                CredentialQuery { id: "q1".into(), format: Some("f1".into()), ..Default::default() },
            ],
            credential_sets: Some(vec![
                CredentialSet {
                    options: vec![vec!["q1".into()]],
                    required: Some(false),
                }
            ]),
        };

        let store = CredentialStore::default();
        let res = dcql_query(&query, &store);
        // Even if q1 doesn't match, it's satisfied because it's not required
        // But matched_credential_sets will be empty because no options matched
        assert!(res.matched_credential_sets.is_empty());
    }
}
