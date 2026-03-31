use crate::credman::CredmanApi;
use crate::dcql::{self, CredentialStore, DCQLQuery, JsonValue};
use nanoserde::{DeJson, DeJsonErr, DeJsonState, DeJsonTok, SerJson};
use std::ffi::CString;
use std::str::Chars;

#[derive(DeJson, Debug, Default)]
#[nserde(default)]
pub struct CredentialManagerRequest {
    pub requests: Option<Vec<CredentialManagerRequestData>>,
    pub providers: Option<Vec<CredentialManagerRequestData>>,
}

#[derive(DeJson, Debug, Default)]
#[nserde(default)]
pub struct CredentialManagerRequestData {
    pub protocol: String,
    pub data: Option<RequestPayload>,    // "modern" spec
    pub request: Option<RequestPayload>, // "legacy" spec
}

#[derive(Debug)]
pub enum RequestPayload {
    String(String),
    Object(JsonValue),
}

impl Default for RequestPayload {
    fn default() -> Self {
        RequestPayload::String(String::new())
    }
}

impl DeJson for RequestPayload {
    fn de_json(state: &mut DeJsonState, input: &mut Chars) -> Result<Self, DeJsonErr> {
        match state.tok {
            DeJsonTok::Str => {
                let v = state.as_string()?;
                state.next_tok(input)?;
                Ok(RequestPayload::String(v))
            }
            DeJsonTok::CurlyOpen => {
                let val = JsonValue::de_json(state, input)?;
                Ok(RequestPayload::Object(val))
            }
            _ => Err(state.err_exp("String or Object")),
        }
    }
}

#[derive(DeJson, Debug, Default)]
#[nserde(default)]
pub struct OpenId4VPRequest {
    pub presentation_definition: Option<DCQLQuery>,
    pub dcql_query: Option<DCQLQuery>,
}

#[derive(DeJson)]
pub struct SignedRequestContainer {
    pub request: String,
}

#[derive(SerJson, Debug)]
pub struct MatchMetadata {
    pub claims: Vec<Vec<String>>,
    pub dc_request_index: usize,
    pub dcql_cred_id: String,
    pub dcql_credential_set_index: Option<String>,
    pub dcql_option_index: Option<String>,
}

pub fn openid4vp_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Starting OpenID4VP matching process");
    
    let registered_data = credman.get_registered_data();
    let store = load_credential_store(&registered_data)?;
    log::debug!("Loaded CredentialStore with {} format entries", store.credentials.len());

    let (requests, is_modern) = parse_cm_request(credman)?;
    log::debug!("Processing {} requests (modern: {})", requests.len(), is_modern);

    for (req_idx, req) in requests.iter().enumerate() {
        if let Err(e) = process_request(req_idx, req, &store, credman, &registered_data, is_modern) {
            log::error!("Error processing request {}: {:?}", req_idx, e);
        }
    }

    log::info!("OpenID4VP matching process completed");
    Ok(())
}

fn load_credential_store(registered_data: &[u8]) -> Result<CredentialStore, Box<dyn std::error::Error>> {
    if registered_data.len() < 4 {
        return Err("Registered data too short".into());
    }
    let json_start = u32::from_le_bytes(registered_data[..4].try_into()?) as usize;
    if json_start >= registered_data.len() {
        return Err("Invalid JSON start offset".into());
    }
    let store_str = std::str::from_utf8(&registered_data[json_start..])?;
    let store: CredentialStore = DeJson::deserialize_json(store_str)?;
    Ok(store)
}

fn parse_cm_request(credman: &impl CredmanApi) -> Result<(Vec<CredentialManagerRequestData>, bool), Box<dyn std::error::Error>> {
    let buffer = credman.get_request_buffer();
    if buffer.is_empty() {
        return Ok((Vec::new(), false));
    }
    let request_str = std::str::from_utf8(&buffer)?;
    let cm_request: CredentialManagerRequest = DeJson::deserialize_json(request_str)?;
    
    let is_modern = cm_request.requests.is_some();
    let requests = cm_request
        .requests
        .or(cm_request.providers)
        .ok_or("No requests or providers found")?;
    
    Ok((requests, is_modern))
}

fn process_request(
    req_idx: usize,
    req: &CredentialManagerRequestData,
    store: &CredentialStore,
    credman: &mut impl CredmanApi,
    registered_data: &[u8],
    is_modern: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!("Examining request {}. Protocol: {}", req_idx, req.protocol);
    if req.protocol != "openid4vp-v1-unsigned" && req.protocol != "openid4vp-v1-signed" {
        return Ok(());
    }

    let query = extract_dcql_query(req, is_modern)?;
    let match_result = dcql::dcql_query(&query, store);

    if !match_result.matched_credential_sets.is_empty() {
        report_match_results(req_idx, &match_result, credman, registered_data)?;
    }
    
    Ok(())
}

fn extract_dcql_query(req: &CredentialManagerRequestData, is_modern: bool) -> Result<DCQLQuery, Box<dyn std::error::Error>> {
    let payload = if is_modern {
        req.data.as_ref().ok_or("Missing data field")?
    } else {
        req.request.as_ref().ok_or("Missing request field")?
    };

    let openid_req = match payload {
        RequestPayload::String(s) => {
            let r: OpenId4VPRequest = DeJson::deserialize_json(s)?;
            r
        }
        RequestPayload::Object(obj) => {
            if req.protocol == "openid4vp-v1-signed" {
                let container: SignedRequestContainer = DeJson::deserialize_json(&nanoserde::SerJson::serialize_json(obj))?;
                let parts: Vec<&str> = container.request.split('.').collect();
                if parts.len() < 2 {
                    return Err("Invalid JWT format".into());
                }
                let payload_bytes = base64_url_decode(parts[1])?;
                DeJson::deserialize_json(std::str::from_utf8(&payload_bytes)?)?
            } else {
                DeJson::deserialize_json(&nanoserde::SerJson::serialize_json(obj))?
            }
        }
    };

    openid_req.dcql_query
        .or(openid_req.presentation_definition)
        .ok_or("No DCQL query found".into())
}

fn report_match_results(
    req_idx: usize,
    match_result: &dcql::MatchedResult,
    credman: &mut impl CredmanApi,
    registered_data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let first_set_options = &match_result.matched_credential_sets[0];
    for option in first_set_options {
        let set_id = if let (Some(sid), Some(oid)) = (&option.set_id, &option.option_id) {
            format!("req:{};set:{};option:{}", req_idx, sid, oid)
        } else {
            format!("req:{};null", req_idx)
        };
        let set_id_cstr = CString::new(set_id)?;
        credman.add_entry_set(&set_id_cstr, option.matched_credential_ids.len() as i32);

        for (doc_idx, dcql_cred_id) in option.matched_credential_ids.iter().enumerate() {
            if let Some(res) = match_result.matched_credentials.get(dcql_cred_id) {
                for matched_cred in &res.matched {
                    report_single_match(req_idx, doc_idx, dcql_cred_id, matched_cred, &set_id_cstr, credman, registered_data, option.set_id.as_ref(), option.option_id.as_ref())?;
                }
            }
        }
    }
    Ok(())
}

fn report_single_match(
    req_idx: usize,
    doc_idx: usize,
    dcql_cred_id: &str,
    matched_cred: &dcql::MatchedCredential,
    set_id_cstr: &CString,
    credman: &mut impl CredmanApi,
    registered_data: &[u8],
    dcql_set_idx: Option<&String>,
    dcql_opt_idx: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cred_id_cstr = CString::new(matched_cred.id.clone())?;
    
    let mut title = None;
    let mut subtitle = None;
    let mut disclaimer = None;
    let mut warning = None;
    let mut metadata_display_text = None;
    let mut icon_info = None;

    if let JsonValue::Object(display_obj) = &matched_cred.display {
        if let Some(JsonValue::Object(verif)) = display_obj.get("verification") {
            title = verif.get("title").and_then(|v| if let JsonValue::String(s) = v { Some(s.clone()) } else { None });
            subtitle = verif.get("subtitle").and_then(|v| if let JsonValue::String(s) = v { Some(s.clone()) } else { None });
            disclaimer = verif.get("explainer").and_then(|v| if let JsonValue::String(s) = v { Some(s.clone()) } else { None });
            warning = verif.get("warning").and_then(|v| if let JsonValue::String(s) = v { Some(s.clone()) } else { None });
            metadata_display_text = verif.get("metadata_display_text").and_then(|v| if let JsonValue::String(s) = v { Some(s.clone()) } else { None });
            
            if let Some(JsonValue::Object(icon)) = verif.get("icon") {
                if let (Some(JsonValue::Number(s)), Some(JsonValue::Number(l))) = (icon.get("start"), icon.get("length")) {
                    icon_info = Some((*s as usize, *l as usize));
                }
            }
        }
    }

    let title_cstr = title.map(|t| CString::new(t).unwrap());
    let subtitle_cstr = subtitle.map(|s| CString::new(s).unwrap());
    let disclaimer_cstr = disclaimer.map(|d| CString::new(d).unwrap());
    let warning_cstr = warning.map(|w| CString::new(w).unwrap());
    
    let icon_bytes = icon_info.and_then(|(s, l)| {
        if s + l <= registered_data.len() { Some(&registered_data[s..s+l]) } else { None }
    });

    let metadata = MatchMetadata {
        claims: matched_cred.matched_claim_metadata.clone(),
        dc_request_index: req_idx,
        dcql_cred_id: dcql_cred_id.to_string(),
        dcql_credential_set_index: dcql_set_idx.cloned(),
        dcql_option_index: dcql_opt_idx.cloned(),
    };
    let metadata_json = nanoserde::SerJson::serialize_json(&metadata);
    let metadata_cstr = CString::new(metadata_json)?;

    credman.add_entry_to_set(
        &cred_id_cstr,
        icon_bytes,
        title_cstr.as_ref().map(|t| t.as_c_str()),
        subtitle_cstr.as_ref().map(|s| s.as_c_str()),
        disclaimer_cstr.as_ref().map(|d| d.as_c_str()),
        warning_cstr.as_ref().map(|w| w.as_c_str()),
        Some(&metadata_cstr),
        set_id_cstr,
        doc_idx as i32,
    );

    for claim_name_val in &matched_cred.matched_claim_names {
        if let JsonValue::Object(display_obj) = claim_name_val {
            if let Some(JsonValue::Object(verif)) = display_obj.get("verification") {
                if let (Some(JsonValue::String(d)), Some(v)) = (verif.get("display"), verif.get("display_value")) {
                    let display_name_cstr = CString::new(d.clone())?;
                    let display_val_cstr = CString::new(v.to_display_string())?;
                    credman.add_field_to_entry_set(&cred_id_cstr, &display_name_cstr, Some(&display_val_cstr), set_id_cstr, doc_idx as i32);
                }
            }
        }
    }
    
    if let Some(text) = metadata_display_text {
        let mdt_cstr = CString::new(text)?;
        credman.add_metadata_display_text_to_entry_set(&cred_id_cstr, Some(&mdt_cstr), set_id_cstr, doc_idx as i32);
    }

    Ok(())
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let input = input.trim_end_matches('=');
    let mut alphabet = [255u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .iter()
        .enumerate()
    {
        alphabet[c as usize] = i as u8;
    }

    let mut output = Vec::new();
    let mut bits = 0u32;
    let mut bit_count = 0;

    for &c in input.as_bytes() {
        let val = alphabet[c as usize];
        if val == 255 {
            continue; 
        }
        bits = (bits << 6) | val as u32;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
        }
    }
    Ok(output)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::CStr;

    #[derive(Debug, Default)]
    pub struct FakeField {
        pub name: String,
        pub value: Option<String>,
    }

    #[derive(Debug, Default)]
    pub struct FakeEntry {
        pub cred_id: String,
        pub title: Option<String>,
        pub subtitle: Option<String>,
        pub disclaimer: Option<String>,
        pub warning: Option<String>,
        pub metadata: Option<String>,
        pub fields: Vec<FakeField>,
    }

    #[derive(Debug, Default)]
    pub struct FakeEntrySet {
        pub set_id: String,
        pub length: i32,
        pub entries: HashMap<i32, FakeEntry>,
    }

    pub struct FakeCredman {
        pub request_buffer: Vec<u8>,
        pub registered_data: Vec<u8>,
        pub entry_sets: HashMap<String, FakeEntrySet>,
    }

    impl FakeCredman {
        pub fn new(request_json: &str, registered_json: &str) -> Self {
            let mut registered_data = 4u32.to_le_bytes().to_vec();
            registered_data.extend_from_slice(registered_json.as_bytes());
            Self {
                request_buffer: request_json.as_bytes().to_vec(),
                registered_data,
                entry_sets: HashMap::new(),
            }
        }
    }

    impl CredmanApi for FakeCredman {
        fn get_request_buffer(&self) -> Vec<u8> {
            self.request_buffer.clone()
        }
        fn get_registered_data(&self) -> Vec<u8> {
            self.registered_data.clone()
        }
        fn add_string_id_entry(
            &mut self,
            _: &CStr,
            _: Option<&[u8]>,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: Option<&CStr>,
        ) {
        }
        fn add_entry_set(&mut self, set_id: &CStr, set_length: i32) {
            let id = set_id.to_str().unwrap().to_string();
            self.entry_sets.insert(
                id.clone(),
                FakeEntrySet {
                    set_id: id,
                    length: set_length,
                    entries: HashMap::new(),
                },
            );
        }
        fn add_entry_to_set(
            &mut self,
            cred_id: &CStr,
            _: Option<&[u8]>,
            title: Option<&CStr>,
            subtitle: Option<&CStr>,
            disclaimer: Option<&CStr>,
            warning: Option<&CStr>,
            metadata: Option<&CStr>,
            set_id: &CStr,
            set_index: i32,
        ) {
            let s_id = set_id.to_str().unwrap().to_string();
            let set = self.entry_sets.get_mut(&s_id).expect("Set not found");
            set.entries.insert(
                set_index,
                FakeEntry {
                    cred_id: cred_id.to_str().unwrap().to_string(),
                    title: title.map(|t| t.to_str().unwrap().to_string()),
                    subtitle: subtitle.map(|s| s.to_str().unwrap().to_string()),
                    disclaimer: disclaimer.map(|d| d.to_str().unwrap().to_string()),
                    warning: warning.map(|w| w.to_str().unwrap().to_string()),
                    metadata: metadata.map(|m| m.to_str().unwrap().to_string()),
                    fields: Vec::new(),
                },
            );
        }
        fn add_field_to_entry_set(
            &mut self,
            cred_id: &CStr,
            field_display_name: &CStr,
            field_display_value: Option<&CStr>,
            set_id: &CStr,
            set_index: i32,
        ) {
            let s_id = set_id.to_str().unwrap().to_string();
            let set = self.entry_sets.get_mut(&s_id).expect("Set not found");
            let entry = set.entries.get_mut(&set_index).expect("Entry not found");
            if entry.cred_id == cred_id.to_str().unwrap() {
                entry.fields.push(FakeField {
                    name: field_display_name.to_str().unwrap().to_string(),
                    value: field_display_value.map(|v| v.to_str().unwrap().to_string()),
                });
            }
        }
        fn add_payment_entry_to_set_v2(
            &mut self,
            _: &CStr,
            _: &CStr,
            _: &CStr,
            _: Option<&CStr>,
            _: Option<&[u8]>,
            _: Option<&CStr>,
            _: Option<&[u8]>,
            _: Option<&[u8]>,
            _: Option<&CStr>,
            _: Option<&CStr>,
            _: &CStr,
            _: i32,
        ) {
        }
        fn add_inline_issuance_entry(
            &mut self,
            _: &CStr,
            _: Option<&[u8]>,
            _: Option<&CStr>,
            _: Option<&CStr>,
        ) {
        }
        fn get_wasm_version(&self) -> u32 {
            6
        }
        fn add_metadata_display_text_to_entry_set(
            &mut self,
            _: &CStr,
            _: Option<&CStr>,
            _: &CStr,
            _: i32,
        ) {
        }
    }

    #[test]
    fn test_openid4vp_mso_mdoc_doctype_matching() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "q1",
                                    "format": "mso_mdoc",
                                    "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                                    "claims": [{"path": ["family_name"], "value": "Doe"}]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "mso_mdoc": {
                    "org.iso.18013.5.1.mDL": [
                        {
                            "id": "mdl_1",
                            "display": {
                                "verification": {
                                    "title": "MDL 1",
                                    "subtitle": "Driving License",
                                    "explainer": "We need your family name to identify you.",
                                    "warning": "Data expires in 30 days."
                                }
                            },
                            "paths": {
                                "family_name": {
                                    "display": {"verification": {"display": "Family Name", "display_value": "Doe"}},
                                    "value": "Doe"
                                }
                            }
                        }
                    ]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        let set = credman.entry_sets.get("req:0;null").expect("Set req:0;null not found");
        assert_eq!(set.length, 1);
        let entry = set.entries.get(&0).expect("Entry 0 not found");
        assert_eq!(entry.cred_id, "mdl_1");
        assert_eq!(entry.title.as_deref(), Some("MDL 1"));
        assert_eq!(entry.subtitle.as_deref(), Some("Driving License"));
        assert_eq!(entry.disclaimer.as_deref(), Some("We need your family name to identify you."));
        assert_eq!(entry.warning.as_deref(), Some("Data expires in 30 days."));
        assert!(entry.metadata.as_ref().unwrap().contains("\"dcql_cred_id\":\"q1\""));
        assert_eq!(entry.fields.len(), 1);
        assert_eq!(entry.fields[0].name, "Family Name");
        assert_eq!(entry.fields[0].value.as_deref(), Some("Doe"));
    }

    #[test]
    fn test_openid4vp_sdjwt_vct_matching() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "q1",
                                    "format": "dc+sd-jwt",
                                    "meta": {"vct_values": ["urn:example:vct"]},
                                    "claims": [{"path": ["name"], "value": "John Doe"}]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "urn:example:vct": [
                        {
                            "id": "sdjwt_1",
                            "display": {"verification": {"title": "SD-JWT 1"}},
                            "paths": {
                                "name": {
                                    "display": {"verification": {"display": "Name", "display_value": "John Doe"}},
                                    "value": "John Doe"
                                }
                            }
                        }
                    ]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        let set = credman.entry_sets.get("req:0;null").expect("Set req:0;null not found");
        assert_eq!(set.length, 1);
        let entry = set.entries.get(&0).expect("Entry 0 not found");
        assert_eq!(entry.cred_id, "sdjwt_1");
    }

    #[test]
    fn test_openid4vp_recursive_path_matching() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "q1",
                                    "format": "dc+sd-jwt",
                                    "meta": {"vct_values": ["urn:example:vct"]},
                                    "claims": [{"path": ["address", "locality"], "value": "London"}]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "urn:example:vct": [
                        {
                            "id": "c1",
                            "display": {"verification": {"title": "C1"}},
                            "paths": {
                                "address": {
                                    "locality": {
                                        "display": {"verification": {"display": "Locality", "display_value": "London"}},
                                        "value": "London"
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        let set = credman.entry_sets.get("req:0;null").expect("Set req:0;null not found");
        let entry = set.entries.get(&0).expect("Entry 0 not found");
        assert_eq!(entry.cred_id, "c1");
        assert_eq!(entry.fields[0].name, "Locality");
        assert_eq!(entry.fields[0].value.as_deref(), Some("London"));
    }

    #[test]
    fn test_openid4vp_multiple_matches() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "q1",
                                    "format": "dc+sd-jwt",
                                    "meta": {"vct_values": ["vct"]},
                                    "claims": [{"path": ["type"], "value": "ID"}]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "vct": [
                        {
                            "id": "c1",
                            "display": {"verification": {"title": "C1"}},
                            "paths": { "type": { "display": {"verification": {"display": "Type", "display_value": "ID"}}, "value": "ID" } }
                        },
                        {
                            "id": "c2",
                            "display": {"verification": {"title": "C2"}},
                            "paths": { "type": { "display": {"verification": {"display": "Type", "display_value": "ID"}}, "value": "ID" } }
                        }
                    ]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        let set = credman.entry_sets.get("req:0;null").expect("Set req:0;null not found");
        assert_eq!(set.length, 1);
        assert_eq!(set.entries.len(), 1); 
    }

    #[test]
    fn test_openid4vp_credential_sets() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["vct1"]}, "claims": [{"path": ["name"]}]},
                                {"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["vct2"]}, "claims": [{"path": ["age"]}]}
                            ],
                            "credential_sets": [
                                {
                                    "options": [
                                        ["q1"],
                                        ["q2"]
                                    ]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "vct1": [
                        {
                            "id": "c1",
                            "display": {"verification": {"title": "C1"}},
                            "paths": {
                                "name": {"display": {"verification": {"display": "Name", "display_value": "John"}}, "value": "John"}
                            }
                        }
                    ],
                    "vct2": [
                        {
                            "id": "c2",
                            "display": {"verification": {"title": "C2"}},
                            "paths": {
                                "age": {"display": {"verification": {"display": "Age", "display_value": "30"}}, "value": "30"}
                            }
                        }
                    ]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        assert!(credman.entry_sets.contains_key("req:0;set:0;option:0"));
        assert!(credman.entry_sets.contains_key("req:0;set:0;option:1"));
        
        let set0 = credman.entry_sets.get("req:0;set:0;option:0").unwrap();
        assert_eq!(set0.entries.get(&0).unwrap().cred_id, "c1");
        
        let set1 = credman.entry_sets.get("req:0;set:0;option:1").unwrap();
        assert_eq!(set1.entries.get(&0).unwrap().cred_id, "c2");
    }

    #[test]
    fn test_openid4vp_no_matches() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "q1",
                                    "format": "dc+sd-jwt",
                                    "meta": {"vct_values": ["vct"]},
                                    "claims": [{"path": ["type"], "value": "Passport"}]
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "vct": [
                        {
                            "id": "c1",
                            "display": {"verification": {"title": "C1"}},
                            "paths": { "type": { "display": {"verification": {"display": "Type", "display_value": "ID"}}, "value": "ID" } }
                        }
                    ]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        assert!(credman.entry_sets.is_empty());
    }

    #[test]
    fn test_openid4vp_credential_sets_complex() {
        let request = r#"{
            "requests": [
                {
                    "protocol": "openid4vp-v1-unsigned",
                    "data": {
                        "dcql_query": {
                            "credentials": [
                                {"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["v1"]}, "claims": [{"path": ["c1"]}]},
                                {"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["v2"]}, "claims": [{"path": ["c2"]}]},
                                {"id": "q3", "format": "dc+sd-jwt", "meta": {"vct_values": ["v3"]}, "claims": [{"path": ["c3"]}]}
                            ],
                            "credential_sets": [
                                {
                                    "options": [["q1"], ["q2"]],
                                    "required": true
                                },
                                {
                                    "options": [["q3"]],
                                    "required": false
                                }
                            ]
                        }
                    }
                }
            ]
        }"#;

        let store = r#"{
            "credentials": {
                "dc+sd-jwt": {
                    "v1": [{"id": "c1", "display": {"verification": {"title": "C1"}}, "paths": {"c1": {"display": {"verification": {"display": "D1", "display_value": "V1"}}, "value": "V1"}}}],
                    "v2": [{"id": "c2", "display": {"verification": {"title": "C2"}}, "paths": {"c2": {"display": {"verification": {"display": "D2", "display_value": "V2"}}, "value": "V2"}}}]
                }
            }
        }"#;

        let mut credman = FakeCredman::new(request, store);
        openid4vp_main(&mut credman).unwrap();

        // req:0;set:0;option:0 (q1 matched c1)
        assert!(credman.entry_sets.contains_key("req:0;set:0;option:0"));
        // req:0;set:0;option:1 (q2 matched c2)
        assert!(credman.entry_sets.contains_key("req:0;set:0;option:1"));
    }

    #[test]
    #[should_panic(expected = "Set not found")]
    fn test_fake_credman_panic_on_missing_set() {
        let mut credman = FakeCredman::new("{}", "{}");
        let set_id = CString::new("non_existent").unwrap();
        let cred_id = CString::new("c1").unwrap();
        credman.add_entry_to_set(&cred_id, None, None, None, None, None, None, &set_id, 0);
    }
}
