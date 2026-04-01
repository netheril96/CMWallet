use crate::json_value::{DeterministicMap, JsonValue};
use nanoserde::{DeJson, SerJson};

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredential>,
    pub credential_sets: Vec<DcqlCredentialSet>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlCredential {
    pub id: String,
    pub format: String,
    pub meta: Option<DcqlMeta>,
    pub claims: Vec<DcqlClaim>,
    pub claim_sets: Vec<Vec<String>>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlMeta {
    pub doctype_value: Option<String>,
    pub vct_values: Vec<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlClaim {
    pub id: Option<String>,
    pub path: Vec<String>,
    pub values: Vec<JsonValue>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlCredentialSet {
    pub options: Vec<Vec<String>>,
    pub required: Option<bool>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct Registry {
    pub credentials: RegistryCredentials,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct RegistryCredentials {
    #[nserde(rename = "mso_mdoc")]
    pub mso_mdoc: Option<DeterministicMap<String, Vec<RegistryCredential>>>,
    #[nserde(rename = "dc+sd-jwt")]
    pub sd_jwt: Option<DeterministicMap<String, Vec<RegistryCredential>>>,
    pub issuance: Option<RegistryIssuance>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct RegistryCredential {
    pub id: String,
    pub display: RegistryDisplay,
    pub paths: DeterministicMap<String, JsonValue>, // Recursive structure
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
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

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct RegistryIcon {
    pub start: usize,
    pub length: usize,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct RegistryIssuance {
    #[nserde(rename = "mso_mdoc")]
    pub mso_mdoc: Vec<RegistryIssuanceEntry>,
    #[nserde(rename = "dc+sd-jwt")]
    pub sd_jwt: Vec<RegistryIssuanceEntry>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct RegistryIssuanceEntry {
    pub id: String,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub icon: Option<RegistryIcon>,
    pub supported: Vec<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct MatchedClaim {
    pub display: JsonValue, // RegistryClaimDisplay
    pub path: Vec<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct MatchedCredential {
    pub id: String,
    pub display: RegistryDisplay,
    pub matched_claim_names: Vec<JsonValue>, // RegistryClaimDisplay
    pub matched_claim_metadata: Vec<Vec<String>>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct MatchCredentialResult {
    pub matched_creds: Vec<MatchedCredential>,
    pub inline_issuance: Option<RegistryIssuanceEntry>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlMatchResult {
    pub matched_credential_sets: Vec<Vec<MatchedCredentialSetInfo>>,
    pub matched_credentials: DeterministicMap<String, DcqlMatchedCredentialEntry>,
    pub inline_issuance: Option<RegistryIssuanceEntry>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct MatchedCredentialSetInfo {
    pub set_id: String,
    pub option_id: String,
    pub matched_credential_ids: Vec<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlMatchedCredentialEntry {
    pub id: String,
    pub matched: Vec<MatchedCredential>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct OpenId4VpRequest {
    pub requests: Vec<ProtocolRequest>,
    pub providers: Vec<ProtocolRequest>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct OpenId4VpData {
    pub dcql_query: Option<DcqlQuery>,
    pub offer: Option<JsonValue>,
    pub transaction_data: Vec<String>,
    pub request: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ProtocolRequestData {
    String(String),
    Object(OpenId4VpData),
}

impl DeJson for ProtocolRequestData {
    fn de_json(
        state: &mut nanoserde::DeJsonState,
        input: &mut std::str::Chars,
    ) -> Result<Self, nanoserde::DeJsonErr> {
        match state.tok {
            nanoserde::DeJsonTok::Str => {
                let s = state.strbuf.clone();
                state.next_tok(input)?;
                Ok(ProtocolRequestData::String(s))
            }
            nanoserde::DeJsonTok::CurlyOpen => {
                let data = DeJson::de_json(state, input)?;
                Ok(ProtocolRequestData::Object(data))
            }
            _ => Err(state.err_exp("String or Object")),
        }
    }
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct ProtocolRequest {
    pub protocol: String,
    pub data: Option<ProtocolRequestData>,
    pub request: Option<String>, // Legacy
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct TransactionData {
    pub credential_ids: Vec<String>,
    #[nserde(rename = "type")]
    pub transaction_type: Option<String>,
    pub payload: Option<TransactionPayload>,
    pub payee_name: Option<String>,
    pub payment_amount: Option<String>,
    pub payment_currency: Option<String>,
    pub merchant_name: Option<String>,
    pub amount: Option<String>,
    pub additional_info: Option<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct TransactionPayload {
    pub payee: Option<Payee>,
    pub amount: Option<f64>,
    pub amount_display: Option<String>,
    pub currency: Option<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct Payee {
    pub name: Option<String>,
}

#[derive(DeJson, SerJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct Metadata {
    pub claims: Vec<Vec<String>>,
    pub dc_request_index: usize,
    pub dcql_cred_id: String,
    pub dcql_credential_set_index: Option<String>,
    pub dcql_option_index: Option<String>,
}
