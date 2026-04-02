use crate::json_value::{DeterministicMap, DeterministicSet, JsonValue};
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
    pub doctype_value: String,
    pub vct_values: Vec<String>,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct DcqlClaim {
    pub id: String,
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
    pub subtitle: String,
    pub explainer: String,
    pub warning: String,
    pub metadata_display_text: String,
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
    pub title: String,
    pub subtitle: String,
    pub icon: Option<RegistryIcon>,
    pub supported: DeterministicSet<String>,
}

use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct MatchedClaim<'a> {
    pub display: &'a JsonValue, // RegistryClaimDisplay
    pub path: &'a [String],
}

#[derive(Debug, Clone)]
pub struct MatchedCredential<'a> {
    pub id: &'a str,
    pub display: &'a RegistryDisplay,
    pub matched_claim_names: Vec<&'a JsonValue>, // RegistryClaimDisplay
    pub matched_claim_metadata: Vec<&'a [String]>,
}

#[derive(Debug, Clone)]
pub struct MatchCredentialResult<'a> {
    pub matched_creds: Vec<MatchedCredential<'a>>,
    pub inline_issuance: Option<&'a RegistryIssuanceEntry>,
}

#[derive(Debug, Clone)]
pub struct DcqlMatchResult<'a> {
    pub matched_credential_sets: Vec<Vec<MatchedCredentialSetInfo<'a>>>,
    pub matched_credentials: DeterministicMap<&'a str, DcqlMatchedCredentialEntry<'a>>,
    pub inline_issuance: Option<&'a RegistryIssuanceEntry>,
}

#[derive(Debug, Clone)]
pub struct MatchedCredentialSetInfo<'a> {
    pub set_id: Cow<'a, str>,
    pub option_id: Cow<'a, str>,
    pub matched_credential_ids: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct DcqlMatchedCredentialEntry<'a> {
    pub id: &'a str,
    pub matched: Vec<MatchedCredential<'a>>,
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
    pub request: String,
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
    pub request: String, // Legacy
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct TransactionData {
    pub credential_ids: Vec<String>,
    #[nserde(rename = "type")]
    pub transaction_type: String,
    pub payload: Option<TransactionPayload>,
    pub payee_name: String,
    pub payment_amount: String,
    pub payment_currency: String,
    pub merchant_name: String,
    pub amount: String,
    pub additional_info: String,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct TransactionPayload {
    pub payee: Option<Payee>,
    pub amount: Option<f64>,
    pub amount_display: String,
    pub currency: String,
}

#[derive(DeJson, Debug, Clone, Default)]
#[nserde(default)]
pub struct Payee {
    pub name: String,
}

/// This provides information to the provider app which credential/set is selected by the user.
#[derive(Debug, Clone, Default)]
pub struct SelectionMetadata<'a> {
    pub claims: &'a [&'a [String]],
    pub dc_request_index: usize,
    pub dcql_cred_id: &'a str,
    pub dcql_credential_set_index: &'a str,
    pub dcql_option_index: &'a str,
}

impl<'a> SerJson for SelectionMetadata<'a> {
    fn ser_json(&self, d: usize, s: &mut nanoserde::SerJsonState) {
        s.out.push('{');

        "claims".ser_json(d, s);
        s.out.push(':');
        s.out.push('[');
        for (i, inner) in self.claims.iter().enumerate() {
            if i > 0 {
                s.out.push(',');
            }
            s.out.push('[');
            for (j, item) in inner.iter().enumerate() {
                if j > 0 {
                    s.out.push(',');
                }
                item.ser_json(d, s);
            }
            s.out.push(']');
        }
        s.out.push(']');

        s.out.push(',');
        "dc_request_index".ser_json(d, s);
        s.out.push(':');
        self.dc_request_index.ser_json(d, s);

        if !self.dcql_cred_id.is_empty() {
            s.out.push(',');
            "dcql_cred_id".ser_json(d, s);
            s.out.push(':');
            self.dcql_cred_id.ser_json(d, s);
        }

        if !self.dcql_credential_set_index.is_empty() {
            s.out.push(',');
            "dcql_credential_set_index".ser_json(d, s);
            s.out.push(':');
            self.dcql_credential_set_index.ser_json(d, s);
        }

        if !self.dcql_option_index.is_empty() {
            s.out.push(',');
            "dcql_option_index".ser_json(d, s);
            s.out.push(':');
            self.dcql_option_index.ser_json(d, s);
        }

        s.out.push('}');
    }
}
