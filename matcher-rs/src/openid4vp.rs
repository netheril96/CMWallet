use nanoserde::DeJson;
use std::collections::HashMap;

pub const MSO_MDOC: &str = "mso_mdoc";
pub const DC_SD_JWT: &str = "dc+sd-jwt";

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct OpenId4VpRegistry {
    pub credentials: RegistryCredentials,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryCredentials {
    pub mso_mdoc: HashMap<String, Vec<CredentialEntry>>,
    #[nserde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: HashMap<String, Vec<CredentialEntry>>,
    pub issuance: IssuanceCredentials,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct IssuanceCredentials {
    pub mso_mdoc: Vec<InlineIssuanceEntry>,
    #[nserde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: Vec<InlineIssuanceEntry>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct CredentialEntry {
    pub id: String,
    pub display: DisplayProperties,
    pub paths: HashMap<String, HashMap<String, RegistryField>>, // 2-level sufficient for mdoc and most sd-jwt
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DisplayProperties {
    pub verification: Option<VerificationDisplay>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct VerificationDisplay {
    pub title: String,
    pub subtitle: Option<String>,
    pub explainer: Option<String>,
    pub warning: Option<String>,
    pub metadata_display_text: Option<String>,
    pub icon: Option<IconInfo>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct IconInfo {
    pub length: u32,
    pub start: u32,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryField {
    pub display: Option<ClaimDisplayProperties>,
    pub value: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct ClaimDisplayProperties {
    pub verification: Option<VerificationFieldDisplay>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct VerificationFieldDisplay {
    pub display: String,
    pub display_value: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct InlineIssuanceEntry {
    pub id: String,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub icon: Option<IconInfo>,
    pub supported: Vec<String>,
}

// --- DC Request Models ---

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DigitalCredentialRequest {
    pub requests: Option<Vec<OpenId4VpRequest>>,
    pub providers: Option<Vec<OpenId4VpRequest>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct OpenId4VpRequest {
    pub protocol: String,
    pub data: Option<OpenId4VpRequestData>,
    pub request: Option<String>, // Legacy spec
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct OpenId4VpRequestData {
    pub dcql_query: Option<DcqlQuery>,
    pub transaction_data: Option<Vec<String>>,
    pub offer: Option<Vec<IssuanceOffer>>, // Check if exists
    pub request: Option<String>, // Signed request JWT
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct IssuanceOffer {
    // Just to check existence
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredential>,
    pub credential_sets: Option<Vec<DcqlCredentialSet>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DcqlCredential {
    pub id: String,
    pub format: String,
    pub meta: Option<DcqlMeta>,
    pub claims: Option<Vec<DcqlClaim>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DcqlMeta {
    pub doctype_value: Option<String>,
    pub vct_values: Option<Vec<String>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DcqlClaim {
    pub id: Option<String>,
    pub path: Vec<String>,
    pub values: Option<Vec<String>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DcqlCredentialSet {
    pub required: Option<bool>,
    pub options: Vec<Vec<String>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct TransactionData {
    #[nserde(rename = "type")]
    pub transaction_type: String,
    pub credential_ids: Option<Vec<String>>,
    pub payload: Option<TransactionPayload>,
    pub payee_name: Option<String>,
    pub payment_amount: Option<String>,
    pub payment_currency: Option<String>,
    pub merchant_name: Option<String>,
    pub amount: Option<String>,
    pub additional_info: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct TransactionPayload {
    pub payee: Option<TransactionPayee>,
    pub amount_display: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct TransactionPayee {
    pub name: String,
}
