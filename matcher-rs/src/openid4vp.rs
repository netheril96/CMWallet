use crate::dcql::DcqQuery;
use base64::Engine;
use log::{debug, error};
use nanoserde::DeJson;

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct OpenId4VpRequestData {
    pub dcql_query: DcqQuery,
    pub transaction_data: Vec<String>, // Base64URL encoded transaction data
    pub offer: String,                 // Presence indicates issuance offer
    #[nserde(rename = "request")]
    pub signed_request: String, // Used in signed flow
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct OpenId4VpRequest {
    pub protocol: String,
    pub data: OpenId4VpRequestData,
    #[nserde(rename = "request")]
    pub legacy_request_data: String, // Used in legacy spec where data is a string
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DigitalPresentationRequest {
    pub requests: Vec<OpenId4VpRequest>,
    pub providers: Vec<OpenId4VpRequest>, // Legacy name
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct Payee {
    pub name: String,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct PaymentPayload {
    pub payee: Payee,
    pub amount_display: String,
    pub amount: f64,
    pub currency: String,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct TransactionData {
    #[nserde(rename = "type")]
    pub transaction_type: String,
    pub payload: PaymentPayload,
    pub credential_ids: Vec<String>,
    pub merchant_name: String, // for legacy/other types
    pub amount: String,        // for legacy/other types
    pub additional_info: String,
    // For payment_details type
    pub payee_name: String,
    pub payment_amount: String,
    pub payment_currency: String,
}

pub fn extract_signed_request_payload(
    signed_request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = signed_request.split('.').collect();
    if parts.len() < 2 {
        error!("Invalid JWT format, expected at least 2 parts, got {}", parts.len());
        return Err("Invalid JWT: missing payload part".into());
    }
    let payload_b64 = parts[1];
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)?;
    let payload = String::from_utf8(decoded)?;
    debug!("Successfully extracted signed request payload: size={}", payload.len());
    Ok(payload)
}

pub fn decode_transaction_data(
    encoded: &str,
) -> Result<TransactionData, Box<dyn std::error::Error>> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;
    let json_str = std::str::from_utf8(&decoded)?;
    debug!("Successfully decoded transaction data JSON: size={}", json_str.len());
    Ok(DeJson::deserialize_json(json_str)?)
}
