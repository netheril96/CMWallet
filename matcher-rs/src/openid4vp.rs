use nanoserde::{DeJson, DeJsonErr, DeJsonState, DeJsonTok};
use crate::dcql::{DcqlQuery, SimpleJson};

#[derive(DeJson, Debug, Default, Clone)]
pub struct OpenId4VpRequestContainer {
    pub requests: Option<Vec<OpenId4VpRequest>>,
    pub providers: Option<Vec<OpenId4VpRequest>>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct OpenId4VpRequest {
    pub protocol: String,
    pub data: OpenId4VpRequestDataEnum,
}

#[derive(Debug, Clone)]
pub enum OpenId4VpRequestDataEnum {
    Object(OpenId4VpRequestData),
    String(String),
}

impl Default for OpenId4VpRequestDataEnum {
    fn default() -> Self {
        Self::Object(Default::default())
    }
}

impl DeJson for OpenId4VpRequestDataEnum {
    fn de_json(state: &mut DeJsonState, i: &mut core::str::Chars) -> Result<Self, DeJsonErr> {
        match state.tok {
            DeJsonTok::Str => {
                let s = state.as_string()?;
                state.next_tok(i)?;
                Ok(Self::String(s))
            }
            DeJsonTok::CurlyOpen => {
                let d = DeJson::de_json(state, i)?;
                Ok(Self::Object(d))
            }
            _ => Err(state.err_token("string or object")),
        }
    }
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct OpenId4VpRequestData {
    pub dcql_query: Option<DcqlQuery>,
    pub transaction_data: Option<Vec<String>>,
    pub offer: Option<SimpleJson>,
    pub request: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct TransactionData {
    pub credential_ids: Option<Vec<String>>,
    #[nserde(rename = "type")]
    pub type_field: String,
    pub payload: Option<TransactionPayload>,
    pub payee_name: Option<String>,
    pub payment_amount: Option<String>,
    pub payment_currency: Option<String>,
    pub merchant_name: Option<String>,
    pub amount: Option<String>,
    pub additional_info: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct TransactionPayload {
    pub payee: Option<Payee>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
pub struct Payee {
    pub name: String,
}

pub fn decode_b64url(input: &str) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut value = 0u32;
    let mut bits = 0i32;

    for &b in input.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            b'=' | b' ' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        value = (value << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buffer.push((value >> bits) as u8);
            value &= (1 << bits) - 1;
        }
    }
    Some(buffer)
}
