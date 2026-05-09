use crate::{
    credman::CredmanApi,
    issuance_matcher::IssuanceMatcherData,
    openid4vci::{DigitalCredentialCreationRequest, RegularizedOpenId4VciRequestData},
};

use nanoserde::DeJson;

const ALLOWED_PROTOCOLS: [&str; 4] = [
    "openid4vci-1.0",
    "openid4vci1.0",
    "openid4vci-1.1",
    "openid4vci1.1",
];

pub fn issuance_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Starting issuance matching process");
    let matcher_data_buffer = credman.get_registered_data();
    log::debug!(
        "Retrieved matcher data buffer, size: {}",
        matcher_data_buffer.len()
    );

    let json_start = u32::from_le_bytes(matcher_data_buffer[..size_of::<u32>()].try_into()?);
    let matcher_data_str = std::str::from_utf8(&matcher_data_buffer[json_start.try_into()?..])?;
    let matcher_data: IssuanceMatcherData = match DeJson::deserialize_json(matcher_data_str) {
        Ok(data) => data,
        Err(e) => {
            log::error!(
                "Failed to deserialize matcher data: {:?}. JSON: {}",
                e,
                matcher_data_str
            );
            return Err(e.into());
        }
    };
    log::debug!("Parsed matcher data for entry: {}", matcher_data.entry_id);

    let request_buffer = credman.get_request_buffer();
    let request_str = std::str::from_utf8(&request_buffer)?;
    let request: DigitalCredentialCreationRequest = match DeJson::deserialize_json(request_str) {
        Ok(req) => req,
        Err(e) => {
            log::error!(
                "Failed to deserialize request: {:?}. JSON: {}",
                e,
                request_str
            );
            return Err(e.into());
        }
    };
    log::debug!(
        "Parsed request with {} sub-requests",
        request.requests.len()
    );

    for (i, r) in request.requests.iter().enumerate() {
        log::trace!("Checking request {}: protocol={}", i, r.protocol);
        if !ALLOWED_PROTOCOLS.iter().any(|s| r.protocol == *s) {
            log::warn!("Unsupported protocol: {}", r.protocol);
            continue;
        }

        let regularized = RegularizedOpenId4VciRequestData::from(&r.data);
        if !matcher_data.filter.matches(&regularized) {
            continue;
        }

        log::info!("Match found for request {} with protocol {}", i, r.protocol);
        let icon = &matcher_data_buffer[matcher_data.icon.0..matcher_data.icon.1];

        log::debug!("Adding string ID entry: {}", matcher_data.entry_id);
        credman.add_string_id_entry(
            &matcher_data.entry_id,
            icon,
            &matcher_data.title,
            &matcher_data.subtitle,
            "",
            "",
        );
        // Assuming we only need to add one entry if any request matches
        break;
    }

    log::info!("Issuance matching process completed");
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test_utils::*;

    fn make_fake_credman(request_json: &'static str, registered_json: &'static str, icon: Vec<u8>) -> FakeCredman {
        let mut credman = FakeCredman::new();
        credman.request_json = request_json.to_string();
        
        let mut result = Vec::with_capacity(4 + icon.len() + registered_json.len());
        result.extend_from_slice(&u32::to_le_bytes(4 + icon.len() as u32));
        result.extend_from_slice(&icon);
        result.extend_from_slice(registered_json.as_bytes());
        credman.credentials_blob = result;
        
        credman
    }

    #[test]
    fn match_case1() {
        let mut credman = make_fake_credman(
            r#"
{
  "requests": [
    {
      "protocol": "openid4vci-1.1",
      "data": {
        "credential_issuer": "https://issuer.my",
        "credential_configuration_ids": [
          "US_SOCIAL_SECURITY_NUMBER"
        ],
        "grants": {
          "authorization_code": {}
        },
        "credential_issuer_metadata": {
          "nonce_endpoint": "https://nonce.my"
        }
      }
    }
  ]
}"#,
            r#"
      {
        "entry_id": "C",
        "title": "TTTT",
        "subtitle": "SSSSS",
        "icon": [0, 0],
        "filter": {
          "And": {
            "filters": [{
              "AllowsConfigurationIds": {
                "configuration_ids": ["US_SOCIAL_SECURITY_NUMBER", "EU_AGE"]
              }
            }, {
              "AllowsIssuers": {
                "issuers": ["ccb", "https://issuer.my"]
              }
            }]
          }
        }
      }"#,
            Vec::new(),
        );

        issuance_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 1);
        let entry = &credman.added_entries[0];
        assert_eq!(entry.entry_id, "C");
        assert_eq!(entry.title, "TTTT");
        assert_eq!(entry.subtitle, "SSSSS");
        assert!(entry.icon.is_empty());
    }

    #[test]
    fn invalid_json() {
        let mut credman = make_fake_credman(
            r#"
{
  "requests": [
    {
      "protocol": "openid4vci-1.1",
      "data": {
        "credential_issuer": "https://issuer.my",
        "credential_configuration_ids": [
          "US_SOCIAL_SECURITY_NUMBER"
        ],
        "grants": {
          "authorization_code": {}
        },
        "credential_issuer_metadata": {
          "nonce_endpoint": "https://nonce.my"
        }
      }
    }
  ]
"#,
            r#"
      {
        "entry_id": "C",
        "title": "TTTT",
        "subtitle": "SSSSS",
        "icon": [0, 0],
        "filter": {"Unit": {}}"#,
            Vec::new(),
        );

        let errmsg = format!("{:?}", issuance_main(&mut credman).unwrap_err());
        assert!(
            errmsg.contains("Unexpected token Eof") || errmsg.contains("Unexpected end of file")
        );
    }

    #[test]
    fn nomatch_case1() {
        let mut credman = make_fake_credman(
            r#"
{
  "requests": [
    {
      "protocol": "openid4vci-1.1",
      "data": {
        "credential_issuer": "https://issuer.my",
        "credential_configuration_ids": [
          "US_SOCIAL_SECURITY_NUMBER"
        ],
        "grants": {
          "authorization_code": {}
        },
        "credential_issuer_metadata": {
          "nonce_endpoint": "https://nonce.my"
        }
      }
    }
  ]
}"#,
            r#"
{
  "entry_id": "C",
  "title": "TTTT",
  "subtitle": "SSSSS",
  "icon": [
    0,
    0
  ],
  "filter": {
    "And": {
      "filters": [
        {
          "AllowsConfigurationIds": {
            "configuration_ids": [
              "US_SOCIAL_SECURITY_NUMBER",
              "EU_AGE"
            ]
          }
        },
        {
          "AllowsIssuers": {
            "issuers": [
              "ccb",
              "https://issuer.my"
            ]
          }
        },
        {
          "Not": {
            "filter": {
              "SupportsNonceEndpoint": {
              }
            }
          }
        }
      ]
    }
  }
}"#,
            Vec::new(),
        );

        issuance_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 0);
    }

    #[test]
    fn match_mdoc_doctype() {
        let mut credman = make_fake_credman(
            r#"
{
  "requests": [
    {
      "protocol": "openid4vci-1.1",
      "data": {
        "credential_issuer": "https://issuer.my",
        "credential_configuration_ids": [
          "FICTITIOUS_STATE_MDL"
        ],
        "grants": {
          "authorization_code": {}
        },
        "credential_issuer_metadata": {
          "nonce_endpoint": "https://nonce.my",
          "credential_configurations_supported": {
            "FICTITIOUS_STATE_MDL": {
              "format": "mso_mdoc",
              "doctype": "org.iso.18013.5.1.mDL"
            }
          }
        }
      }
    }
  ]
}"#,
            r#"
{
  "entry_id": "C",
  "title": "TTTT",
  "subtitle": "SSSSS",
  "icon": [
    0,
    0
  ],
  "filter": {
    "Or": {
      "filters": [
        {
          "AllowsConfigurationIds": {
            "configuration_ids": [
              "US_SOCIAL_SECURITY_NUMBER",
              "EU_AGE"
            ]
          }
        },
        {
          "AllowsIssuers": {
            "issuers": [
              "ccb"
            ]
          }
        },
        {
          "SupportsMdocDoctype": {
            "doctypes": [
              "org.iso.18013.5.1.mDL"
            ]
          }
        }
      ]
    }
  }
}"#,
            Vec::new(),
        );

        issuance_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 1);
    }
}
