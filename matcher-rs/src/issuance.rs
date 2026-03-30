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
    let matcher_data_buffer = credman.get_registered_data();
    let json_start = u32::from_le_bytes(matcher_data_buffer[..size_of::<u32>()].try_into()?);
    let matcher_data: IssuanceMatcherData = DeJson::deserialize_json(std::str::from_utf8(
        &matcher_data_buffer[json_start.try_into()?..],
    )?)?;
    let request: DigitalCredentialCreationRequest =
        DeJson::deserialize_json(std::str::from_utf8(&credman.get_request_buffer())?)?;
    if request.requests.iter().any(|r| {
        ALLOWED_PROTOCOLS.iter().any(|s| r.protocol == *s)
            && matcher_data
                .filter
                .matches(&RegularizedOpenId4VciRequestData::from(&r.data))
    }) {
        let icon = &matcher_data_buffer[matcher_data.icon.0..matcher_data.icon.1];
        credman.add_string_id_entry(
            &matcher_data.entry_id,
            if icon.is_empty() { None } else { Some(icon) },
            matcher_data.title.as_deref(),
            matcher_data.subtitle.as_deref(),
            None,
            None,
        );
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    struct AddedEntry {
        entry_id: String,
        icon: Option<Vec<u8>>,
        title: Option<String>,
        subtitle: Option<String>,
        disclaimer: Option<String>,
        warning: Option<String>,
    }

    struct FakeCredman {
        request_json: &'static str,
        registered_json: &'static str,
        icon: Vec<u8>,
        added_entries: Vec<AddedEntry>,
    }

    impl CredmanApi for FakeCredman {
        fn get_request_buffer(&self) -> Vec<u8> {
            self.request_json.as_bytes().into()
        }

        fn get_registered_data(&self) -> Vec<u8> {
            let mut result = Vec::with_capacity(4 + self.icon.len() + self.registered_json.len());
            result.extend_from_slice(&u32::to_le_bytes(4 + self.icon.len() as u32));
            result.extend_from_slice(&self.icon);
            result.extend_from_slice(self.registered_json.as_bytes());
            result
        }

        fn add_string_id_entry(
            &mut self,
            entry_id: &str,
            icon: Option<&[u8]>,
            title: Option<&str>,
            subtitle: Option<&str>,
            disclaimer: Option<&str>,
            warning: Option<&str>,
        ) {
            self.added_entries.push(AddedEntry {
                entry_id: entry_id.to_string(),
                icon: icon.map(|i| i.to_vec()),
                title: title.map(|c| c.to_string()),
                subtitle: subtitle.map(|c| c.to_string()),
                disclaimer: disclaimer.map(|c| c.to_string()),
                warning: warning.map(|c| c.to_string()),
            });
        }

        fn add_entry_set(&mut self, _set_id: &str, _set_length: i32) {}

        fn add_entry_to_set(
            &mut self,
            _cred_id: &str,
            _icon: Option<&[u8]>,
            _title: &str,
            _subtitle: &str,
            _disclaimer: &str,
            _warning: Option<&str>,
            _metadata: &str,
            _set_id: &str,
            _set_index: i32,
        ) {
        }

        fn add_field_to_entry_set(
            &mut self,
            _cred_id: &str,
            _field_display_name: &str,
            _field_display_value: Option<&str>,
            _set_id: &str,
            _set_index: i32,
        ) {
        }

        fn add_payment_entry_to_set_v2(
            &mut self,
            _cred_id: &str,
            _merchant_name: &str,
            _payment_method_name: &str,
            _payment_method_subtitle: &str,
            _payment_method_icon: Option<&[u8]>,
            _transaction_amount: &str,
            _bank_icon: Option<&[u8]>,
            _payment_provider_icon: Option<&[u8]>,
            _additional_info: &str,
            _metadata: &str,
            _set_id: &str,
            _set_index: i32,
        ) {
        }

        fn add_inline_issuance_entry(
            &mut self,
            _cred_id: &str,
            _icon: Option<&[u8]>,
            _title: &str,
            _subtitle: &str,
        ) {
        }

        fn get_wasm_version(&self) -> u32 {
            0
        }

        fn set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(
            &mut self,
            _cred_id: &str,
            _secondary_disclaimer: Option<&str>,
            _url_display_text: Option<&str>,
            _url_value: Option<&str>,
            _set_id: &str,
            _set_index: i32,
        ) {
        }

        fn add_metadata_display_text_to_entry_set(
            &mut self,
            _cred_id: &str,
            _metadata_display_text: &str,
            _set_id: &str,
            _set_index: i32,
        ) {
        }
    }

    #[test]
    fn match_case1() {
        let mut credman = FakeCredman {
            request_json: r#"
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
            registered_json: r#"
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
            icon: Vec::new(),
            added_entries: Vec::new(),
        };

        issuance_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 1);
        let entry = &credman.added_entries[0];
        assert_eq!(entry.entry_id, "C");
        assert_eq!(entry.title.as_ref().unwrap(), "TTTT");
        assert_eq!(entry.subtitle.as_ref().unwrap(), "SSSSS");
        assert!(entry.icon.is_none());
    }

    #[test]
    fn invalid_json() {
        let mut credman = FakeCredman {
            request_json: r#"
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
            registered_json: r#"
      {
        "entry_id": "C",
        "title": "TTTT",
        "subtitle": "SSSSS",
        "icon": [0, 0],
        "filter": {"Unit": {}}"#,
            icon: Vec::new(),
            added_entries: Vec::new(),
        };

        let errmsg = format!("{:?}", issuance_main(&mut credman).unwrap_err());
        assert!(
            errmsg.contains("Unexpected token Eof") || errmsg.contains("Unexpected end of file")
        );
    }

    #[test]
    fn nomatch_case1() {
        let mut credman = FakeCredman {
            request_json: r#"
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
            registered_json: r#"
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
            icon: Vec::new(),
            added_entries: Vec::new(),
        };

        issuance_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 0);
    }

    #[test]
    fn match_mdoc_doctype() {
        let mut credman = FakeCredman {
            request_json: r#"
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
            registered_json: r#"
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
            icon: Vec::new(),
            added_entries: Vec::new(),
        };

        issuance_main(&mut credman).unwrap();

        assert_eq!(credman.added_entries.len(), 1);
    }
}
