use nanoserde::DeJson;
use std::collections::HashMap;

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct ClaimQuery {
    pub id: String,
    pub path: Vec<String>,
    pub values: Vec<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct MetaQuery {
    pub doctype_value: String,
    pub vct_values: Vec<String>,
    pub credential_authorization_jwt: String,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct CredentialQuery {
    pub id: String,
    pub format: String,
    pub meta: MetaQuery,
    pub claims: Vec<ClaimQuery>,
    pub claim_sets: Vec<Vec<String>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct CredentialSetQuery {
    pub required: bool,
    pub options: Vec<Vec<String>>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct DcqQuery {
    pub credentials: Vec<CredentialQuery>,
    pub credential_sets: Vec<CredentialSetQuery>,
}

// Registry Data Structures
#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryIcon {
    pub start: usize,
    pub length: usize,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct VerificationEntryDisplay {
    pub title: String,
    pub subtitle: String,
    pub explainer: String,
    pub warning: String,
    pub metadata_display_text: String,
    pub icon: RegistryIcon,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryEntryDisplay {
    pub verification: VerificationEntryDisplay,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct VerificationFieldDisplay {
    #[nserde(rename = "display")]
    pub display_name: String,
    pub display_value: String,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryFieldDisplay {
    pub verification: VerificationFieldDisplay,
}

#[derive(Debug, Default, Clone)]
pub struct RegistryPathNode {
    pub value: String,
    pub display: RegistryFieldDisplay,
    pub children: HashMap<String, RegistryPathNode>,
}

impl DeJson for RegistryPathNode {
    fn de_json(
        state: &mut nanoserde::DeJsonState,
        input: &mut std::str::Chars,
    ) -> Result<Self, nanoserde::DeJsonErr> {
        let mut node = RegistryPathNode::default();
        if state.tok != nanoserde::DeJsonTok::CurlyOpen {
            return Err(state.err_parse("Expected { for RegistryPathNode"));
        }
        state.next_tok(input)?;
        while state.tok != nanoserde::DeJsonTok::CurlyClose {
            if let nanoserde::DeJsonTok::Str = &state.tok {
                let key = state.strbuf.clone();
                state.next_tok(input)?;
                if state.tok != nanoserde::DeJsonTok::Colon {
                    return Err(state.err_parse("Expected : after key"));
                }
                state.next_tok(input)?;
                match key.as_str() {
                    "value" => {
                        node.value = DeJson::de_json(state, input)?;
                    }
                    "display" => {
                        node.display = DeJson::de_json(state, input)?;
                    }
                    _ => {
                        node.children.insert(key, DeJson::de_json(state, input)?);
                    }
                }
                if state.tok == nanoserde::DeJsonTok::Comma {
                    state.next_tok(input)?;
                }
            } else {
                return Err(state.err_parse("Expected string key in RegistryPathNode"));
            }
        }
        state.next_tok(input)?;
        Ok(node)
    }
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryCredential {
    pub id: String,
    pub display: RegistryEntryDisplay,
    pub paths: RegistryPathNode,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryIssuanceEntry {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub icon: RegistryIcon,
    pub supported: Vec<String>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryFormatCollection {
    pub mso_mdoc: HashMap<String, Vec<RegistryCredential>>,
    #[nserde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: HashMap<String, Vec<RegistryCredential>>,
    pub issuance: RegistryIssuanceCollection,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct RegistryIssuanceCollection {
    pub mso_mdoc: Vec<RegistryIssuanceEntry>,
    #[nserde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: Vec<RegistryIssuanceEntry>,
}

#[derive(DeJson, Debug, Default, Clone)]
#[nserde(default)]
pub struct CredentialStore {
    pub credentials: RegistryFormatCollection,
}
