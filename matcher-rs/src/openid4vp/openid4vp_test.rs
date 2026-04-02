use super::*;
use nanoserde::{DeJson, SerJson};

#[derive(SerJson, DeJson, PartialEq, Debug, Clone, Default)]
enum EntryType {
    #[default]
    Verification,
    InlineIssuance,
    Payment,
    UserInfo,
    Export,
}

#[derive(SerJson, DeJson, PartialEq, Debug, Clone, Default)]
struct FakeEntry {
    #[nserde(rename = "credId")]
    cred_id: String,
    #[nserde(rename = "type")]
    entry_type: EntryType,
    #[nserde(default)]
    title: String,
    #[nserde(default)]
    subtitle: String,
    #[nserde(default)]
    disclaimer: String,
    #[nserde(default)]
    warning: String,
    #[nserde(default)]
    metadata_display_text: String,
    #[nserde(default)]
    fields: Vec<(String, String)>,
    #[nserde(default)]
    merchant_name: String,
    #[nserde(default)]
    transaction_amount: String,
    #[nserde(default)]
    additional_info: String,
}

#[derive(SerJson, DeJson, PartialEq, Debug, Clone)]
struct FakeEntrySet {
    #[nserde(rename = "setId")]
    set_id: String,
    #[nserde(rename = "setLength")]
    set_length: i32,
    #[nserde(default)]
    entries: DeterministicMap<String, DeterministicMap<String, FakeEntry>>,
}

#[derive(SerJson, DeJson, PartialEq, Debug)]
struct FakeCredmanResult {
    #[nserde(rename = "entrySets")]
    entry_sets: DeterministicMap<String, FakeEntrySet>,
    #[nserde(rename = "standaloneEntries")]
    standalone_entries: Vec<FakeEntry>,
}

struct FakeCredman {
    entry_sets: DeterministicMap<String, FakeEntrySet>,
    standalone_entries: Vec<FakeEntry>,
    wasm_version: u32,
    request_json: String,
    credentials_blob: Vec<u8>,
}

impl FakeCredman {
    fn new() -> Self {
        Self {
            entry_sets: DeterministicMap::new(),
            standalone_entries: Vec::new(),
            wasm_version: 9999,
            request_json: String::new(),
            credentials_blob: Vec::new(),
        }
    }
}

impl CredmanApi for FakeCredman {
    fn get_request_buffer(&self) -> Vec<u8> {
        self.request_json.as_bytes().to_vec()
    }
    fn get_registered_data(&self) -> Vec<u8> {
        self.credentials_blob.clone()
    }
    fn get_wasm_version(&self) -> u32 {
        self.wasm_version
    }
    fn add_string_id_entry(
        &mut self,
        _id: &str,
        _icon: &[u8],
        _title: &str,
        _subtitle: &str,
        _disclaimer: &str,
        _warning: &str,
    ) {
    }
    fn add_entry_set(&mut self, set_id: &str, set_length: i32) {
        let s_id = set_id.to_string();
        self.entry_sets.insert(
            s_id.clone(),
            FakeEntrySet {
                set_id: s_id,
                set_length,
                entries: DeterministicMap::new(),
            },
        );
    }
    fn add_entry_to_set(
        &mut self,
        cred_id: &str,
        _icon: &[u8],
        title: &str,
        subtitle: &str,
        disclaimer: &str,
        warning: &str,
        _metadata: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let s_id = set_id.to_string();
        let c_id = cred_id.to_string();
        let entry = FakeEntry {
            cred_id: c_id.clone(),
            entry_type: EntryType::Verification,
            title: title.to_string(),
            subtitle: subtitle.to_string(),
            disclaimer: disclaimer.to_string(),
            warning: warning.to_string(),
            metadata_display_text: String::new(),
            fields: Vec::new(),
            merchant_name: String::new(),
            transaction_amount: String::new(),
            additional_info: String::new(),
        };
        self.entry_sets
            .get_mut(&s_id)
            .unwrap()
            .entries
            .entry(set_index.to_string())
            .or_insert_with(DeterministicMap::new)
            .insert(c_id, entry);
    }
    fn add_field_to_entry_set(
        &mut self,
        cred_id: &str,
        field_display_name: &str,
        field_display_value: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let s_id = set_id.to_string();
        let c_id = cred_id.to_string();
        let f_name = field_display_name.to_string();
        let f_val = field_display_value.to_string();
        self.entry_sets
            .get_mut(&s_id)
            .unwrap()
            .entries
            .get_mut(&set_index.to_string())
            .unwrap()
            .get_mut(&c_id)
            .unwrap()
            .fields
            .push((f_name, f_val));
    }
    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &str,
        merchant_name: &str,
        _method_name: &str,
        _method_subtitle: &str,
        _icon: &[u8],
        transaction_amount: &str,
        _bank_icon: &[u8],
        _provider_icon: &[u8],
        additional_info: &str,
        _metadata: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let s_id = set_id.to_string();
        let c_id = cred_id.to_string();
        let entry = FakeEntry {
            cred_id: c_id.clone(),
            entry_type: EntryType::Payment,
            title: String::new(),
            subtitle: String::new(),
            disclaimer: String::new(),
            warning: String::new(),
            metadata_display_text: String::new(),
            fields: Vec::new(),
            merchant_name: merchant_name.to_string(),
            transaction_amount: transaction_amount.to_string(),
            additional_info: additional_info.to_string(),
        };
        self.entry_sets
            .get_mut(&s_id)
            .unwrap()
            .entries
            .entry(set_index.to_string())
            .or_insert_with(DeterministicMap::new)
            .insert(c_id, entry);
    }
    fn add_inline_issuance_entry(
        &mut self,
        cred_id: &str,
        _icon: &[u8],
        title: &str,
        subtitle: &str,
    ) {
        let entry = FakeEntry {
            cred_id: cred_id.to_string(),
            entry_type: EntryType::InlineIssuance,
            title: title.to_string(),
            subtitle: subtitle.to_string(),
            disclaimer: String::new(),
            warning: String::new(),
            metadata_display_text: String::new(),
            fields: Vec::new(),
            merchant_name: String::new(),
            transaction_amount: String::new(),
            additional_info: String::new(),
        };
        self.standalone_entries.push(entry);
    }
    fn add_metadata_display_text_to_entry_set(
        &mut self,
        cred_id: &str,
        metadata_display_text: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let s_id = set_id.to_string();
        let c_id = cred_id.to_string();
        self.entry_sets
            .get_mut(&s_id)
            .unwrap()
            .entries
            .get_mut(&set_index.to_string())
            .unwrap()
            .get_mut(&c_id)
            .unwrap()
            .metadata_display_text = metadata_display_text.to_string();
    }
}

fn create_registry_blob(json_str: &str) -> Vec<u8> {
    let mut blob = Vec::new();
    let offset = 4 + 10;
    blob.extend_from_slice(&(offset as u32).to_le_bytes());
    for i in 0..10 {
        blob.push(i as u8);
    }
    blob.extend_from_slice(json_str.as_bytes());
    blob
}

fn run_test_impl(test_name: &str, custom_registry: Option<&str>) {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let testdata_dir = std::path::PathBuf::from(manifest_dir).join("../matcher/testdata");

    let registry_json = match custom_registry {
        Some(s) => s.to_string(),
        None => std::fs::read_to_string(testdata_dir.join("registry.json")).unwrap(),
    };

    let request_path = testdata_dir.join(format!("{}_request.json", test_name));
    let expected_path = testdata_dir.join(format!("{}_expected.json", test_name));

    let request_json = std::fs::read_to_string(&request_path)
        .unwrap_or_else(|_| panic!("Failed to read {:?}", request_path));
    let expected_json = std::fs::read_to_string(&expected_path)
        .unwrap_or_else(|_| panic!("Failed to read {:?}", expected_path));

    let mut credman = FakeCredman::new();
    credman.credentials_blob = create_registry_blob(&registry_json);
    credman.request_json = request_json;

    openid4vp_main(&mut credman).unwrap();

    let result = FakeCredmanResult {
        entry_sets: credman.entry_sets,
        standalone_entries: credman.standalone_entries,
    };

    let expected_result: FakeCredmanResult = DeJson::deserialize_json(&expected_json).unwrap();

    assert_eq!(
        result, expected_result,
        "Test {} failed",
        test_name
    );
}

macro_rules! define_test {
    ($func_name:ident, $test_name:expr) => {
        #[test]
        fn $func_name() {
            run_test_impl($test_name, None);
        }
    };
}

define_test!(tc07_mdoc_match, "TC07_MdocMatch");
define_test!(tc08_mdoc_mismatch, "TC08_MdocMismatch");
define_test!(tc09_sdjwt_match, "TC09_SdjwtMatch");
define_test!(tc10_sdjwt_mismatch, "TC10_SdjwtMismatch");
define_test!(tc11_inline_issuance_fallback, "TC11_InlineIssuanceFallback");
define_test!(tc12_missing_format, "TC12_MissingFormat");
define_test!(tc13_return_all_claims, "TC13_ReturnAllClaims");
define_test!(tc14_match_specific_claims, "TC14_MatchSpecificClaims");
define_test!(tc15_match_nested_claims, "TC15_MatchNestedClaims");
define_test!(tc16_fail_missing_claims, "TC16_FailMissingClaims");
define_test!(tc17_match_claim_values_bool, "TC17_MatchClaimValuesBool");
define_test!(tc18_fail_claim_values_bool, "TC18_FailClaimValuesBool");
define_test!(tc19_match_claim_values_int, "TC19_MatchClaimValuesInt");
define_test!(tc20_fail_claim_values_int, "TC20_FailClaimValuesInt");
define_test!(tc21_match_first_claim_set, "TC21_MatchFirstClaimSet");
define_test!(tc22_match_second_claim_set, "TC22_MatchSecondClaimSet");
define_test!(tc23_fail_all_claim_sets, "TC23_FailAllClaimSets");
define_test!(tc24_dcql_query_single, "TC24_DcqlQuerySingle");
define_test!(tc25_dcql_query_set_match, "TC25_DcqlQuerySetMatch");
define_test!(
    tc26_dcql_query_set_fail_required,
    "TC26_DcqlQuerySetFailRequired"
);
define_test!(
    tc27_dcql_query_set_fail_optional,
    "TC27_DcqlQuerySetFailOptional"
);
define_test!(
    tc28_dcql_query_complex_overlapping_sets,
    "TC28_DcqlQueryComplexOverlappingSets"
);
define_test!(
    tc29_dcql_query_openid4vp_spec_example,
    "TC29_DcqlQueryOpenID4VPSpecExample"
);
define_test!(tc30_parse_v1_unsigned, "TC30_ParseV1Unsigned");
define_test!(tc31_parse_v1_signed, "TC31_ParseV1Signed");
define_test!(tc32_extract_payment_sca1, "TC32_ExtractPaymentSca1");
define_test!(tc33_extract_payment_details, "TC33_ExtractPaymentDetails");
define_test!(tc34_extract_payment_generic, "TC34_ExtractPaymentGeneric");
define_test!(tc35_wasm_add_entry_to_set, "TC35_WasmAddEntryToSet");
define_test!(tc36_wasm_payment_v2, "TC36_WasmPaymentV2");

#[test]
fn tc37_wasm_metadata_text() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let testdata_dir = std::path::PathBuf::from(manifest_dir).join("../matcher/testdata");
    let mut registry_json =
        std::fs::read_to_string(testdata_dir.join("registry.json")).unwrap();
    let target = "\"title\": \"John's Driving License\"";
    if let Some(pos) = registry_json.find(target) {
        registry_json.insert_str(pos, "\"metadata_display_text\": \"Verified Member\", ");
    }
    run_test_impl("TC37_WasmMetadataText", Some(&registry_json));
}
