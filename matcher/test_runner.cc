#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <cmath>

extern "C" {
#include "cJSON/cJSON.h"
#include "dcql.h"
#include "base64.h"
#include "credentialmanager.h"
int openid4vp_main();
}

using json = nlohmann::json;

// --- FakeCredman Implementation ---
enum class EntryType {
    Verification,
    InlineIssuance,
    Payment,
    UserInfo,
    Export
};

struct FakeEntry {
    std::string credId;
    EntryType type;
    std::string title;
    std::string subtitle;
    std::string disclaimer;
    std::string warning;
    std::string metadata_display_text;
    std::vector<std::pair<std::string, std::string>> fields;
    std::string merchant_name;
    std::string transaction_amount;
    std::string additional_info;
};

struct FakeEntrySet {
    std::string setId;
    int setLength;
    // setIndex -> credId -> entry
    std::map<int, std::map<std::string, FakeEntry>> entries;
};

class FakeCredman {
public:
    static FakeCredman& GetInstance() {
        static FakeCredman instance;
        return instance;
    }

    void Reset() {
        entrySets.clear();
        standaloneEntries.clear();
        wasmVersion = 1;
        requestJson = "";
        credentialsBlob.clear();
    }

    std::map<std::string, FakeEntrySet> entrySets;
    std::vector<FakeEntry> standaloneEntries;
    uint32_t wasmVersion = 1;
    std::string requestJson;
    std::vector<uint8_t> credentialsBlob;

private:
    FakeCredman() = default;
};

// --- Mocked ACM APIs (extern "C") ---
extern "C" {
void GetWasmVersion(uint32_t* version) {
    *version = FakeCredman::GetInstance().wasmVersion;
}

void GetRequestSize(uint32_t* size) {
    *size = FakeCredman::GetInstance().requestJson.size();
}

void GetRequestBuffer(void* buffer) {
    memcpy(buffer, FakeCredman::GetInstance().requestJson.c_str(), FakeCredman::GetInstance().requestJson.size());
}

void GetCredentialsSize(uint32_t* size) {
    *size = FakeCredman::GetInstance().credentialsBlob.size();
}

size_t ReadCredentialsBuffer(void* buffer, size_t offset, size_t len) {
    if (offset >= FakeCredman::GetInstance().credentialsBlob.size()) return 0;
    size_t toRead = std::min(len, (size_t)(FakeCredman::GetInstance().credentialsBlob.size() - offset));
    memcpy(buffer, FakeCredman::GetInstance().credentialsBlob.data() + offset, toRead);
    return toRead;
}

void AddEntrySet(const char* set_id, int set_length) {
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id] = {s_id, set_length, {}};
}

void AddEntryToSet(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning, const char* metadata, const char* set_id, int set_index) {
    FakeEntry entry;
    entry.credId = cred_id ? cred_id : "";
    entry.type = EntryType::Verification;
    entry.title = title ? title : "";
    entry.subtitle = subtitle ? subtitle : "";
    entry.disclaimer = disclaimer ? disclaimer : "";
    entry.warning = warning ? warning : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[set_index][entry.credId] = entry;
}

void AddFieldToEntrySet(const char* cred_id, const char* field_display_name, const char* field_display_value, const char* set_id, int set_index) {
    std::string c_id = cred_id ? cred_id : "";
    std::string f_name = field_display_name ? field_display_name : "";
    std::string f_val = field_display_value ? field_display_value : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[set_index][c_id].fields.push_back({f_name, f_val});
}

void AddPaymentEntryToSetV2(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* additional_info, const char* metadata, const char* set_id, int set_index) {
    FakeEntry entry;
    entry.credId = cred_id ? cred_id : "";
    entry.type = EntryType::Payment;
    entry.merchant_name = merchant_name ? merchant_name : "";
    entry.transaction_amount = transaction_amount ? transaction_amount : "";
    entry.additional_info = additional_info ? additional_info : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[set_index][entry.credId] = entry;
}

void AddPaymentEntryToSet(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* metadata, const char* set_id, int set_index) {
    AddPaymentEntryToSetV2(cred_id, merchant_name, payment_method_name, payment_method_subtitle, payment_method_icon, payment_method_icon_len, transaction_amount, bank_icon, bank_icon_len, payment_provider_icon, payment_provider_icon_len, "", metadata, set_id, set_index);
}

void AddMetadataDisplayTextToEntrySet(const char *cred_id, const char *metadata_display_text, const char *set_id, int set_index) {
    std::string c_id = cred_id ? cred_id : "";
    std::string m_text = metadata_display_text ? metadata_display_text : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[set_index][c_id].metadata_display_text = m_text;
}

void AddInlineIssuanceEntry(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle) {
    FakeEntry entry;
    entry.credId = cred_id ? cred_id : "";
    entry.type = EntryType::InlineIssuance;
    entry.title = title ? title : "";
    entry.subtitle = subtitle ? subtitle : "";
    FakeCredman::GetInstance().standaloneEntries.push_back(entry);
}

// Deprecated or unused stubs
void AddEntry(long long, const char*, size_t, const char*, const char*, const char*, const char*) {}
void AddField(long long, const char*, const char*) {}
void AddStringIdEntry(const char*, const char*, size_t, const char*, const char*, const char*, const char*) {}
void AddFieldForStringIdEntry(const char*, const char*, const char*) {}
void AddPaymentEntry(const char*, const char*, const char*, const char*, const char*, size_t, const char*, const char*, size_t, const char*, size_t) {}
void SetAdditionalDisclaimerAndUrlForVerificationEntry(const char*, const char*, const char*, const char*) {}
void SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(const char*, const char*, const char*, const char*, const char*, int) {}
void GetCallingAppInfo(CallingAppInfo*) {}
void SelfDeclarePackageInfo(const char*, const char*, size_t) {}
}

// --- Helper for creating registry blob ---
std::vector<uint8_t> CreateRegistryBlob(const std::string& jsonStr) {
    std::vector<uint8_t> blob;
    int offset = 4 + 10; // 4 bytes header + 10 bytes mock icon
    blob.resize(offset + jsonStr.size());
    memcpy(blob.data(), &offset, 4);
    for (int i = 0; i < 10; ++i) blob[4 + i] = (uint8_t)i;
    memcpy(blob.data() + offset, jsonStr.c_str(), jsonStr.size());
    return blob;
}

const std::string MOCK_REGISTRY_JSON = R"({
  "credentials": {
    "mso_mdoc": {
      "org.iso.18013.5.1.mDL": [
        {
          "id": "mdoc_cred_1",
          "display": {
            "verification": {
              "title": "John's Driving License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "family_name": { "value": "Doe", "display": { "verification": { "display": "Family Name" } } },
              "given_name": { "value": "John", "display": { "verification": { "display": "Given Name" } } },
              "age": { "value": 21, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": true, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        },
        {
          "id": "mdoc_cred_underage",
          "display": {
            "verification": {
              "title": "Underage License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "age": { "value": 18, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": false, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        },
        {
          "id": "mdoc_cred_3",
          "display": {
            "verification": {
              "title": "Alice's Driving License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "family_name": { "value": "Smith", "display": { "verification": { "display": "Family Name" } } },
              "given_name": { "value": "Alice", "display": { "verification": { "display": "Given Name" } } },
              "age": { "value": 25, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": true, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        },
        {
          "id": "mdoc_cred_4",
          "display": {
            "verification": {
              "title": "Jane's Driving License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "family_name": { "value": "Doe", "display": { "verification": { "display": "Family Name" } } },
              "given_name": { "value": "Jane", "display": { "verification": { "display": "Given Name" } } },
              "age": { "value": 30, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": true, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        }
      ]
    },
    "dc+sd-jwt": {
      "urn:eu.europa.ec.eudi:pid:1": [
        {
          "id": "sdjwt_cred_1",
          "display": {
            "verification": {
              "title": "My EU PID",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "user": {
              "address": {
                "locality": { "value": "Brussels", "display": { "verification": { "display": "City", "display_value": "Brussels" } } },
                "country": { "value": "BE", "display": { "verification": { "display": "Country", "display_value": "Belgium" } } }
              },
              "name": {
                "first": { "value": "Jane", "display": { "verification": { "display": "First Name", "display_value": "Jane" } } }
              }
            }
          }
        }
      ],
      "https://credentials.example.com/identity_credential": [
        {
          "id": "sdjwt_spec_pid",
          "display": { "verification": { "title": "Spec PID", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "given_name": { "value": "Alice", "display": { "verification": { "display": "Given Name" } } },
            "family_name": { "value": "Smith", "display": { "verification": { "display": "Family Name" } } },
            "address": {
              "street_address": { "value": "123 Spec St", "display": { "verification": { "display": "Street" } } }
            }
          }
        }
      ],
      "https://othercredentials.example/pid": [
        {
          "id": "sdjwt_spec_other_pid",
          "display": { "verification": { "title": "Other PID", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "given_name": { "value": "Bob", "display": { "verification": { "display": "Given Name" } } },
            "family_name": { "value": "Jones", "display": { "verification": { "display": "Family Name" } } },
            "address": {
              "street_address": { "value": "456 Other St", "display": { "verification": { "display": "Street" } } }
            }
          }
        }
      ],
      "https://credentials.example.com/reduced_identity_credential": [
        {
          "id": "sdjwt_spec_reduced_1",
          "display": { "verification": { "title": "Reduced PID", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "given_name": { "value": "Charlie", "display": { "verification": { "display": "Given Name" } } },
            "family_name": { "value": "Brown", "display": { "verification": { "display": "Family Name" } } }
          }
        }
      ],
      "https://cred.example/residence_credential": [
        {
          "id": "sdjwt_spec_reduced_2",
          "display": { "verification": { "title": "Residence Cred", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "postal_code": { "value": "12345", "display": { "verification": { "display": "Zip" } } },
            "locality": { "value": "Townsville", "display": { "verification": { "display": "City" } } },
            "region": { "value": "State", "display": { "verification": { "display": "Region" } } }
          }
        }
      ],
      "https://company.example/company_rewards": [
        {
          "id": "sdjwt_spec_rewards",
          "display": { "verification": { "title": "Rewards", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "rewards_number": { "value": "9999", "display": { "verification": { "display": "Rewards No" } } }
          }
        }
      ]
    },
    "issuance": {
      "mso_mdoc": [
        {
          "id": "issuance_mdl_1",
          "title": "Get a New mDL",
          "subtitle": "From your local DMV",
          "icon": { "start": 4, "length": 10 },
          "supported": [ "org.iso.18013.5.1.mDL" ]
        }
      ],
      "dc+sd-jwt": [
        {
          "id": "issuance_pid_1",
          "title": "Get a New EU PID",
          "subtitle": "Official Digital ID",
          "icon": { "start": 4, "length": 10 },
          "supported": [ "urn:eu.europa.ec.eudi:pid:1" ]
        }
      ]
    }
  }
})";

void RunRequest(const json& dcql_query, uint32_t wasm_version = 2) {
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().wasmVersion = wasm_version;
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    
    json request = {{"requests", {{
        {"protocol", "openid4vp-v1-unsigned"},
        {"data", {{"dcql_query", dcql_query}}}
    }}}};
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
}

// --- Group 1: Base64-URL Decoding ---
TEST_CASE("TC01_DecodeEmptyString") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"", &output);
    CHECK(len == 0);
    if (output) free(output);
}

TEST_CASE("TC02_DecodeNoPadding") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"SGVsbG8", &output);
    CHECK(len == 5);
    CHECK(std::string(output, len) == "Hello");
    if (output) free(output);
}

TEST_CASE("TC03_DecodeOnePadding") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"SGVsbG8=", &output);
    CHECK(len == 5);
    CHECK(std::string(output, len) == "Hello");
    if (output) free(output);
}

TEST_CASE("TC04_DecodeTwoPaddings") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"SGVsbA==", &output);
    CHECK(len == 4);
    CHECK(std::string(output, len) == "Hell");
    if (output) free(output);
}

TEST_CASE("TC05_DecodeUrlSafeChars") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"-_-_", &output);
    CHECK(len == 3);
    CHECK((uint8_t)output[0] == 0xFB);
    CHECK((uint8_t)output[1] == 0xFF);
    CHECK((uint8_t)output[2] == 0xBF);
    if (output) free(output);
}

TEST_CASE("TC06_DecodeInvalidChars") {
    char* output = nullptr;
    B64DecodeURL((char*)"SGV@#G8", &output);
    if (output) free(output);
}

// --- Group 2: DCQL Query & Matching ---
TEST_CASE("TC07_MdocMatch") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]})"));
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0].count("mdoc_cred_1"));
    CHECK(set.entries[0]["mdoc_cred_1"].type == EntryType::Verification);
}

TEST_CASE("TC08_MdocMismatch") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "UNKNOWN"}}]})"));
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC09_SdjwtMatch") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eu.europa.ec.eudi:pid:1"]}}]})"));
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0].count("sdjwt_cred_1"));
}

TEST_CASE("TC10_SdjwtMismatch") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["UNKNOWN"]}}]})"));
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC11_InlineIssuanceFallback") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}], "offer": true})"));
    CHECK(!FakeCredman::GetInstance().standaloneEntries.empty());
    CHECK(FakeCredman::GetInstance().standaloneEntries[0].type == EntryType::InlineIssuance);
}

TEST_CASE("TC12_MissingFormat") {
    RunRequest(json::parse(R"({"credentials": [{"id": "w3c", "format": "w3c_vc", "meta": {"vct_values": ["some_vct"]}}]})"));
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC13_ReturnAllClaims") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]})"));
    auto& entry = FakeCredman::GetInstance().entrySets.begin()->second.entries[0]["mdoc_cred_1"];
    CHECK(entry.fields.size() == 4);
}

TEST_CASE("TC14_MatchSpecificClaims") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]})"));
    auto& entry = FakeCredman::GetInstance().entrySets.begin()->second.entries[0]["mdoc_cred_1"];
    CHECK(entry.fields.size() == 1);
    CHECK(entry.fields[0].first == "Family Name");
}

TEST_CASE("TC15_MatchNestedClaims") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eu.europa.ec.eudi:pid:1"]}, "claims": [{"path": ["user", "address", "locality"]}]}]})"));
    auto& entry = FakeCredman::GetInstance().entrySets.begin()->second.entries[0]["sdjwt_cred_1"];
    CHECK(entry.fields.size() == 1);
    CHECK(entry.fields[0].first == "City");
    CHECK(entry.fields[0].second == "Brussels");
}

TEST_CASE("TC16_FailMissingClaims") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eu.europa.ec.eudi:pid:1"]}, "claims": [{"path": ["unknown", "claim"]}]}]})"));
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC17_MatchClaimValuesBool") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "age_over_21"], "values": [true]}]}]})"));
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0].count("mdoc_cred_1"));
}

TEST_CASE("TC18_FailClaimValuesBool") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "age_over_21"], "values": [false]}]}]})"));
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0].count("mdoc_cred_underage"));
    CHECK(!set.entries[0].count("mdoc_cred_1"));
}

TEST_CASE("TC19_MatchClaimValuesInt") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "age"], "values": [21, 22]}]}]})"));
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0].count("mdoc_cred_1"));
}

TEST_CASE("TC20_FailClaimValuesInt") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "age"], "values": [100]}]}]})"));
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC21_MatchFirstClaimSet") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"id": "given_name", "path": ["org.iso.18013.5.1", "given_name"]}, {"id": "unknown", "path": ["org.iso.18013.5.1", "unknown"]}], "claim_sets": [["given_name"], ["unknown"]]}]})"));
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC22_MatchSecondClaimSet") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"id": "unknown", "path": ["org.iso.18013.5.1", "unknown"]}, {"id": "given_name", "path": ["org.iso.18013.5.1", "given_name"]}], "claim_sets": [["unknown"], ["given_name"]]}]})"));
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC23_FailAllClaimSets") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"id": "unknown", "path": ["org.iso.18013.5.1", "unknown"]}, {"id": "another_unknown", "path": ["org.iso.18013.5.1", "another_unknown"]}], "claim_sets": [["unknown"], ["another_unknown"]]}]})"));
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC24_DcqlQuerySingle") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]})"), 2);
    CHECK(FakeCredman::GetInstance().entrySets.size() == 1);
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.setLength == 1);
}

TEST_CASE("TC25_DcqlQuerySetMatch") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eu.europa.ec.eudi:pid:1"]}}], "credential_sets": [{"options": [["pid"]]}]})"), 2);
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC26_DcqlQuerySetFailRequired") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["UNKNOWN"]}}], "credential_sets": [{"required": true, "options": [["pid"]]}]})"), 2);
    CHECK(FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC27_DcqlQuerySetFailOptional") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}, {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["UNKNOWN"]}}], "credential_sets": [{"required": true, "options": [["mdl"]]}, {"required": false, "options": [["pid"]]}]})"), 2);
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC28_DcqlQueryComplexOverlappingSets") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl1", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "given_name"], "values": ["John"]}]}, {"id": "mdl2", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "given_name"], "values": ["Jane"]}]}, {"id": "mdl3", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "family_name"], "values": ["Doe"]}]}], "credential_sets": [{"options": [["mdl1", "mdl3"], ["mdl2", "mdl3"], ["mdl1", "mdl2"]]}]})"), 2);
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC29_DcqlQueryOpenID4VPSpecExample") {
    RunRequest(json::parse(R"({"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}, "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["address", "street_address"]}]}, {"id": "other_pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://othercredentials.example/pid"]}, "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["address", "street_address"]}]}, {"id": "pid_reduced_cred_1", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/reduced_identity_credential"]}, "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]}, {"id": "pid_reduced_cred_2", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://cred.example/residence_credential"]}, "claims": [{"path": ["postal_code"]}, {"path": ["locality"]}, {"path": ["region"]}]}, {"id": "nice_to_have", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://company.example/company_rewards"]}, "claims": [{"path": ["rewards_number"]}]}], "credential_sets": [{"options": [["pid"], ["other_pid"], ["pid_reduced_cred_1", "pid_reduced_cred_2"]]}, {"required": false, "options": [["nice_to_have"]]}]})"), 2);
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

// --- Group 3: Protocol Parsing & Integration ---
TEST_CASE("TC30_ParseV1Unsigned") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]})"));
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

TEST_CASE("TC31_ParseV1Signed") {
    std::string b64_payload = "eyJkY3FsX3F1ZXJ5Ijp7ImNyZWRlbnRpYWxzIjpbeyJmb3JtYXQiOiJtc29fbWRvYyIsImlkIjoibWRsIiwibWV0YSI6eyJkb2N0eXBlX3ZhbHVlIjoib3JnLmlzby4xODAxMy41LjEubURMIn19XX19";
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().wasmVersion = 2;
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-signed", "data": {"request": "header.)" + b64_payload + R"(.signature"}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    CHECK(!FakeCredman::GetInstance().entrySets.empty());
}

std::string B64_PAYMENT_SCA1 = "eyJ0eXBlIjoidXJuOmV1ZGk6c2NhOnBheW1lbnQ6MSIsInBheWxvYWQiOnsicGF5ZWUiOnsibmFtZSI6Ik1lcmNoYW50IFgifSwiYW1vdW50X2Rpc3BsYXkiOiJFVVIgNTAuMDAifSwiY3JlZGVudGlhbF9pZHMiOlsibWRsIl19";

TEST_CASE("TC32_ExtractPaymentSca1") {
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    FakeCredman::GetInstance().wasmVersion = 3;
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}, "transaction_data": [")" + B64_PAYMENT_SCA1 + R"("]}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    auto& entry = set.entries[0]["mdoc_cred_1"];
    CHECK(entry.type == EntryType::Payment);
    CHECK(entry.merchant_name == "Merchant X");
    CHECK(entry.transaction_amount == "EUR 50.00");
}

TEST_CASE("TC33_ExtractPaymentDetails") {
    std::string b64 = "eyJ0eXBlIjoicGF5bWVudF9kZXRhaWxzIiwicGF5ZWVfbmFtZSI6Ik1lcmNoYW50IFkiLCJwYXltZW50X2Ftb3VudCI6IjEwLjAwIiwicGF5bWVudF9jdXJyZW5jeSI6IlVTRCIsImNyZWRlbnRpYWxfaWRzIjpbIm1kbCJdfQ==";
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    FakeCredman::GetInstance().wasmVersion = 3;
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}, "transaction_data": [")" + b64 + R"("]}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    auto& entry = set.entries[0]["mdoc_cred_1"];
    CHECK(entry.type == EntryType::Payment);
    CHECK(entry.merchant_name == "Merchant Y");
    CHECK(entry.transaction_amount == "USD 10.00");
}

TEST_CASE("TC34_ExtractPaymentGeneric") {
    std::string b64 = "eyJtZXJjaGFudF9uYW1lIjoiTWVyY2hhbnQgWiIsImFtb3VudCI6IkZyZWUiLCJjcmVkZW50aWFsX2lkcyI6WyJtZGwiXX0=";
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    FakeCredman::GetInstance().wasmVersion = 3;
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}, "transaction_data": [")" + b64 + R"("]}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    auto& entry = set.entries[0]["mdoc_cred_1"];
    CHECK(entry.type == EntryType::Payment);
    CHECK(entry.merchant_name == "Merchant Z");
    CHECK(entry.transaction_amount == "Free");
}

TEST_CASE("TC35_WasmAddEntryToSet") {
    RunRequest(json::parse(R"({"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]})"));
    auto& entry = FakeCredman::GetInstance().entrySets.begin()->second.entries[0]["mdoc_cred_1"];
    CHECK(entry.title == "John's Driving License");
}

TEST_CASE("TC36_WasmPaymentV2") {
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    FakeCredman::GetInstance().wasmVersion = 3;
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}, "transaction_data": [")" + B64_PAYMENT_SCA1 + R"("]}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0]["mdoc_cred_1"].type == EntryType::Payment);
}

TEST_CASE("TC37_WasmPaymentV1") {
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(MOCK_REGISTRY_JSON);
    FakeCredman::GetInstance().wasmVersion = 2;
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}, "transaction_data": [")" + B64_PAYMENT_SCA1 + R"("]}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    auto& set = FakeCredman::GetInstance().entrySets.begin()->second;
    CHECK(set.entries[0]["mdoc_cred_1"].type == EntryType::Payment);
}

TEST_CASE("TC38_WasmMetadataText") {
    std::string registry_with_meta = MOCK_REGISTRY_JSON;
    size_t pos = registry_with_meta.find("\"title\": \"John's Driving License\"");
    registry_with_meta.insert(pos, "\"metadata_display_text\": \"Verified Member\", ");
    FakeCredman::GetInstance().Reset();
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(registry_with_meta);
    FakeCredman::GetInstance().wasmVersion = 5;
    json request = json::parse(R"({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"dcql_query": {"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}}}]})");
    FakeCredman::GetInstance().requestJson = request.dump();
    openid4vp_main();
    auto& entry = FakeCredman::GetInstance().entrySets.begin()->second.entries[0]["mdoc_cred_1"];
    CHECK(entry.metadata_display_text == "Verified Member");
}
