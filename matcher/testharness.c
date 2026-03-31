#include <stdio.h>
#include <sys/stat.h>

#include "credentialmanager.h"

#define REQUEST_PATH "request.json"
#define CREDS_PATH "testcreds.json"

void GetFileSize(const char* path, uint32_t* size) {
    struct stat s;
    stat(path, &s);
    *size = s.st_size;
}

void GetRequestSize(uint32_t* size) {
    GetFileSize(REQUEST_PATH, size);
}

void GetRequestBuffer(void* buffer) {
    uint32_t len;
    GetRequestSize(&len);
    FILE* f = fopen(REQUEST_PATH, "r");
    fread(buffer, len, 1, f);
    fclose(f);
}

void GetCredentialsSize(uint32_t* size) {
    GetFileSize(CREDS_PATH, size);
}

size_t ReadCredentialsBuffer(void* buffer, size_t offset, size_t len) {
    FILE* f = fopen(CREDS_PATH, "r");
    fseek(f, offset, SEEK_SET);
    size_t bytes_read = fread(buffer, 1, len, f);
    fclose(f);
    return bytes_read;
}

void AddStringIdEntry(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning) {
    printf("AddStringIdEntry id:%s title:%s subtitle:%s\n", cred_id, title, subtitle);
}

void AddFieldForStringIdEntry(const char* cred_id, const char* field_display_name, const char* field_display_value) {
    printf("AddFieldForStringIdEntry id:%s field_display_name:%s field_display_value:%s\n", cred_id, field_display_name, field_display_value);
}

void AddEntrySet(const char* set_id, int set_length) {
    printf("AddEntrySet id:%s length:%d\n", set_id, set_length);
}

void AddEntryToSet(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning, const char* metadata, const char* set_id, int set_index) {
    printf("AddEntryToSet set_id:%s index:%d cred_id:%s title:%s subtitle:%s disclaimer:%s warning:%s metadata:%s\n", set_id, set_index, cred_id, title, subtitle, disclaimer, warning, metadata);
}

void AddFieldToEntrySet(const char* cred_id, const char* field_display_name, const char* field_display_value, const char* set_id, int set_index) {
    printf("AddFieldToEntrySet set_id:%s index:%d cred_id:%s field:%s value:%s\n", set_id, set_index, cred_id, field_display_name, field_display_value);
}

void AddPaymentEntryToSetV2(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* additional_info, const char* metadata, const char* set_id, int set_index) {
    printf("AddPaymentEntryToSetV2 set_id:%s index:%d cred_id:%s merchant:%s\n", set_id, set_index, cred_id, merchant_name);
}

void AddPaymentEntryToSet(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* metadata, const char* set_id, int set_index) {
    printf("AddPaymentEntryToSet set_id:%s index:%d cred_id:%s\n", set_id, set_index, cred_id);
}

void GetWasmVersion(uint32_t* version) {
    *version = 6;
}

void AddInlineIssuanceEntry(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle) {
    printf("AddInlineIssuanceEntry id:%s title:%s\n", cred_id, title);
}

void AddMetadataDisplayTextToEntrySet(const char *cred_id, const char *metadata_display_text, const char *set_id, int set_index) {
    printf("AddMetadataDisplayTextToEntrySet set_id:%s index:%d cred_id:%s text:%s\n", set_id, set_index, cred_id, metadata_display_text);
}

void AddPaymentEntry(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len) {
    printf("AddPaymentEntry id:%s merchant:%s\n", cred_id, merchant_name);
}
