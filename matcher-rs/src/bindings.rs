use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct CallingAppInfo {
    pub package_name: [u8; 256],
    pub origin: [u8; 512],
}

unsafe extern "C" {
    pub fn AddEntry(
        cred_id: i64,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
        disclaimer: *const c_char,
        warning: *const c_char,
    );
    pub fn AddEntry_L(
        cred_id: i64,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        title_len: usize,
        subtitle: *const c_char,
        subtitle_len: usize,
        disclaimer: *const c_char,
        disclaimer_len: usize,
        warning: *const c_char,
        warning_len: usize,
    );
    pub fn AddField(
        cred_id: i64,
        field_display_name: *const c_char,
        field_display_value: *const c_char,
    );
    pub fn AddField_L(
        cred_id: i64,
        field_display_name: *const c_char,
        field_display_name_len: usize,
        field_display_value: *const c_char,
        field_display_value_len: usize,
    );
    pub fn AddEntrySet(set_id: *const c_char, set_length: i32);
    pub fn AddEntrySet_L(set_id: *const c_char, set_id_len: usize, set_length: i32);
    pub fn AddEntryToSet(
        cred_id: *const c_char,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
        disclaimer: *const c_char,
        warning: *const c_char,
        metadata: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    );
    pub fn AddEntryToSet_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        title_len: usize,
        subtitle: *const c_char,
        subtitle_len: usize,
        disclaimer: *const c_char,
        disclaimer_len: usize,
        warning: *const c_char,
        warning_len: usize,
        metadata: *const c_char,
        metadata_len: usize,
        set_id: *const c_char,
        set_id_len: usize,
        set_index: i32,
    );
    pub fn AddFieldToEntrySet(
        cred_id: *const c_char,
        field_display_name: *const c_char,
        field_display_value: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    );
    pub fn AddFieldToEntrySet_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        field_display_name: *const c_char,
        field_display_name_len: usize,
        field_display_value: *const c_char,
        field_display_value_len: usize,
        set_id: *const c_char,
        set_id_len: usize,
        set_index: i32,
    );
    pub fn AddPaymentEntryToSet(
        cred_id: *const c_char,
        merchant_name: *const c_char,
        payment_method_name: *const c_char,
        payment_method_subtitle: *const c_char,
        payment_method_icon: *const c_char,
        payment_method_icon_len: usize,
        transaction_amount: *const c_char,
        bank_icon: *const c_char,
        bank_icon_len: usize,
        payment_provider_icon: *const c_char,
        payment_provider_icon_len: usize,
        metadata: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    );
    pub fn AddPaymentEntryToSetV2(
        cred_id: *const c_char,
        merchant_name: *const c_char,
        payment_method_name: *const c_char,
        payment_method_subtitle: *const c_char,
        payment_method_icon: *const c_char,
        payment_method_icon_len: usize,
        transaction_amount: *const c_char,
        bank_icon: *const c_char,
        bank_icon_len: usize,
        payment_provider_icon: *const c_char,
        payment_provider_icon_len: usize,
        additional_info: *const c_char,
        metadata: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    );
    pub fn AddPaymentEntryToSetV2_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        merchant_name: *const c_char,
        merchant_name_len: usize,
        payment_method_name: *const c_char,
        payment_method_name_len: usize,
        payment_method_subtitle: *const c_char,
        payment_method_subtitle_len: usize,
        payment_method_icon: *const c_char,
        payment_method_icon_len: usize,
        transaction_amount: *const c_char,
        transaction_amount_len: usize,
        bank_icon: *const c_char,
        bank_icon_len: usize,
        payment_provider_icon: *const c_char,
        payment_provider_icon_len: usize,
        additional_info: *const c_char,
        additional_info_len: usize,
        metadata: *const c_char,
        metadata_len: usize,
        set_id: *const c_char,
        set_id_len: usize,
        set_index: i32,
    );
    pub fn AddStringIdEntry(
        cred_id: *const c_char,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
        disclaimer: *const c_char,
        warning: *const c_char,
    );
    pub fn AddStringIdEntry_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        title_len: usize,
        subtitle: *const c_char,
        subtitle_len: usize,
        disclaimer: *const c_char,
        disclaimer_len: usize,
        warning: *const c_char,
        warning_len: usize,
    );
    pub fn AddFieldForStringIdEntry(
        cred_id: *const c_char,
        field_display_name: *const c_char,
        field_display_value: *const c_char,
    );
    pub fn AddFieldForStringIdEntry_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        field_display_name: *const c_char,
        field_display_name_len: usize,
        field_display_value: *const c_char,
        field_display_value_len: usize,
    );
    pub fn GetRequestBuffer(buffer: *mut c_void);
    pub fn GetRequestSize(size: *mut u32);
    pub fn ReadCredentialsBuffer(buffer: *mut c_void, offset: usize, len: usize) -> usize;
    pub fn GetCredentialsSize(size: *mut u32);
    pub fn GetWasmVersion(version: *mut u32);
    pub fn AddPaymentEntry(
        cred_id: *const c_char,
        merchant_name: *const c_char,
        payment_method_name: *const c_char,
        payment_method_subtitle: *const c_char,
        payment_method_icon: *const c_char,
        payment_method_icon_len: usize,
        transaction_amount: *const c_char,
        bank_icon: *const c_char,
        bank_icon_len: usize,
        payment_provider_icon: *const c_char,
        payment_provider_icon_len: usize,
    );
    pub fn AddInlineIssuanceEntry(
        cred_id: *const c_char,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
    );
    pub fn AddInlineIssuanceEntry_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        title_len: usize,
        subtitle: *const c_char,
        subtitle_len: usize,
    );
    pub fn SetAdditionalDisclaimerAndUrlForVerificationEntry(
        cred_id: *const c_char,
        secondary_disclaimer: *const c_char,
        url_display_text: *const c_char,
        url_value: *const c_char,
    );
    pub fn SetAdditionalDisclaimerAndUrlForVerificationEntry_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        secondary_disclaimer: *const c_char,
        secondary_disclaimer_len: usize,
        url_display_text: *const c_char,
        url_display_text_len: usize,
        url_value: *const c_char,
        url_value_len: usize,
    );
    pub fn SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(
        cred_id: *const c_char,
        secondary_disclaimer: *const c_char,
        url_display_text: *const c_char,
        url_value: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    );
    pub fn SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        secondary_disclaimer: *const c_char,
        secondary_disclaimer_len: usize,
        url_display_text: *const c_char,
        url_display_text_len: usize,
        url_value: *const c_char,
        url_value_len: usize,
        set_id: *const c_char,
        set_id_len: usize,
        set_index: i32,
    );
    pub fn GetCallingAppInfo(info: *mut CallingAppInfo);
    pub fn SelfDeclarePackageInfo(
        package_display_name: *const c_char,
        package_icon: *const c_char,
        package_icon_len: usize,
    );
    pub fn SelfDeclarePackageInfo_L(
        package_display_name: *const c_char,
        package_display_name_len: usize,
        package_icon: *const c_char,
        package_icon_len: usize,
    );
    pub fn AddMetadataDisplayTextToEntrySet(
        cred_id: *const c_char,
        metadata_display_text: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    );
    pub fn AddMetadataDisplayTextToEntrySet_L(
        cred_id: *const c_char,
        cred_id_len: usize,
        metadata_display_text: *const c_char,
        metadata_display_text_len: usize,
        set_id: *const c_char,
        set_id_len: usize,
        set_index: i32,
    );
}
