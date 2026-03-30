use std::os::raw::c_void;

use crate::bindings::*;

pub trait CredmanApi {
    fn get_request_buffer(&self) -> Vec<u8>;
    fn get_registered_data(&self) -> Vec<u8>;
    fn add_string_id_entry(
        &mut self,
        entry_id: &str,
        icon: Option<&[u8]>,
        title: Option<&str>,
        subtitle: Option<&str>,
        disclaimer: Option<&str>,
        warning: Option<&str>,
    );
    fn add_entry_set(&mut self, set_id: &str, set_length: i32);
    fn add_entry_to_set(
        &mut self,
        cred_id: &str,
        icon: Option<&[u8]>,
        title: &str,
        subtitle: &str,
        disclaimer: &str,
        warning: Option<&str>,
        metadata: &str,
        set_id: &str,
        set_index: i32,
    );
    fn add_field_to_entry_set(
        &mut self,
        cred_id: &str,
        field_display_name: &str,
        field_display_value: Option<&str>,
        set_id: &str,
        set_index: i32,
    );
    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &str,
        merchant_name: &str,
        payment_method_name: &str,
        payment_method_subtitle: &str,
        payment_method_icon: Option<&[u8]>,
        transaction_amount: &str,
        bank_icon: Option<&[u8]>,
        payment_provider_icon: Option<&[u8]>,
        additional_info: &str,
        metadata: &str,
        set_id: &str,
        set_index: i32,
    );
    fn add_inline_issuance_entry(
        &mut self,
        cred_id: &str,
        icon: Option<&[u8]>,
        title: &str,
        subtitle: &str,
    );
    fn get_wasm_version(&self) -> u32;
    fn set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(
        &mut self,
        cred_id: &str,
        secondary_disclaimer: Option<&str>,
        url_display_text: Option<&str>,
        url_value: Option<&str>,
        set_id: &str,
        set_index: i32,
    );
    fn add_metadata_display_text_to_entry_set(
        &mut self,
        cred_id: &str,
        metadata_display_text: &str,
        set_id: &str,
        set_index: i32,
    );
}

pub struct CredmanApiImpl;

fn to_ptr_len(s: &str) -> (*const std::os::raw::c_char, usize) {
    (s.as_ptr() as *const std::os::raw::c_char, s.len())
}

fn opt_to_ptr_len(s: Option<&str>) -> (*const std::os::raw::c_char, usize) {
    s.map_or((std::ptr::null(), 0), |x| to_ptr_len(x))
}

impl CredmanApi for CredmanApiImpl {
    fn get_request_buffer(&self) -> Vec<u8> {
        let mut size: u32 = 0;
        unsafe {
            GetRequestSize(&mut size);
        }
        let mut r = vec![0; size as usize];
        unsafe {
            GetRequestBuffer(r.as_mut_ptr() as *mut c_void);
        }
        r
    }
    fn get_registered_data(&self) -> Vec<u8> {
        let mut size: u32 = 0;
        unsafe {
            GetCredentialsSize(&mut size);
        }
        let mut r = vec![0; size.try_into().unwrap()];
        unsafe {
            ReadCredentialsBuffer(r.as_mut_ptr() as *mut c_void, 0, size as usize);
        }
        r
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
        let (id_ptr, id_len) = to_ptr_len(entry_id);
        let icon_bytes =
            icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const std::os::raw::c_char;
        let icon_length = icon.map_or(0, |x| x.len());
        let (t_ptr, t_len) = opt_to_ptr_len(title);
        let (s_ptr, s_len) = opt_to_ptr_len(subtitle);
        let (d_ptr, d_len) = opt_to_ptr_len(disclaimer);
        let (w_ptr, w_len) = opt_to_ptr_len(warning);
        unsafe {
            AddStringIdEntry_L(
                id_ptr,
                id_len,
                icon_bytes,
                icon_length,
                t_ptr,
                t_len,
                s_ptr,
                s_len,
                d_ptr,
                d_len,
                w_ptr,
                w_len,
            );
        }
    }

    fn add_entry_set(&mut self, set_id: &str, set_length: i32) {
        let (ptr, len) = to_ptr_len(set_id);
        unsafe {
            AddEntrySet_L(ptr, len, set_length);
        }
    }

    fn add_entry_to_set(
        &mut self,
        cred_id: &str,
        icon: Option<&[u8]>,
        title: &str,
        subtitle: &str,
        disclaimer: &str,
        warning: Option<&str>,
        metadata: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let (id_ptr, id_len) = to_ptr_len(cred_id);
        let icon_bytes =
            icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const std::os::raw::c_char;
        let icon_length = icon.map_or(0, |x| x.len());
        let (t_ptr, t_len) = to_ptr_len(title);
        let (s_ptr, s_len) = to_ptr_len(subtitle);
        let (d_ptr, d_len) = to_ptr_len(disclaimer);
        let (w_ptr, w_len) = opt_to_ptr_len(warning);
        let (m_ptr, m_len) = to_ptr_len(metadata);
        let (sid_ptr, sid_len) = to_ptr_len(set_id);
        unsafe {
            AddEntryToSet_L(
                id_ptr, id_len, icon_bytes, icon_length, t_ptr, t_len, s_ptr, s_len, d_ptr, d_len,
                w_ptr, w_len, m_ptr, m_len, sid_ptr, sid_len, set_index,
            );
        }
    }

    fn add_field_to_entry_set(
        &mut self,
        cred_id: &str,
        field_display_name: &str,
        field_display_value: Option<&str>,
        set_id: &str,
        set_index: i32,
    ) {
        let (id_ptr, id_len) = to_ptr_len(cred_id);
        let (fn_ptr, fn_len) = to_ptr_len(field_display_name);
        let (fv_ptr, fv_len) = opt_to_ptr_len(field_display_value);
        let (sid_ptr, sid_len) = to_ptr_len(set_id);
        unsafe {
            AddFieldToEntrySet_L(
                id_ptr, id_len, fn_ptr, fn_len, fv_ptr, fv_len, sid_ptr, sid_len, set_index,
            );
        }
    }

    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &str,
        merchant_name: &str,
        payment_method_name: &str,
        payment_method_subtitle: &str,
        payment_method_icon: Option<&[u8]>,
        transaction_amount: &str,
        bank_icon: Option<&[u8]>,
        payment_provider_icon: Option<&[u8]>,
        additional_info: &str,
        metadata: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let (id_ptr, id_len) = to_ptr_len(cred_id);
        let (m_ptr, m_len) = to_ptr_len(merchant_name);
        let (pmn_ptr, pmn_len) = to_ptr_len(payment_method_name);
        let (pms_ptr, pms_len) = to_ptr_len(payment_method_subtitle);
        let pmic_ptr =
            payment_method_icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const std::os::raw::c_char;
        let pmic_len = payment_method_icon.map_or(0, |x| x.len());
        let (ta_ptr, ta_len) = to_ptr_len(transaction_amount);
        let bic_ptr = bank_icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const std::os::raw::c_char;
        let bic_len = bank_icon.map_or(0, |x| x.len());
        let ppic_ptr =
            payment_provider_icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const std::os::raw::c_char;
        let ppic_len = payment_provider_icon.map_or(0, |x| x.len());
        let (ai_ptr, ai_len) = to_ptr_len(additional_info);
        let (met_ptr, met_len) = to_ptr_len(metadata);
        let (sid_ptr, sid_len) = to_ptr_len(set_id);
        unsafe {
            AddPaymentEntryToSetV2_L(
                id_ptr, id_len, m_ptr, m_len, pmn_ptr, pmn_len, pms_ptr, pms_len, pmic_ptr, pmic_len,
                ta_ptr, ta_len, bic_ptr, bic_len, ppic_ptr, ppic_len, ai_ptr, ai_len, met_ptr,
                met_len, sid_ptr, sid_len, set_index,
            );
        }
    }

    fn add_inline_issuance_entry(
        &mut self,
        cred_id: &str,
        icon: Option<&[u8]>,
        title: &str,
        subtitle: &str,
    ) {
        let (id_ptr, id_len) = to_ptr_len(cred_id);
        let icon_bytes =
            icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const std::os::raw::c_char;
        let icon_length = icon.map_or(0, |x| x.len());
        let (t_ptr, t_len) = to_ptr_len(title);
        let (s_ptr, s_len) = to_ptr_len(subtitle);
        unsafe {
            AddInlineIssuanceEntry_L(id_ptr, id_len, icon_bytes, icon_length, t_ptr, t_len, s_ptr, s_len);
        }
    }

    fn get_wasm_version(&self) -> u32 {
        let mut version: u32 = 0;
        unsafe {
            GetWasmVersion(&mut version);
        }
        version
    }

    fn set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(
        &mut self,
        cred_id: &str,
        secondary_disclaimer: Option<&str>,
        url_display_text: Option<&str>,
        url_value: Option<&str>,
        set_id: &str,
        set_index: i32,
    ) {
        let (id_ptr, id_len) = to_ptr_len(cred_id);
        let (sd_ptr, sd_len) = opt_to_ptr_len(secondary_disclaimer);
        let (udt_ptr, udt_len) = opt_to_ptr_len(url_display_text);
        let (uv_ptr, uv_len) = opt_to_ptr_len(url_value);
        let (sid_ptr, sid_len) = to_ptr_len(set_id);
        unsafe {
            SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet_L(
                id_ptr, id_len, sd_ptr, sd_len, udt_ptr, udt_len, uv_ptr, uv_len, sid_ptr, sid_len,
                set_index,
            );
        }
    }

    fn add_metadata_display_text_to_entry_set(
        &mut self,
        cred_id: &str,
        metadata_display_text: &str,
        set_id: &str,
        set_index: i32,
    ) {
        let (id_ptr, id_len) = to_ptr_len(cred_id);
        let (mdt_ptr, mdt_len) = to_ptr_len(metadata_display_text);
        let (sid_ptr, sid_len) = to_ptr_len(set_id);
        unsafe {
            AddMetadataDisplayTextToEntrySet_L(id_ptr, id_len, mdt_ptr, mdt_len, sid_ptr, sid_len, set_index);
        }
    }
}
