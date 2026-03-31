use std::{ffi::CStr, os::raw::c_void, os::raw::c_char};

use crate::bindings::*;

pub trait CredmanApi {
    fn get_request_buffer(&self) -> Vec<u8>;
    fn get_registered_data(&self) -> Vec<u8>;
    fn get_wasm_version(&self) -> u32;
    
    fn add_entry_set(&mut self, set_id: &CStr, set_length: i32);
    
    fn add_entry_to_set(
        &mut self,
        cred_id: &CStr,
        icon: Option<&[u8]>,
        title: &CStr,
        subtitle: Option<&CStr>,
        explainer: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    );

    fn add_field_to_entry_set(
        &mut self,
        cred_id: &CStr,
        field_display_name: &CStr,
        field_display_value: Option<&CStr>,
        set_id: &CStr,
        set_index: i32,
    );

    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &CStr,
        merchant_name: &CStr,
        title: &CStr,
        subtitle: Option<&CStr>,
        icon: Option<&[u8]>,
        transaction_amount: &CStr,
        additional_info: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    );

    fn add_inline_issuance_entry(
        &mut self,
        cred_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
    );

    fn add_metadata_display_text_to_entry_set(
        &mut self,
        cred_id: &CStr,
        metadata_display_text: &CStr,
        set_id: &CStr,
        set_index: i32,
    );

    fn add_string_id_entry(
        &mut self,
        entry_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
    );
}

pub struct CredmanApiImpl;

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
    fn get_wasm_version(&self) -> u32 {
        let mut version: u32 = 0;
        unsafe {
            GetWasmVersion(&mut version);
        }
        version
    }

    fn add_entry_set(&mut self, set_id: &CStr, set_length: i32) {
        unsafe {
            AddEntrySet(set_id.as_ptr(), set_length);
        }
    }

    fn add_entry_to_set(
        &mut self,
        cred_id: &CStr,
        icon: Option<&[u8]>,
        title: &CStr,
        subtitle: Option<&CStr>,
        explainer: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    ) {
        let icon_ptr = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const c_char;
        let icon_len = icon.map_or(0, |x| x.len());
        unsafe {
            AddEntryToSet(
                cred_id.as_ptr(),
                icon_ptr,
                icon_len,
                title.as_ptr(),
                subtitle.map_or(std::ptr::null(), |x| x.as_ptr()),
                explainer.map_or(std::ptr::null(), |x| x.as_ptr()),
                std::ptr::null(), // warning
                metadata.as_ptr(),
                set_id.as_ptr(),
                set_index,
            );
        }
    }

    fn add_field_to_entry_set(
        &mut self,
        cred_id: &CStr,
        field_display_name: &CStr,
        field_display_value: Option<&CStr>,
        set_id: &CStr,
        set_index: i32,
    ) {
        unsafe {
            AddFieldToEntrySet(
                cred_id.as_ptr(),
                field_display_name.as_ptr(),
                field_display_value.map_or(std::ptr::null(), |x| x.as_ptr()),
                set_id.as_ptr(),
                set_index,
            );
        }
    }

    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &CStr,
        merchant_name: &CStr,
        title: &CStr,
        subtitle: Option<&CStr>,
        icon: Option<&[u8]>,
        transaction_amount: &CStr,
        additional_info: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    ) {
        let icon_ptr = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const c_char;
        let icon_len = icon.map_or(0, |x| x.len());
        unsafe {
            AddPaymentEntryToSetV2(
                cred_id.as_ptr(),
                merchant_name.as_ptr(),
                title.as_ptr(),
                subtitle.map_or(std::ptr::null(), |x| x.as_ptr()),
                icon_ptr,
                icon_len,
                transaction_amount.as_ptr(),
                std::ptr::null(), // bank_icon
                0,
                std::ptr::null(), // payment_provider_icon
                0,
                additional_info.map_or(std::ptr::null(), |x| x.as_ptr()),
                metadata.as_ptr(),
                set_id.as_ptr(),
                set_index,
            );
        }
    }

    fn add_inline_issuance_entry(
        &mut self,
        cred_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
    ) {
        let icon_ptr = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const c_char;
        let icon_len = icon.map_or(0, |x| x.len());
        unsafe {
            AddInlineIssuanceEntry(
                cred_id.as_ptr(),
                icon_ptr,
                icon_len,
                title.map_or(std::ptr::null(), |x| x.as_ptr()),
                subtitle.map_or(std::ptr::null(), |x| x.as_ptr()),
            );
        }
    }

    fn add_metadata_display_text_to_entry_set(
        &mut self,
        cred_id: &CStr,
        metadata_display_text: &CStr,
        set_id: &CStr,
        set_index: i32,
    ) {
        unsafe {
            AddMetadataDisplayTextToEntrySet(
                cred_id.as_ptr(),
                metadata_display_text.as_ptr(),
                set_id.as_ptr(),
                set_index,
            );
        }
    }

    fn add_string_id_entry(
        &mut self,
        entry_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
    ) {
        let icon_bytes = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const c_char;
        let icon_length = icon.map_or(0, |x| x.len());
        unsafe {
            AddStringIdEntry(
                entry_id.as_ptr(),
                icon_bytes,
                icon_length,
                title.map_or(std::ptr::null(), |x| x.as_ptr()),
                subtitle.map_or(std::ptr::null(), |x| x.as_ptr()),
                disclaimer.map_or(std::ptr::null(), |x| x.as_ptr()),
                warning.map_or(std::ptr::null(), |x| x.as_ptr()),
            );
        }
    }
}
