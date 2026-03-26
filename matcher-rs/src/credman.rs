use std::{ffi::CStr, os::raw::c_void};

use crate::bindings::{
    AddEntrySet, AddEntryToSet, AddFieldToEntrySet, AddInlineIssuanceEntry, AddPaymentEntryToSetV2,
    AddStringIdEntry, GetCredentialsSize, GetRequestBuffer, GetRequestSize, GetWasmVersion,
    ReadCredentialsBuffer,
};

#[cfg(feature = "logging")]
use crate::bindings::HostLog;

pub trait CredmanApi {
    fn get_request_buffer(&self) -> Vec<u8>;
    fn get_registered_data(&self) -> Vec<u8>;
    fn add_string_id_entry(
        &mut self,
        entry_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
    );
    fn add_entry_set(&mut self, set_id: &CStr, set_length: i32);
    fn add_entry_to_set(
        &mut self,
        cred_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    );
    fn add_field_to_entry_set(
        &mut self,
        cred_id: &CStr,
        field_display_name: &CStr,
        field_display_value: &CStr,
        set_id: &CStr,
        set_index: i32,
    );
    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &CStr,
        merchant_name: &CStr,
        payment_method_name: &CStr,
        payment_method_subtitle: &CStr,
        payment_method_icon: Option<&[u8]>,
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
        title: &CStr,
        subtitle: &CStr,
    );
    fn get_wasm_version(&self) -> u32;
    fn host_log(&self, msg: &str);
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
    fn add_string_id_entry(
        &mut self,
        entry_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
    ) {
        let icon_bytes = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const i8;
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
    fn add_entry_set(&mut self, set_id: &CStr, set_length: i32) {
        unsafe {
            AddEntrySet(set_id.as_ptr(), set_length);
        }
    }
    fn add_entry_to_set(
        &mut self,
        cred_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    ) {
        let icon_bytes = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const i8;
        let icon_length = icon.map_or(0, |x| x.len());
        unsafe {
            AddEntryToSet(
                cred_id.as_ptr(),
                icon_bytes,
                icon_length,
                title.map_or(std::ptr::null(), |x| x.as_ptr()),
                subtitle.map_or(std::ptr::null(), |x| x.as_ptr()),
                disclaimer.map_or(std::ptr::null(), |x| x.as_ptr()),
                warning.map_or(std::ptr::null(), |x| x.as_ptr()),
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
        field_display_value: &CStr,
        set_id: &CStr,
        set_index: i32,
    ) {
        unsafe {
            AddFieldToEntrySet(
                cred_id.as_ptr(),
                field_display_name.as_ptr(),
                field_display_value.as_ptr(),
                set_id.as_ptr(),
                set_index,
            );
        }
    }
    fn add_payment_entry_to_set_v2(
        &mut self,
        cred_id: &CStr,
        merchant_name: &CStr,
        payment_method_name: &CStr,
        payment_method_subtitle: &CStr,
        payment_method_icon: Option<&[u8]>,
        transaction_amount: &CStr,
        additional_info: Option<&CStr>,
        metadata: &CStr,
        set_id: &CStr,
        set_index: i32,
    ) {
        let icon_bytes = payment_method_icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const i8;
        let icon_length = payment_method_icon.map_or(0, |x| x.len());
        unsafe {
            AddPaymentEntryToSetV2(
                cred_id.as_ptr(),
                merchant_name.as_ptr(),
                payment_method_name.as_ptr(),
                payment_method_subtitle.as_ptr(),
                icon_bytes,
                icon_length,
                transaction_amount.as_ptr(),
                std::ptr::null(), // bank_icon
                0,                // bank_icon_len
                std::ptr::null(), // payment_provider_icon
                0,                // payment_provider_icon_len
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
        title: &CStr,
        subtitle: &CStr,
    ) {
        let icon_bytes = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const i8;
        let icon_length = icon.map_or(0, |x| x.len());
        unsafe {
            AddInlineIssuanceEntry(
                cred_id.as_ptr(),
                icon_bytes,
                icon_length,
                title.as_ptr(),
                subtitle.as_ptr(),
            );
        }
    }
    fn get_wasm_version(&self) -> u32 {
        let mut version: u32 = 0;
        unsafe {
            GetWasmVersion(&mut version);
        }
        version
    }

    #[cfg(feature = "logging")]
    fn host_log(&self, msg: &str) {
        unsafe {
            HostLog(msg.as_ptr() as *const i8, msg.len() as i32);
        }
    }

    #[cfg(not(feature = "logging"))]
    fn host_log(&self, _msg: &str) {
        // No-op when logging is disabled
    }
}

