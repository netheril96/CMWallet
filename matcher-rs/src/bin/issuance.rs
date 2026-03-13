use matcher_rs::{credman::CredmanApi, credman::CredmanApiImpl, issuance::issuance_main};

fn main() {
    let mut credman = CredmanApiImpl {};
    credman.host_log("WASM issuance started");
    match issuance_main(&mut credman) {
        Ok(_) => credman.host_log("WASM issuance finished successfully"),
        Err(e) => credman.host_log(&format!("WASM issuance failed: {:?}", e)),
    }
}

// Credman expects this as the entry point, but it isn't there if the target is wasm32-unknown-unknown.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    main();
}
