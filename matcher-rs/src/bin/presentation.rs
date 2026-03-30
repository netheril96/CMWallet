use matcher_rs::{credman::CredmanApiImpl, logger, presentation::presentation_main};

fn main() {
    logger::init();
    presentation_main(&mut CredmanApiImpl {}).unwrap();
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    main();
}
