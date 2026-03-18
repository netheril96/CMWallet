# 1. Build with maximum rustc optimizations
CARGO_PROFILE_RELEASE_OPT_LEVEL="z" \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
CARGO_PROFILE_RELEASE_STRIP=true \
cargo build \
  --target wasm32-unknown-unknown \
  --release


