#!/bin/bash
set -e

# Change directory to the location of this script
cd "$(dirname "$0")"

WASM_PATH="target/wasm32-unknown-unknown/release/issuance.wasm"

# Run 1.sh to 8.sh and copy the output WASM file after each build
for i in {1..8}; do
    echo "--- Executing $i.sh ---"
    rm -rf target
    bash "./$i.sh"
    
    DEST="../app/src/main/assets/openid4vci-serde-$i.wasm"
    echo "Copying $WASM_PATH to $DEST"
    cp "$WASM_PATH" "$DEST"
done

echo "All builds completed and files copied."
