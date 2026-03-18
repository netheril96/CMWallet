#!/bin/bash
set -e

# Change directory to the location of this script
cd "$(dirname "$0")"

# Run 1.sh to 8.sh and copy the output WASM file after each build
for i in {1..8}; do
    echo "--- Executing $i.sh ---"
    bash "./$i.sh"
    
    DEST="../app/src/main/assets/openid4vci-nano-$i.wasm"
    echo "Copying target/wasm32-unknown-unknown/release/issuance.wasm to $DEST"
    cp target/wasm32-unknown-unknown/release/issuance.wasm "$DEST"
done

echo "All builds completed and files copied."
