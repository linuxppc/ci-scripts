#!/bin/bash

set -e

# Source OS release information
. /etc/os-release

# Extract major version
major="${VERSION_ID%%.*}"

# Only install Rust for Ubuntu 24.04 and later
if [[ "$major" -ge 24 ]]; then
    echo "Installing Rust toolchain for Ubuntu $VERSION_ID..."

    # Set up Rust environment variables
    export RUSTUP_HOME=/opt/rustup
    export CARGO_HOME=/opt/cargo
    export PATH="/opt/cargo/bin:${PATH}"

    # Install rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --no-modify-path

    # Source cargo environment
    . "$CARGO_HOME/env"

    # Install nightly toolchain with rust-src component
    rustup toolchain install nightly \
        && rustup default nightly \
        && rustup component add rust-src --toolchain nightly \
        && cargo install --locked bindgen-cli

    # Verify installation
    echo "Rust toolchain installed successfully:"
    rustc --version
    cargo --version
    bindgen --version

    # Verify rust-src is available
    if [ -f "$(rustc --print sysroot)/lib/rustlib/src/rust/library/core/src/lib.rs" ]; then
        echo "rust-src component verified successfully"
    else
        echo "WARNING: rust-src component not found at expected location"
        exit 1
    fi
else
    echo "Skipping Rust installation for Ubuntu $VERSION_ID (requires 24.04 or later)"
fi

# Made with Bob
