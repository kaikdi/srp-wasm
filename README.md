# Install Rust toolchain

curl --proto '=https' --tlsv1.2 -sSf <https://sh.rustup.rs> | sh
rustup update stable

# Add WASM target for Rust

rustup target add wasm32-unknown-unknown

# Install wasm-bindgen CLI

cargo install wasm-bindgen-cli

# Install cargo-make for task running

cargo install cargo-make
