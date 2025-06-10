# SRP-WASM

A secure [Secure Remote Password (SRP-6a)](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol) library written in Rust and compiled to WebAssembly, usable in both browser and Node.js environments.

## Features

- SRP-6a protocol implementation in Rust
- WebAssembly target for high performance and portability
- Client and server bindings for both browser and Node.js
- Safe password-authenticated key exchange
- No plaintext password transmission

## Use Cases

- Secure login system without exposing passwords
- Replace password-based auth in web apps with strong cryptographic exchange
- Works seamlessly with WebAssembly in modern frontend or backend apps
