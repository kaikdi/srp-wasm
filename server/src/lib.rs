#![allow(non_snake_case)]

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use common::{N, compute_K, compute_k, compute_u, g, getRandomValues, m1, m2};
use num_bigint::BigUint;
use subtle::ConstantTimeEq;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

#[wasm_bindgen]
pub struct SrpServerVerifier {
    S: Vec<u8>,
    m1: Vec<u8>,
    m2: Vec<u8>,
}

#[wasm_bindgen]
impl SrpServerVerifier {
    pub fn session_key(&self) -> Vec<u8> {
        self.S.clone()
    }

    pub fn server_proof(&self) -> Vec<u8> {
        self.m2.clone()
    }

    pub fn verify_client(&self, client_response: &[u8]) -> bool {
        self.m1.ct_eq(client_response).into()
    }
}

#[wasm_bindgen]
pub struct SrpServer {
    N: BigUint,
    g: BigUint,
}

#[wasm_bindgen]
impl SrpServer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            N: BigUint::parse_bytes(&N.as_bytes(), 16).expect("Failed to create N."),
            g: BigUint::from(g),
        }
    }

    /// Client's private value a = random()
    pub fn generate_b(&self) -> Vec<u8> {
        let mut a = [0u8; 32];
        getRandomValues(&mut a);

        a.to_vec()
    }

    /// Client's public value B = k*v + g^b % N
    pub fn compute_B(&self, v: &[u8], b: &[u8]) -> Vec<u8> {
        let k = compute_k(&self.N.to_bytes_be(), &self.g.to_bytes_be());
        let v = BigUint::from_bytes_be(v);

        ((k * v + self.g.modpow(&BigUint::from_bytes_be(b), &self.N)) % &self.N).to_bytes_be()
    }

    /// Premaster secret: S = (A * v^u) ^ b % N
    fn compute_S(&self, A: &[u8], b: &[u8], v: &[u8]) -> Vec<u8> {
        let B = &self.compute_B(v, b);
        let u = compute_u(A, B);
        let v = BigUint::from_bytes_be(v);

        let A = BigUint::from_bytes_be(A);
        let base = (A * &v.modpow(&u, &self.N)) % &self.N;

        let b = BigUint::from_bytes_be(b);
        base.modpow(&b, &self.N).to_bytes_be()
    }

    pub fn srp_server_verifier(
        &self,
        A: &[u8],
        b: &[u8],
        B: &[u8],
        v: &[u8],
        salt: &[u8],
        username: &str,
    ) -> Result<SrpServerVerifier, JsError> {
        let S = self.compute_S(A, &b, v);
        let K = compute_K(&S);
        let m1 = match m1(A, B, &K, username, salt) {
            Ok(m1) => m1,
            Err(e) => return Err(JsError::new(e.as_str())),
        };
        let m2 = m2(&A, &m1, &S);

        Ok(SrpServerVerifier { S, m1, m2 })
    }
}
