#![allow(non_snake_case)]

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use blake2::{Blake2b512, Digest};
use common::{N, SrpError, compute_K, compute_k, compute_u, g, getRandomValues, m1, m2};
use num_bigint::BigUint;
use subtle::ConstantTimeEq;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

#[wasm_bindgen]
pub struct SrpClientVerifier {
    S: Vec<u8>,
    m1: Vec<u8>,
    m2: Vec<u8>,
}

#[wasm_bindgen]
impl SrpClientVerifier {
    pub fn session_key(&self) -> Vec<u8> {
        self.S.clone()
    }

    pub fn client_proof(&self) -> Vec<u8> {
        self.m1.clone()
    }

    pub fn verify_server(&self, server_response: &[u8]) -> bool {
        self.m2.ct_eq(server_response).into()
    }
}

#[wasm_bindgen]
pub struct SrpClient {
    N: BigUint,
    g: BigUint,
}

#[wasm_bindgen]
impl SrpClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            N: BigUint::parse_bytes(&N.as_bytes(), 16).expect("Failed to create N."),
            g: BigUint::from(g),
        }
    }

    /// Private key: x = H(s | H(I | ":" | P))
    fn compute_x(&self, salt: &[u8], username: &str, password: &str) -> BigUint {
        let mut hasher = Blake2b512::new();
        hasher.update(username);
        hasher.update(":");
        hasher.update(password);
        let inner_hash = hasher.finalize_reset();

        hasher.update(salt);
        hasher.update(inner_hash);
        let x_hash = hasher.finalize();

        BigUint::from_bytes_be(&x_hash)
    }

    /// 2.4. SRP Verifier Creation (RFC 5054)
    ///
    /// Computes `v = g^x % N`, where `x = H(s | H(I ":" P))`.
    /// Reference: https://datatracker.ietf.org/doc/html/rfc5054#section-2.4
    pub fn verifier(&self, salt: &[u8], username: &str, password: &str) -> Vec<u8> {
        let x = self.compute_x(salt, username, password);

        self.g.modpow(&x, &self.N).to_bytes_be()
    }

    /// Client's private value a = random()
    pub fn generate_a(&self) -> Vec<u8> {
        let mut a = [0u8; 32];
        getRandomValues(&mut a);

        a.to_vec()
    }

    /// Client's public value A = g^a % N
    pub fn compute_A(&self, a: &[u8]) -> Vec<u8> {
        self.g
            .modpow(&BigUint::from_bytes_be(a), &self.N)
            .to_bytes_be()
    }

    /// Premaster secret: S = (B - k * g^x) ^ (a + u * x) mod N
    fn compute_S(
        &self,
        a: &[u8],
        A: &[u8],
        B: &[u8],
        salt: &[u8],
        username: &str,
        password: &str,
    ) -> Result<Vec<u8>, JsError> {
        let a_as_big_int = BigUint::from_bytes_be(a);
        let B_as_big_int = BigUint::from_bytes_be(B);
        let n = &self.N;

        // 2.5.4 Client Key Exchange
        //
        // The server MUST abort the handshake with an "illegal_parameter" alert if A % N = 0.
        // Reference: https://datatracker.ietf.org/doc/html/rfc5054#section-2.5.4
        if &B_as_big_int % n == BigUint::default() {
            return Err(JsError::new(SrpError::IllegalParameter.as_str()));
        }

        let u = compute_u(&A, B);
        let k = compute_k(&self.N.to_bytes_be(), &self.g.to_bytes_be());
        let x = self.compute_x(salt, username, password);

        // <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N

        let base = (k * &self.g.modpow(&x, n)) % n;
        let base = (&B_as_big_int + n - base) % n;
        let exp = (u * x) + a_as_big_int;

        Ok(base.modpow(&exp, n).to_bytes_be())
    }

    pub fn srp_client_verifier(
        &self,
        a: &[u8],
        A: &[u8],
        B: &[u8],
        salt: &[u8],
        username: &str,
        password: &str,
    ) -> Result<SrpClientVerifier, JsError> {
        let S = self.compute_S(a, &A, B, salt, username, password)?;
        let K = compute_K(&S);
        let m1 = match m1(A, B, &K, username, salt) {
            Ok(m1) => m1,
            Err(e) => return Err(JsError::new(e.as_str())),
        };
        let m2 = m2(&A, &m1, &S);

        Ok(SrpClientVerifier { S, m1, m2 })
    }
}
