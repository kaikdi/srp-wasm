#![allow(non_snake_case)]

use common::{N, SrpError, compute_K, compute_k, compute_u, g, m1, m2};
use num_bigint::BigUint;
use rand::{TryRngCore, rngs::OsRng};
use subtle::ConstantTimeEq;

pub struct SrpServerVerifier {
    pub S: Vec<u8>,
    pub m1: Vec<u8>,
    pub m2: Vec<u8>,
}

impl SrpServerVerifier {
    pub fn session_key(&self) -> &[u8] {
        &self.S
    }

    pub fn server_proof(&self) -> &[u8] {
        &self.m2
    }

    pub fn verify_client(&self, client_response: &[u8]) -> bool {
        self.m1.ct_eq(client_response).into()
    }
}

pub struct SrpServer {
    N: BigUint,
    g: BigUint,
}

impl SrpServer {
    pub fn new() -> Self {
        Self {
            N: BigUint::parse_bytes(&N.as_bytes(), 16).expect("Failed to create N."),
            g: BigUint::from(g),
        }
    }

    /// Client's private value a = random()
    pub fn generate_b(&self) -> Result<Vec<u8>, SrpError> {
        let mut b = [0u8; 32];
        let mut rng = OsRng;
        match rng.try_fill_bytes(&mut b) {
            Ok(_) => Ok(b.to_vec()),
            Err(_) => Err(SrpError::IllegalParameter),
        }
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
        salt: &[u8],
        username: &str,
    ) -> Result<SrpServerVerifier, SrpError> {
        let S = self.compute_S(A, &b, B);
        let K = compute_K(&S);
        let m1 = m1(A, B, &K, username, salt)?;
        let m2 = m2(&A, &m1, &S);

        Ok(SrpServerVerifier { S, m1, m2 })
    }
}

