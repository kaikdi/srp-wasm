#![allow(non_snake_case)]

use blake2::{Blake2b512, Digest};
use num_bigint::BigUint;
use wasm_bindgen::prelude::wasm_bindgen;

pub const N: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

#[allow(non_upper_case_globals)]
pub const g: u8 = 2;

#[derive(Debug)]
pub enum SrpError {
    IllegalParameter,
    BadRecordMac,
}

impl SrpError {
    pub fn as_str(&self) -> &str {
        match self {
            SrpError::IllegalParameter => "IllegalParameter",
            SrpError::BadRecordMac => "BadRecordMac",
        }
    }
}

/// Multiplier parameter: k = H(N | PAD(g))
pub fn compute_k(n_bytes: &[u8], g_bytes: &[u8]) -> BigUint {
    let mut g_padded = vec![0u8; n_bytes.len() - g_bytes.len()];
    g_padded.extend(g_bytes);

    let mut hasher = Blake2b512::new();
    hasher.update(n_bytes);
    hasher.update(g_padded);
    let k_hash = hasher.finalize();

    BigUint::from_bytes_be(&k_hash)
}

/// Session Key: K = H(S)
pub fn compute_K(premaster_secret: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(premaster_secret);

    hasher.finalize().to_vec()
}

/// Scrambling parameter: u = H(PAD(A) | PAD(B))
pub fn compute_u(A: &[u8], B: &[u8]) -> BigUint {
    let mut hasher = Blake2b512::new();
    hasher.update(A);
    hasher.update(B);
    let u_hash = hasher.finalize();

    BigUint::from_bytes_be(&u_hash)
}

/// Client Proof: M1 = H(H(N) XOR H(g) | H(username) | salt | A | B | K)
pub fn m1(A: &[u8], B: &[u8], K: &[u8], username: &str, salt: &[u8]) -> Result<Vec<u8>, SrpError> {
    let mut hasher = Blake2b512::new();

    // H(N)
    let hn = Blake2b512::digest(
        &BigUint::parse_bytes(N.as_bytes(), 16)
            .ok_or(SrpError::IllegalParameter)?
            .to_bytes_be(),
    );

    // H(g)
    let hg = Blake2b512::digest(&[g]);

    // H(N) XOR H(g)
    let hng_xor_hg: Vec<u8> = hn.iter().zip(hg.iter()).map(|(a, b)| a ^ b).collect();

    // H(username)
    let hu = Blake2b512::digest(username.as_bytes());

    hasher.update(hng_xor_hg);
    hasher.update(hu);
    hasher.update(salt);
    hasher.update(A);
    hasher.update(B);
    hasher.update(K);

    Ok(hasher.finalize().to_vec())
}

/// Server Proof: M2 = H(A | M1 | K)
pub fn m2(A: &[u8], m1: &[u8], K: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(A);
    hasher.update(m1);
    hasher.update(K);

    hasher.finalize().to_vec()
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = crypto)]
    pub fn getRandomValues(buf: &mut [u8]);
}
