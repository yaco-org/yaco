//! Keys derived from the join token.
//!
//! The join token is the cluster secret.
//! Every node derives the same keys from it,
//! so the keys are never sent over the network.

mod tests;

use defguard_wireguard_rs::key::Key;
use hkdf::Hkdf;
use sha2::Sha256;

/// A shorter token is too easy to guess.
pub const MIN_TOKEN_LEN: usize = 16;

/// All keys that come from the cluster secret.
pub struct ClusterKeys {
    /// Private key of the bootstrap interface in the server role (every member).
    pub boot_server: Key,
    /// Private key of the bootstrap interface in the client role (a joining node).
    pub boot_client: Key,
    /// Pre-shared key for every peer of the mesh interface.
    pub mesh_psk: Key,
}

impl ClusterKeys {
    pub fn derive(token: &str) -> anyhow::Result<ClusterKeys> {
        anyhow::ensure!(
            token.len() >= MIN_TOKEN_LEN,
            "the join token must have at least {MIN_TOKEN_LEN} characters"
        );
        Ok(ClusterKeys {
            boot_server: derive_key(token, "yaco-bootstrap-server-v1"),
            boot_client: derive_key(token, "yaco-bootstrap-client-v1"),
            mesh_psk: derive_key(token, "yaco-mesh-psk-v1"),
        })
    }
}

/// HKDF-SHA256 with no salt.
/// The result is a WireGuard private key or pre-shared key.
/// WireGuard clamps private keys itself, so any 32 bytes are valid.
fn derive_key(token: &str, info: &str) -> Key {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, token.as_bytes())
        .expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key::new(okm)
}
