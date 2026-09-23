#![cfg(test)]

use super::*;

const TOKEN: &str = "0123456789abcdef";

#[test]
fn keys_are_stable() {
    // If these values change, nodes of different versions cannot join each other.
    // Reference values from Python: hmac/hashlib, RFC 5869 with no salt.
    let keys = ClusterKeys::derive(TOKEN).unwrap();
    assert_eq!(
        keys.boot_server.to_string(),
        "4lAI2XxYeisYZOiOjeG772iG6nZGMTzyCDroB+oPcz8="
    );
    assert_eq!(
        keys.boot_client.to_string(),
        "wwg09tnkbQ61Fu04U4l1Z9KE+3DtmgnyXfxFExUJgS4="
    );
    assert_eq!(
        keys.mesh_psk.to_string(),
        "0QXXdTWKC0so+1oKPD2JA8yraR1aFPZlRGYJ8i/3wKI="
    );
}

#[test]
fn different_tokens_give_different_keys() {
    let a = ClusterKeys::derive(TOKEN).unwrap();
    let b = ClusterKeys::derive("0123456789abcdeX").unwrap();
    assert_ne!(a.boot_server.to_string(), b.boot_server.to_string());
    assert_ne!(a.boot_client.to_string(), b.boot_client.to_string());
    assert_ne!(a.mesh_psk.to_string(), b.mesh_psk.to_string());
}

#[test]
fn short_token_is_an_error() {
    assert!(ClusterKeys::derive("short").is_err());
}
