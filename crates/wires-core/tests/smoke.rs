//! Smoke test: proves the crate links and exposes a usable public surface.
//! (Placeholder — real behavior tests land with the real logic.)

#[test]
fn version_is_nonempty() {
    assert!(!wires_core::version().is_empty());
}
