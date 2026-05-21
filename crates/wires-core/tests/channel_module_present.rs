#[test]
fn channel_module_exposes_marker() {
    // Smoke test: the module exists and exposes a marker constant.
    assert_eq!(wires_core::channel::MODULE_VERSION, 1);
}
