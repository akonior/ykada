#[test]
fn test_initialize_yubikey_sign_data_and_independently_verify() {
    let verifying_key = ykada::initialize_yubikey();
    let signature = ykada::sign_raw_data(&[0, 1, 2, 3, 4, 5, 6, 7, 8]);

    assert!(matches!(
        verifying_key.verify_strict(&[0, 1, 2, 3, 4, 5, 6, 7, 8], &signature),
        Ok(())
    ));
}
