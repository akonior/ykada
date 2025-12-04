use yubikey_piv;

#[test]
fn test_initialize_yubikey_sign_data_and_independently_verify() {
    yubikey_piv::initialize_logger();
    let verifying_key = yubikey_piv::initialize_yubikey();
    let signature = yubikey_piv::sign_raw_data(&[0, 1, 2, 3, 4, 5, 6, 7, 8]);

    assert!(matches!(
        verifying_key.verify_strict(&[0, 1, 2, 3, 4, 5, 6, 7, 8], &signature),
        Ok(())
    ));
}
