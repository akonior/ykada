// Example demonstrating basic YubiKey usage as a library
//
// Run with: cargo run --example basic_signing
//
// Note: This example requires a YubiKey to be connected

fn main() -> anyhow::Result<()> {
    println!("YubiKey Basic Signing Example");
    println!("==============================\n");

    // Initialize YubiKey with a default test key
    println!("Initializing YubiKey with test key...");
    let verifying_key = ykada::initialize_yubikey();
    println!("✓ YubiKey initialized");
    println!("  Public key: {:?}\n", verifying_key);

    // Sign some data
    let message = b"Hello, YubiKey!";
    println!("Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = ykada::sign_raw_data(message);
    println!("✓ Message signed");
    println!("  Signature: {:?}\n", signature);

    // Verify the signature
    println!("Verifying signature...");
    match verifying_key.verify_strict(message, &signature) {
        Ok(()) => println!("✓ Signature verified successfully!"),
        Err(e) => println!("✗ Signature verification failed: {:?}", e),
    }

    Ok(())
}
