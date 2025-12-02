from pycardano import Address, Network, PaymentSigningKey, PaymentVerificationKey

def main():
    print("Hello from test-data-generator!")

def generate_test_data():
    payment_signing_key = PaymentSigningKey.generate()
    payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)

    network = Network.TESTNET
    address = Address(payment_part=payment_verification_key.hash(), network=network)

    print(f"Payment signing key: {payment_signing_key}")
    print(f"Payment verification key: {payment_verification_key}")
    print(f"Network: {network}")
    print(f"Address: {address}")

if __name__ == "__main__":
    generate_test_data()
