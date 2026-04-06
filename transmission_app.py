import hashlib
from cryptography.fernet import Fernet

def run_crypto_project():
    # 1. Accept User Input
    message = input("Enter a message to secure: ").encode()

    # 2. Hash the input using SHA-256 (Integrity Checkpoint A)
    # This creates a 'fingerprint' of the original data.
    original_hash = hashlib.sha256(message).hexdigest()
    print(f"\n[Integrity] Original SHA-256 Hash: {original_hash}")

    # 3. Key Generation & Entropy
    # Fernet.generate_key() uses os.urandom() for high-entropy randomness.
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    print(f"[Key Gen] Symmetric Key Generated (Base64): {key.decode()}")

    # 4. Encrypt the input using AES (Confidentiality)
    # Fernet uses AES-128 in CBC mode with HMAC for authentication.
    cipher_text = cipher_suite.encrypt(message)
    print(f"[Confidentiality] Ciphertext: {cipher_text.decode()}")

    # 5. Decrypt the content
    decrypted_message = cipher_suite.decrypt(cipher_text)
    print(f"\n[Process] Decrypted Message: {decrypted_message.decode()}")

    # 6. Verify Integrity via Hash Comparison
    new_hash = hashlib.sha256(decrypted_message).hexdigest()
    print(f"[Integrity] Decrypted SHA-256 Hash: {new_hash}")

    if original_hash == new_hash:
        print("SUCCESS: Integrity verified. The hashes match!")
    else:
        print("FAILURE: Integrity breach detected!")

if __name__ == "__main__":
    run_crypto_project()
