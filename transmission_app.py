import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(message, key):
    """Encrypts message using AES-256-GCM and returns ciphertext, nonce, and hash."""
    # 1. Ensure Key is 32 bytes (256 bits)
    if len(key) < 32:
        key = key.ljust(32, b'\0')
    
    # 2. Hash the input message to create a verification tag (Integrity)
    original_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
    
    # 3. Encrypt using AES-GCM (Confidentiality & Authentication)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(message.encode('utf-8'), 16))
    
    # Return everything needed for decryption + the hash
    return base64.b64encode(cipher.nonce).decode('utf-8'), \
           base64.b64encode(ciphertext).decode('utf-8'), \
           base64.b64encode(tag).decode('utf-8'), \
           original_hash

def decrypt_message(nonce_b64, ciphertext_b64, tag_b64, key, expected_hash):
    """Decrypts message and verifies integrity via hash comparison."""
    key = key.ljust(32, b'\0')
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_bytes = unpad(cipher.decrypt_and_verify(ciphertext, tag), 16)
    decrypted_message = decrypted_bytes.decode('utf-8')
    
    # Verify Integrity
    new_hash = hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()
    
    if new_hash == expected_hash:
        return decrypted_message, True
    else:
        return None, False

# --- Main Execution ---
if __name__ == "__main__":
    my_key = b'supersecretkey123456789012345678' # 32-byte key
    secret = "This is a secret message!"
    
    print(f"Original: {secret}")
    
    # Encrypt
    nonce, ct, tag, original_h = encrypt_message(secret, my_key)
    print(f"Encrypted: {ct}")
    
    # Decrypt and Verify
    decrypted, integrity_ok = decrypt_message(nonce, ct, tag, my_key, original_h)
    
    print(f"Decrypted: {decrypted}")
    print(f"Integrity Verified: {integrity_ok}")
