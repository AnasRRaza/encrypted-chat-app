#!/usr/bin/env python3
"""
Encryption Demonstration Tool
Shows how text and images are encrypted/decrypted in the chat application
"""

import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Same constants as in the actual chat app
FIXED_SALT = b'encrypted_chat_v1'

def derive_key_from_password(password, salt):
    """Derive encryption key from password using PBKDF2-HMAC-SHA256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def print_header(title):
    """Print a nice header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def demo_text_encryption():
    """Demonstrate text message encryption"""
    print_header("TEXT MESSAGE ENCRYPTION DEMO")

    # Step 1: Password
    password = "demo123"
    print(f"\n1. Password: '{password}'")

    # Step 2: Key Derivation
    print("\n2. Key Derivation (PBKDF2-HMAC-SHA256):")
    print(f"   - Algorithm: SHA-256")
    print(f"   - Iterations: 100,000")
    print(f"   - Salt: {FIXED_SALT}")
    key = derive_key_from_password(password, FIXED_SALT)
    print(f"   - Derived Key (Base64): {key.decode()[:32]}...")

    # Step 3: Create cipher
    cipher = Fernet(key)
    print(f"\n3. Encryption Method: Fernet (AES-128 in CBC mode + HMAC)")

    # Step 4: Original message
    original_message = "Hello! This is a secret message."
    print(f"\n4. ORIGINAL MESSAGE (Plaintext):")
    print(f"   '{original_message}'")
    print(f"   Length: {len(original_message)} characters")

    # Step 5: Create JSON payload (like actual app)
    payload = {"sender": "Alice", "message": original_message}
    json_data = json.dumps(payload).encode('utf-8')
    print(f"\n5. JSON Payload:")
    print(f"   {json_data.decode()}")

    # Step 6: Encrypt
    encrypted = cipher.encrypt(json_data)
    print(f"\n6. ENCRYPTED DATA (what goes over the network):")
    print(f"   {encrypted}")
    print(f"   Length: {len(encrypted)} bytes")
    print(f"\n   First 50 bytes (hex): {encrypted[:50].hex()}")
    print(f"   ☝️ This is UNREADABLE gibberish - completely encrypted!")

    # Step 7: Decrypt
    decrypted = cipher.decrypt(encrypted)
    recovered_payload = json.loads(decrypted.decode('utf-8'))
    print(f"\n7. DECRYPTED DATA (receiver side):")
    print(f"   {recovered_payload}")
    print(f"   Message: '{recovered_payload['message']}'")

    # Show what happens with wrong password
    print(f"\n8. What happens with WRONG password:")
    wrong_key = derive_key_from_password("wrong_password", FIXED_SALT)
    wrong_cipher = Fernet(wrong_key)
    try:
        wrong_cipher.decrypt(encrypted)
        print("   ❌ This shouldn't happen!")
    except Exception as e:
        print(f"   ❌ Decryption FAILED: {type(e).__name__}")
        print(f"   ✅ This proves the encryption is working!")

def demo_image_encryption():
    """Demonstrate image encryption"""
    print_header("IMAGE ENCRYPTION DEMO")

    password = "demo123"
    key = derive_key_from_password(password, FIXED_SALT)
    cipher = Fernet(key)

    # Simulate image data (fake PNG header + data)
    fake_image_data = b'\x89PNG\r\n\x1a\n' + b'[simulated image data]' * 10
    print(f"\n1. ORIGINAL IMAGE DATA (binary):")
    print(f"   First 20 bytes: {fake_image_data[:20]}")
    print(f"   Total size: {len(fake_image_data)} bytes")

    # Base64 encode (for JSON)
    print(f"\n2. Base64 Encoding (for JSON transport):")
    image_b64 = base64.b64encode(fake_image_data).decode('ascii')
    print(f"   Encoded: {image_b64[:50]}...")
    print(f"   ⚠️ NOTE: Base64 is NOT encryption, just encoding!")

    # Create image payload
    print(f"\n3. Create JSON Payload:")
    payload = {
        "sender": "Bob",
        "filename": "secret_photo.jpg",
        "extension": ".jpg",
        "data": image_b64,
        "size": len(fake_image_data)
    }
    json_data = json.dumps(payload).encode('utf-8')
    print(f"   Payload size: {len(json_data)} bytes")

    # Encrypt
    print(f"\n4. ENCRYPT with Fernet (AES-128 + HMAC):")
    encrypted = cipher.encrypt(json_data)
    print(f"   Encrypted data: {encrypted[:60]}...")
    print(f"   Encrypted size: {len(encrypted)} bytes")
    print(f"\n   🔒 The entire image is encrypted!")
    print(f"   🔒 Filename, sender, and data are all hidden!")

    # Show encrypted vs plaintext comparison
    print(f"\n5. COMPARISON:")
    print(f"   Plaintext contains: '{payload['filename']}'")
    print(f"   Encrypted contains: {encrypted[:40]}...")
    print(f"   ✅ Filename is NOT visible in encrypted data!")

    # Decrypt
    print(f"\n6. DECRYPTION (receiver side):")
    decrypted = cipher.decrypt(encrypted)
    recovered = json.loads(decrypted.decode('utf-8'))
    recovered_image = base64.b64decode(recovered['data'])
    print(f"   Filename: {recovered['filename']}")
    print(f"   Image data: {recovered_image[:20]}...")
    print(f"   ✅ Image matches original: {recovered_image == fake_image_data}")

def demo_network_capture():
    """Show what network traffic looks like"""
    print_header("WHAT AN ATTACKER SEES ON THE NETWORK")

    password = "secret123"
    key = derive_key_from_password(password, FIXED_SALT)
    cipher = Fernet(key)

    # Encrypt a message
    message = "My credit card number is 1234-5678-9012-3456"
    payload = {"sender": "Alice", "message": message}
    encrypted = cipher.encrypt(json.dumps(payload).encode())

    print(f"\n❌ ATTACKER'S VIEW (network capture):")
    print(f"\n   Raw bytes on network:")
    print(f"   {encrypted.hex()}")
    print(f"\n   Trying to decode as text:")
    try:
        print(f"   {encrypted.decode('utf-8', errors='replace')}")
    except:
        print("   [Binary gibberish - cannot decode]")

    print(f"\n   Can attacker see 'credit card'? NO ❌")
    print(f"   Can attacker see '1234-5678'? NO ❌")
    print(f"   Can attacker see 'Alice'? NO ❌")
    print(f"\n   ✅ Everything is encrypted!")

    print(f"\n✅ YOUR VIEW (with correct password):")
    decrypted = cipher.decrypt(encrypted)
    recovered = json.loads(decrypted.decode())
    print(f"   Sender: {recovered['sender']}")
    print(f"   Message: {recovered['message']}")

def demo_encryption_technique():
    """Explain the encryption technique used"""
    print_header("ENCRYPTION TECHNIQUE DETAILS")

    print("""
📚 ENCRYPTION TECHNIQUE USED:

1. KEY DERIVATION: PBKDF2-HMAC-SHA256
   - Purpose: Convert password into encryption key
   - Algorithm: PBKDF2 (Password-Based Key Derivation Function 2)
   - Hash Function: HMAC with SHA-256
   - Iterations: 100,000 (slows down brute-force attacks)
   - Output: 32-byte key suitable for Fernet

2. MESSAGE ENCRYPTION: Fernet
   - Symmetric encryption scheme
   - Based on: AES-128 in CBC mode
   - Authentication: HMAC-SHA256
   - Timestamp: Included for key rotation
   - Components:
     * Version (1 byte)
     * Timestamp (8 bytes)
     * Initialization Vector - IV (16 bytes)
     * Ciphertext (variable length)
     * HMAC signature (32 bytes)

3. SECURITY FEATURES:
   ✅ Confidentiality: AES-128 encryption
   ✅ Integrity: HMAC prevents tampering
   ✅ Authentication: HMAC verifies sender
   ✅ Salt: Prevents rainbow table attacks
   ✅ High iteration count: Slows brute-force

4. PROTOCOL:
   - Message Type (1 byte): TEXT (0x00) or IMAGE (0x01)
   - Length Header (4 bytes): Size of encrypted payload
   - Encrypted Payload: Fernet-encrypted JSON data

5. FOR IMAGES:
   Image → Binary → Base64 → JSON → Fernet Encrypt → Network
   Network → Fernet Decrypt → JSON → Base64 Decode → Binary → Save
    """)

def main():
    """Run all demonstrations"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          ENCRYPTED CHAT - ENCRYPTION DEMONSTRATION               ║
║                  Course Project Demo Tool                        ║
╚══════════════════════════════════════════════════════════════════╝

This tool demonstrates how the chat application encrypts and
decrypts text messages and images.
    """)

    # Run all demos
    demo_encryption_technique()
    demo_text_encryption()
    demo_image_encryption()
    demo_network_capture()

    # Final summary
    print_header("SUMMARY FOR YOUR TEACHER")
    print("""
✅ ENCRYPTION METHOD: PBKDF2-HMAC-SHA256 + Fernet (AES-128-CBC + HMAC)

✅ KEY POINTS:
   1. Password is NEVER sent over network
   2. Password is converted to encryption key using PBKDF2
   3. All messages are encrypted with Fernet (AES-128)
   4. Images are encrypted the same way as text
   5. Attacker cannot read encrypted data without password
   6. Wrong password cannot decrypt messages

✅ SECURITY PROPERTIES:
   - Confidentiality: ✅ (AES-128 encryption)
   - Integrity: ✅ (HMAC signature)
   - Authentication: ✅ (HMAC with shared key)
   - Protection from brute-force: ✅ (100k iterations)

✅ WHAT'S ENCRYPTED:
   - Message content ✅
   - Sender name ✅
   - Image data ✅
   - Image filename ✅
   - Everything except message type and length ✅

❌ LIMITATIONS (Educational Project):
   - No protection against man-in-the-middle attacks
   - No perfect forward secrecy
   - Simple password-based security
    """)

    print("\n" + "="*70)
    print("  Run this demo for your teacher to show encryption in action!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
