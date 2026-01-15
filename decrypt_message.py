#!/usr/bin/env python3
"""
Decryption Tool for Encrypted Chat Messages

This tool decrypts messages captured from the chat application.
Use it to demonstrate to your instructor that you can decrypt
the encrypted data using the correct password.

Usage:
    python decrypt_message.py
    # Then follow the interactive prompts

Supports:
    - Pasting short encrypted text directly
    - Reading from a file (for long image data)
    - Reading from the encryption_log.json file
"""

import base64
import json
import getpass
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Same constants as in the chat application
FIXED_SALT = b'encrypted_chat_v1'
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption_log.json")


def derive_key_from_password(password, salt):
    """
    Derive a Fernet-compatible key from password using PBKDF2.
    This is the SAME function used in server.py and client.py.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)


def decrypt_message(encrypted_data, password):
    """
    Decrypt an encrypted message using the provided password.

    Args:
        encrypted_data: The Fernet token (encrypted data as bytes or string)
        password: The password used for encryption

    Returns:
        Dictionary containing the decrypted payload

    Raises:
        InvalidToken: If password is wrong or data is corrupted
    """
    # Derive key from password
    key = derive_key_from_password(password, FIXED_SALT)
    cipher = Fernet(key)

    # Ensure encrypted_data is bytes
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')

    # Decrypt
    decrypted_bytes = cipher.decrypt(encrypted_data)

    # Parse JSON payload
    payload = json.loads(decrypted_bytes.decode('utf-8'))

    return payload


def print_header():
    """Print welcome header"""
    print("""
+======================================================================+
|           ENCRYPTED CHAT - MESSAGE DECRYPTION TOOL                   |
|                   For Instructor Demonstration                       |
+======================================================================+

This tool decrypts messages from the Encrypted Chat application.
It uses the SAME encryption method as the chat:
  - Key Derivation: PBKDF2-HMAC-SHA256 (100,000 iterations)
  - Encryption: Fernet (AES-128-CBC + HMAC-SHA256)
""")


def print_result(payload, msg_type="TEXT"):
    """Pretty print the decrypted result"""
    print("\n" + "="*70)
    print("  DECRYPTION SUCCESSFUL!")
    print("="*70)

    print(f"\n  Message Type: {msg_type}")
    print(f"  Sender: {payload.get('sender', 'Unknown')}")

    if 'message' in payload:
        # Text message
        print(f"  Message: {payload['message']}")
    elif 'filename' in payload:
        # Image message
        print(f"  Image: {payload['filename']}")
        print(f"  Extension: {payload.get('extension', 'unknown')}")
        print(f"  Size: {payload.get('size', 0) / 1024:.1f} KB")
        if 'data' in payload:
            print(f"  Image Data (first 50 chars of base64): {payload['data'][:50]}...")
            print(f"  Image Data Length: {len(payload['data'])} characters")

    print("\n  Full JSON payload (truncated for display):")
    # Don't show full image data
    display_payload = payload.copy()
    if 'data' in display_payload and len(str(display_payload['data'])) > 100:
        display_payload['data'] = str(display_payload['data'])[:100] + "...[truncated]"
    print(f"  {json.dumps(display_payload, indent=2)}")

    print("="*70)


def load_from_log_file():
    """Load messages from the encryption log file"""
    if not os.path.exists(LOG_FILE):
        print(f"\nLog file not found: {LOG_FILE}")
        print("Start a chat session first to generate the log.")
        return None

    try:
        with open(LOG_FILE, 'r') as f:
            messages = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"\nError reading log file: {e}")
        return None

    # Filter out stop markers
    messages = [m for m in messages if not m.get('_stop')]

    if not messages:
        print("\nNo messages found in log file.")
        return None

    print(f"\nFound {len(messages)} message(s) in log file:\n")
    for i, msg in enumerate(messages):
        content = msg.get('decrypted_content', '')[:50]
        if len(msg.get('decrypted_content', '')) > 50:
            content += '...'
        print(f"  [{i+1}] {msg['timestamp']} | {msg['direction']:8} | {msg['sender']:10} | {msg['msg_type']:5} | {content}")

    print()
    while True:
        choice = input("Enter message number to decrypt (or 'q' to cancel): ").strip()
        if choice.lower() == 'q':
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(messages):
                return messages[idx]['encrypted_data']
            else:
                print("Invalid number. Try again.")
        except ValueError:
            print("Please enter a number.")


def load_from_file():
    """Load encrypted data from a file"""
    filepath = input("\nEnter the path to the file containing encrypted data: ").strip()

    if not filepath:
        print("No path provided.")
        return None

    # Expand ~ to home directory
    filepath = os.path.expanduser(filepath)

    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None

    try:
        with open(filepath, 'r') as f:
            data = f.read().strip()
        print(f"Read {len(data)} characters from file.")
        return data
    except IOError as e:
        print(f"Error reading file: {e}")
        return None


def get_encrypted_input():
    """Get encrypted data from user - supports multiple input methods"""
    print("\n" + "-"*70)
    print("How would you like to provide the encrypted data?")
    print("-"*70)
    print("  [1] Select from encryption log (recommended for images)")
    print("  [2] Paste directly (for short text messages)")
    print("  [3] Read from a file")
    print("  [q] Quit")
    print()

    choice = input("Your choice: ").strip().lower()

    if choice == 'q':
        return None
    elif choice == '1':
        return load_from_log_file()
    elif choice == '2':
        print("\nPaste the encrypted message (the gAAAAA... string):")
        print("(For long data, use option 1 or 3 instead)")
        data = input("> ").strip()
        return data if data else None
    elif choice == '3':
        return load_from_file()
    else:
        print("Invalid choice.")
        return None


def save_decrypted_image(payload):
    """Offer to save decrypted image to disk"""
    if 'data' not in payload or 'filename' not in payload:
        return

    save = input("\nWould you like to save the decrypted image? (y/n): ").strip().lower()
    if save != 'y':
        return

    # Decode image data
    try:
        image_data = base64.b64decode(payload['data'])
    except Exception as e:
        print(f"Error decoding image: {e}")
        return

    # Get output filename
    default_name = f"decrypted_{payload['filename']}"
    filename = input(f"Enter filename (default: {default_name}): ").strip()
    if not filename:
        filename = default_name

    # Save file
    try:
        with open(filename, 'wb') as f:
            f.write(image_data)
        print(f"Image saved to: {filename}")
    except IOError as e:
        print(f"Error saving file: {e}")


def main():
    """Interactive mode for decrypting messages"""
    print_header()

    while True:
        encrypted_input = get_encrypted_input()

        if encrypted_input is None:
            continue_choice = input("\nTry again? (y/n): ").strip().lower()
            if continue_choice != 'y':
                print("\nGoodbye!")
                break
            continue

        if encrypted_input.lower() == 'q':
            print("\nGoodbye!")
            break

        # Check if it looks like Fernet token
        if not encrypted_input.startswith('gAAAAA'):
            print("\nWARNING: This doesn't look like a Fernet token.")
            print("Fernet tokens typically start with 'gAAAAA'")
            continue_anyway = input("Try anyway? (y/n): ").strip().lower()
            if continue_anyway != 'y':
                continue

        # Get password
        password = getpass.getpass("\nEnter the chat password: ")

        if not password:
            print("Password cannot be empty.")
            continue

        # Attempt decryption
        print("\nAttempting decryption...")
        print(f"  - Using PBKDF2-HMAC-SHA256 with salt: {FIXED_SALT}")
        print(f"  - Iterations: 100,000")
        print(f"  - Cipher: Fernet (AES-128-CBC + HMAC)")
        print(f"  - Encrypted data length: {len(encrypted_input)} characters")

        try:
            payload = decrypt_message(encrypted_input, password)

            # Determine message type
            if 'message' in payload:
                msg_type = "TEXT"
            elif 'filename' in payload:
                msg_type = "IMAGE"
            else:
                msg_type = "UNKNOWN"

            print_result(payload, msg_type)

            # Offer to save image if it's an image
            if msg_type == "IMAGE":
                save_decrypted_image(payload)

        except InvalidToken:
            print("\n" + "!"*70)
            print("  DECRYPTION FAILED!")
            print("!"*70)
            print("\n  Possible reasons:")
            print("  1. Wrong password")
            print("  2. Encrypted data was corrupted or incomplete")
            print("  3. Data was encrypted with different salt/settings")
            print("\n  This proves the encryption is working correctly!")
            print("  Without the correct password, data cannot be decrypted.")
            print("!"*70)

        except json.JSONDecodeError:
            print("\nDecryption succeeded but JSON parsing failed.")
            print("The data may not be a chat message.")

        except Exception as e:
            print(f"\nError: {e}")

        # Ask if user wants to continue
        print()
        continue_choice = input("Decrypt another message? (y/n): ").strip().lower()
        if continue_choice != 'y':
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()
