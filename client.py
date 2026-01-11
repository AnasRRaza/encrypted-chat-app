import socket
import getpass
import struct
import json
import base64
import os
from time import sleep
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Protocol constants
MSG_TYPE_TEXT = 0x00
MSG_TYPE_IMAGE = 0x01
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB
CHUNK_SIZE = 4096
FIXED_SALT = b'encrypted_chat_v1'


def derive_key_from_password(password, salt):
    """
    Derive a Fernet-compatible key from password using PBKDF2.

    Args:
        password: User's password string
        salt: Salt bytes (must be identical on both sides)

    Returns:
        32-byte key suitable for Fernet
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


def send_all(sock, data):
    """
    Send all data through socket, handling partial sends.

    Args:
        sock: Socket connection
        data: Bytes to send

    Raises:
        ConnectionError: If socket closes during send
    """
    total_sent = 0
    data_len = len(data)

    while total_sent < data_len:
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise ConnectionError("Socket connection broken during send")
        total_sent += sent


def recv_exact(sock, num_bytes):
    """
    Receive exactly num_bytes from socket, handling partial receives.

    Args:
        sock: Socket connection
        num_bytes: Exact number of bytes to receive

    Returns:
        Bytes data of length num_bytes

    Raises:
        ConnectionError: If socket closes before receiving all data
    """
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            raise ConnectionError("Socket connection broken during receive")
        data += chunk
    return data


def send_message(sock, msg_type, payload, cipher):
    """
    Send a structured message through socket.

    Args:
        sock: Socket connection
        msg_type: Message type byte (MSG_TYPE_TEXT or MSG_TYPE_IMAGE)
        payload: Dictionary to send (will be JSON-serialized)
        cipher: Fernet cipher for encryption

    Raises:
        ValueError: If payload exceeds MAX_MESSAGE_SIZE
        ConnectionError: If socket fails
    """
    # Serialize payload to JSON
    json_data = json.dumps(payload).encode('utf-8')

    # Encrypt payload
    encrypted_payload = cipher.encrypt(json_data)

    # Check size limit
    if len(encrypted_payload) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message size {len(encrypted_payload)} exceeds limit {MAX_MESSAGE_SIZE}")

    # Build message: [type(1)] + [length(4)] + [encrypted_payload]
    message_type = struct.pack('!B', msg_type)
    message_length = struct.pack('!I', len(encrypted_payload))

    full_message = message_type + message_length + encrypted_payload

    # Send atomically
    send_all(sock, full_message)


def recv_message(sock, cipher):
    """
    Receive a structured message from socket.

    Args:
        sock: Socket connection
        cipher: Fernet cipher for decryption

    Returns:
        Tuple of (message_type, payload_dict)

    Raises:
        ConnectionError: If socket closes unexpectedly
        ValueError: If message is malformed or too large
        InvalidToken: If decryption fails
    """
    # Receive message type (1 byte)
    type_bytes = recv_exact(sock, 1)
    msg_type = struct.unpack('!B', type_bytes)[0]

    # Receive message length (4 bytes)
    length_bytes = recv_exact(sock, 4)
    msg_length = struct.unpack('!I', length_bytes)[0]

    # Validate length
    if msg_length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message length {msg_length} exceeds maximum {MAX_MESSAGE_SIZE}")

    # Receive encrypted payload
    encrypted_payload = recv_exact(sock, msg_length)

    # Decrypt and deserialize
    decrypted_data = cipher.decrypt(encrypted_payload)
    payload = json.loads(decrypted_data.decode('utf-8'))

    return msg_type, payload


def read_image_file(filepath):
    """
    Read image file and extract extension.

    Args:
        filepath: Path to image file

    Returns:
        Tuple of (binary_data, file_extension)

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file can't be read
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Image file not found: {filepath}")

    # Get file extension
    _, ext = os.path.splitext(filepath)
    if not ext:
        ext = '.bin'

    # Read binary data
    with open(filepath, 'rb') as f:
        data = f.read()

    return data, ext


def save_image_file(data, sender, extension, output_dir="received_images"):
    """
    Save received image to disk with timestamp.

    Args:
        data: Binary image data
        sender: Name of sender
        extension: File extension (e.g., '.jpg')
        output_dir: Directory to save images

    Returns:
        Full path to saved file

    Raises:
        IOError: If file can't be written
    """
    # Create directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Generate filename: sender_timestamp.ext
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{sender}_{timestamp}{extension}"
    filepath = os.path.join(output_dir, filename)

    # Write file
    with open(filepath, 'wb') as f:
        f.write(data)

    return filepath


def chat(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to the server...")
    sleep(2)
    client.connect((host, port))
    print(f"Connected to server {host}:{port}")

    name = input("Your name: ")
    password = getpass.getpass("Enter password for encrypted chat: ")
    key = derive_key_from_password(password, FIXED_SALT)
    cipher = Fernet(key)

    while True:
        msg = input("Me: ")

        # Check for /image command
        if msg.startswith("/image "):
            filepath = msg[7:].strip()

            try:
                # Read image file
                image_data, ext = read_image_file(filepath)

                # Encode to base64 for JSON transport
                image_b64 = base64.b64encode(image_data).decode('ascii')

                # Get filename
                filename = os.path.basename(filepath)

                # Create payload
                payload = {
                    "sender": name,
                    "filename": filename,
                    "extension": ext,
                    "data": image_b64,
                    "size": len(image_data)
                }

                # Send as IMAGE message
                print(f"[Sending image: {filename} ({len(image_data) / 1024:.1f} KB)...]")
                send_message(client, MSG_TYPE_IMAGE, payload, cipher)
                print("[Image sent successfully]")

            except FileNotFoundError:
                print(f"ERROR: File not found: {filepath}")
                continue
            except ValueError as e:
                print(f"ERROR: {e}")
                continue
            except Exception as e:
                print(f"ERROR: Failed to send image: {e}")
                continue

        elif msg.lower() == "bye":
            # Send goodbye message
            payload = {"sender": name, "message": msg}
            send_message(client, MSG_TYPE_TEXT, payload, cipher)
            client.close()
            print("Disconnected from server.")
            break

        else:
            # Send regular text message
            payload = {"sender": name, "message": msg}
            send_message(client, MSG_TYPE_TEXT, payload, cipher)

        # Receive response
        try:
            msg_type, response = recv_message(client, cipher)

            if msg_type == MSG_TYPE_TEXT:
                print(f"{response['sender']}: {response['message']}")

            elif msg_type == MSG_TYPE_IMAGE:
                # Decode base64 image
                image_data = base64.b64decode(response['data'])

                # Save to disk
                filepath = save_image_file(
                    image_data,
                    response['sender'],
                    response['extension']
                )

                size_kb = response['size'] / 1024
                print(f"{response['sender']}: [IMAGE RECEIVED: {response['filename']} ({size_kb:.1f} KB)]")
                print(f"Saved to: {filepath}")

        except ConnectionError:
            print("Connection lost.")
            break
        except InvalidToken:
            print("ERROR: Decryption failed. Password mismatch?")
            continue
        except Exception as e:
            print(f"ERROR: {e}")
            continue

if __name__ == "__main__":
    print("Ask the server maintainer for server IP and PORT.")
    host = input("Enter the server IP address: ")
    port = int(input("Enter the server PORT: "))

    try:
        chat(host, port)
    except KeyboardInterrupt:
        print("\nDisconnected. Bye!")
    except Exception as e:
        print(f"Error: {e}")
