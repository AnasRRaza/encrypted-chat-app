# Encrypted-Python-Chat

A terminal-based encrypted chat application built with Python 3 that provides peer-to-peer encrypted communication over TCP sockets using Fernet symmetric encryption.

## Features

- **End-to-End Encryption**: Messages are encrypted using Fernet (symmetric encryption) from the cryptography library
- **Terminal-Based**: Works entirely in the command line/terminal - no GUI required
- **Cross-Platform**: Independent of operating system (though some features are optimized for macOS/Linux)
- **Network Flexibility**: Supports both internal (LAN) and external (internet) network communication
- **External Network Access**: Uses SSH tunneling via serveo.net for easy internet access without port forwarding
- **Secure Password Input**: Uses `getpass` for secure password entry without echoing to screen

## Requirements

- Python 3.x
- `cryptography` library

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/Encrypted-Python-Chat.git
cd Encrypted-Python-Chat
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Starting the Server

Run the server script:

```bash
python server.py
```

You'll be prompted to choose between:
- **Internal Network (I)**: For local network communication (LAN)
  - Server will ask for host IP and port
  - Share your local IP address with the client

- **External Network (E)**: For internet communication
  - Automatically sets up SSH tunnel via serveo.net on port 9568
  - Server displays the public IP to share with clients
  - Requires SSH access (typically available on macOS/Linux)

After network setup:
1. Enter your name
2. Enter an encryption password (must match client's password)
3. Wait for client connection

### Connecting as Client

Run the client script:

```bash
python client.py
```

1. Enter the server IP address (provided by server host)
2. Enter the server PORT (provided by server host)
3. Enter your name
4. Enter the encryption password (must match server's password)

### Chatting

- Type your message and press Enter to send
- Received messages appear automatically
- Type `bye` to disconnect and exit

### Example Session

**Server:**
```
$ python server.py
Chat on Internal or External Network? (I/E): I
Your local IP/host IP is set to:
192.168.1.100
Enter the host: 192.168.1.100
Enter the port: 5000
Waiting for connection from the client...
Got connection from: ('192.168.1.101', 54321)
Your name: Alice
Enter password for encrypted chat: [hidden]
```

**Client:**
```
$ python client.py
Ask the server maintainer for server IP and PORT.
Enter the server IP address: 192.168.1.100
Enter the server PORT: 5000
Connecting to the server...
Connected to server 192.168.1.100:5000
Your name: Bob
Enter password for encrypted chat: [hidden]
Me: Hello Alice!
```

## How It Works

### Socket Communication
- Uses Python's `socket` library to establish TCP connections
- Server binds to a host/port and listens for incoming connections
- Client connects to the server's IP address and port

### Encryption
- Uses Fernet symmetric encryption from the `cryptography` library
- Each party generates an encryption key locally
- Messages are encrypted before transmission and decrypted upon receipt
- Password input is securely collected using `getpass` (no echo to screen)

### External Network Access
When running in external mode, the server uses SSH reverse tunneling via serveo.net:
- Command: `ssh -R 9568:0.0.0.0:9568 serveo.net`
- This creates a public endpoint accessible over the internet
- Automatically cleans up the SSH tunnel on exit

## Known Limitations

### Encryption Key Sharing
**Important**: The current implementation has a known limitation where the client and server generate separate encryption keys but attempt to decrypt each other's messages. For proper encrypted communication, both parties would need to:
- Derive the encryption key from the shared password using a Key Derivation Function (KDF)
- OR exchange keys securely before communication begins

The password is currently collected but not used in key generation.

### Platform Compatibility
- External network mode requires SSH (typically available on macOS/Linux)
- Local IP detection uses `ipconfig getifaddr en0` (macOS-specific)
- Screen clearing uses `clear` command (Unix/Linux/macOS)
- Windows users may need to modify these commands

## Troubleshooting

### Connection Refused
- **Issue**: Client cannot connect to server
- **Solutions**:
  - Verify server is running and listening
  - Check IP address and port number are correct
  - Ensure firewall isn't blocking the port
  - For internal network, confirm both devices are on the same network

### External Network Not Working
- **Issue**: SSH tunnel to serveo.net fails
- **Solutions**:
  - Ensure SSH is installed and accessible
  - Check internet connection
  - serveo.net service must be operational
  - Try internal network mode instead

### Port Already in Use
- **Issue**: `Address already in use` error
- **Solutions**:
  - Choose a different port number
  - Kill any process using the port: `lsof -ti:PORT | xargs kill`
  - Wait a moment for the OS to release the port

### Decryption Errors
- **Issue**: Cannot decrypt messages
- **Solutions**:
  - Ensure both client and server are using the same password
  - Restart both applications with matching passwords
  - Note: Due to the key-sharing limitation mentioned above, some encryption issues may occur

## Technical Details

- **Language**: Python 3.x
- **Networking**: TCP sockets via `socket` library
- **Encryption**: Fernet symmetric encryption via `cryptography` library
- **External Access**: SSH reverse tunneling via serveo.net
- **Dependencies**: See `requirements.txt`

## Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

## License

This project is open source and available for educational purposes.

## Security Notice

This application is designed for educational purposes. For production use, consider:
- Implementing proper key exchange (e.g., Diffie-Hellman)
- Using the password to derive encryption keys (KDF)
- Adding message authentication (HMAC)
- Implementing perfect forward secrecy
- Adding user authentication
