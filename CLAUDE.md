# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Encrypted-Python-Chat is a terminal-based encrypted chat application built with Python 3. It provides peer-to-peer encrypted communication over TCP sockets using the Fernet symmetric encryption scheme.

## Setup and Installation

```bash
# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running the Application

### Start the Server
```bash
python server.py
```
- Choose Internal (I) or External (E) network mode
- For internal: provide local IP and port
- For external: uses serveo.net tunneling on port 9568
- Enter a password for encryption when prompted

### Start the Client
```bash
python client.py
```
- Enter server IP address and port provided by server
- Use same password as server for successful decryption
- Type messages and press Enter to send
- Type "bye" to disconnect

## Architecture

### Core Components

**server.py** - Server-side chat implementation
- Socket binding and listening (server.py:42-44)
- Network mode selection: internal LAN or external via SSH tunneling (server.py:29-37)
- Fernet encryption key generation (server.py:53)
- Message receive/decrypt and send/encrypt loop (server.py:56-70)

**client.py** - Client-side chat implementation
- Socket connection to server (client.py:6-10)
- Fernet encryption key generation (client.py:14)
- Message send/encrypt and receive/decrypt loop (client.py:17-28)

### Encryption Architecture

Both client and server:
1. Generate independent Fernet keys locally (server.py:53, client.py:14)
2. Use their own key to encrypt outgoing messages
3. Use their own key to decrypt incoming messages

**CRITICAL ISSUE**: The current implementation has a fundamental flaw - client and server generate separate encryption keys but attempt to decrypt each other's messages with their own keys. This will cause decryption failures. For proper operation, both parties need to share the same key (typically derived from the password using a KDF).

### External Network Access

The server can expose itself to external networks using serveo.net SSH tunneling:
- Command: `ssh -R 9568:0.0.0.0:9568 serveo.net` (server.py:21)
- Cleanup on exit: `pkill -f 'ssh -R 9568:0.0.0.0:9568 serveo.net'` (server.py:67, 94)

## Important Notes

### Password Handling
- Password is collected via `getpass.getpass()` for secure input (server.py:52, client.py:13)
- Password is currently NOT used in encryption - it's collected but ignored
- The encryption key is randomly generated, not derived from the password

### Platform Considerations
- Server uses `system('clear')` which is Unix/Linux/macOS specific (server.py:47)
- Local IP detection uses `ipconfig getifaddr en0` which is macOS-specific (server.py:83)
- Windows compatibility may require adjustments

### Dependencies
- `cryptography` library (Fernet) - used instead of the `simple-crypt` mentioned in README
- Standard library: `socket`, `getpass`, `sys`, `os`, `time`, `platform`, `subprocess`
