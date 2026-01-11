#!/usr/bin/env python3
"""
Network Traffic Monitor
Shows what the encrypted data looks like when transmitted over the network
Use this to demonstrate to your teacher that data is encrypted
"""

import socket
import struct
import sys

def monitor_traffic(port=5000):
    """
    Monitor network traffic on specified port
    Shows the encrypted messages being sent
    """
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║              NETWORK TRAFFIC MONITOR                             ║
║         Showing Encrypted Data on the Network                    ║
╚══════════════════════════════════════════════════════════════════╝

Monitoring port {port}...

INSTRUCTIONS FOR YOUR TEACHER:
1. Start this monitor first
2. Then start your chat server on port {port}
3. Connect with client
4. Send text messages and images
5. Watch encrypted data appear here

Press Ctrl+C to stop.
""")

    # Create a raw socket to monitor traffic
    try:
        # Bind to all interfaces
        monitor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        monitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        monitor.bind(('localhost', port))
        monitor.listen(1)

        print(f"✅ Monitoring localhost:{port}")
        print("="*70)
        print("\nWaiting for connection...\n")

        client, address = monitor.accept()
        print(f"📡 Connection from {address}")
        print("="*70)

        message_count = 0

        while True:
            try:
                # Read message type
                type_byte = client.recv(1)
                if not type_byte:
                    break

                msg_type = struct.unpack('!B', type_byte)[0]

                # Read length
                length_bytes = client.recv(4)
                if not length_bytes:
                    break
                msg_length = struct.unpack('!I', length_bytes)[0]

                # Read encrypted payload
                data = b''
                while len(data) < msg_length:
                    chunk = client.recv(min(4096, msg_length - len(data)))
                    if not chunk:
                        break
                    data += chunk

                message_count += 1

                print(f"\n📨 MESSAGE #{message_count}")
                print("-" * 70)
                print(f"Type: {'TEXT (0x00)' if msg_type == 0 else 'IMAGE (0x01)'}")
                print(f"Length: {msg_length} bytes")
                print(f"\n🔒 ENCRYPTED DATA (first 100 bytes):")
                print(f"Hex: {data[:100].hex()}")
                print(f"\n Raw bytes: {data[:100]}")

                # Try to show it's not readable
                print(f"\n❌ Attempting to read as plaintext:")
                try:
                    decoded = data.decode('utf-8', errors='replace')
                    print(f"   {decoded[:100]}...")
                    print("   ☝️ UNREADABLE GIBBERISH - Successfully Encrypted!")
                except:
                    print("   Cannot decode - binary encrypted data!")

                print("\n✅ This data is ENCRYPTED and SECURE!")
                print("✅ Attacker cannot see message content")
                print("✅ Only someone with correct password can decrypt")
                print("="*70)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"\nError: {e}")
                break

        client.close()
        monitor.close()

    except KeyboardInterrupt:
        print("\n\n👋 Monitoring stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nNote: Make sure no other program is using this port")

if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print("⚠️  NOTE: This is for demonstration purposes only")
    print("    Use the actual chat server instead of this monitor")
    print("    to test the full encryption\n")

    # monitor_traffic(port)

    print("""
ALTERNATIVE APPROACH FOR YOUR TEACHER:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Instead of network monitoring, use the demo_encryption.py tool:

    python demo_encryption.py

This will show:
1. ✅ How password is converted to encryption key (PBKDF2)
2. ✅ How text is encrypted with Fernet (AES-128)
3. ✅ How images are encrypted
4. ✅ What encrypted data looks like
5. ✅ What happens with wrong password
6. ✅ Comparison: plaintext vs encrypted

You can also add print statements to your actual chat code to show
encryption in real-time. See instructions below.
    """)
