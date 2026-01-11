import socket, getpass
from time import sleep
from cryptography.fernet import Fernet

def chat(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to the server...")
    sleep(2)
    client.connect((host, port))
    print(f"Connected to server {host}:{port}")

    name = input("Your name: ")
    password = getpass.getpass("Enter password for encrypted chat: ")
    key = Fernet.generate_key()
    cipher = Fernet(key)

    while True:
        msg = input("Me: ")
        enc_msg = cipher.encrypt(f"{name}: {msg}".encode())
        client.send(enc_msg)

        if msg.lower() == "bye":
            client.close()
            print("Disconnected from server.")
            break

        response = client.recv(1024)
        print(cipher.decrypt(response).decode())

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
