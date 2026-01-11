#!/usr/bin/python3

import socket
import getpass
import sys
import os
from os import system
from time import sleep
from platform import system as systemos, architecture
from cryptography.fernet import Fernet


# Function to generate a key and encrypt/decrypt messages
def generate_key(password):
    return Fernet(Fernet.generate_key())


# Using serveo.net to forward port for external network communication
def runServeo():
    print("Connecting to External network....")
    system('ssh -R 9568:0.0.0.0:9568 serveo.net > /dev/null &')
    sleep(5)
    ip = socket.gethostbyname('serveo.net')
    print("IP: {} \t PORT: 9568".format(ip))
    print("Share the above IP and PORT number with client.")


# Checking if user needs to connect through Internal Network or External Network
def internal_external():
    mode = input("Chat on Internal or External Network? (I/E): ")
    if mode.lower() == 'e':
        return True
    elif mode.lower() == 'i':
        return False
    else:
        print("Choose the correct option!")
        return internal_external()


# Actual code to chat over the network
def chat(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creating the socket
    server.bind((host, port))  # Binding the host and port
    server.listen(5)
    print("Waiting for connection from the client...")
    client, address = server.accept()  # Accepting connection from the client
    system('clear')
    print('Got connection from:', address)
    name = input("Your name: ")  # Name to identify yourself

    # Generate a key for encryption and decryption
    password = getpass.getpass("Enter password for encrypted chat: ")
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    while True:
        # Decrypt and display the received encrypted message
        encrypted_msg = client.recv(1024)
        print(cipher_suite.decrypt(encrypted_msg).decode('utf-8'))

        msg = input("Me: ")
        enc_msg = cipher_suite.encrypt((name + " : " + msg).encode('utf-8'))
        if msg.lower() == "bye":
            client.send(enc_msg)  # Send encrypted message
            client.close()
            server.close()
            system("pkill -f 'ssh -R 9568:0.0.0.0:9568 serveo.net'")
            exit(0)
        else:
            client.send(enc_msg)  # Send encrypted message


if __name__ == '__main__':
    host = ''
    if internal_external():
        runServeo()
        host = "0.0.0.0"
        port = 9568
    else:
        print("Your local IP/host IP is set to:")
        try:
            import subprocess
            local_ip = subprocess.getoutput("ipconfig getifaddr en0")  # Get local IP for macOS
            print(local_ip)
        except Exception as e:
            print("Unable to determine local IP address. Error:", e)

        host = input("Enter the host: ")
        port = int(input("Enter the port: "))
    try:
        chat(host, port)
    except KeyboardInterrupt:
        print("\nKeyboard Interrupted! \nBye bye...")
        system("pkill -f 'ssh -R 9568:0.0.0.0:9568 serveo.net'")
        exit()
