
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def send_message(message):

    msg = message

    try:
        client_socket.send(msg)  # Sending
    except socket.error as msg:
        print(f"Error: {msg}")
        client_socket.close()
        server_socket.close()
        exit()

    try:
        data = client_socket.recv(1024)  # Receiving
    except socket.error as msg:
        print(f"Error: {msg}")
        client_socket.close()
        server_socket.close()
        exit()

    received_message = data

    return received_message


if __name__ == '__main__':

    print("Welcome, Bob")

    # SOCKET SETUP - - - - - - - - - - - - - - - - - - - - - - -

    server_socket = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_STREAM
    )

    host = socket.gethostname()  # '172.100.88.3'
    port = 12347

    try:
        server_socket.bind((host, port))  # Binding
    except socket.error as msg:
        print(f"Error: {msg}")
        exit()

    server_socket.listen(5)
    print('Waiting client connection...')

    try:
        client_socket, address = server_socket.accept()  # Accepting
    except socket.error as msg:
        print(f"Error: {msg}")
        server_socket.close()
        exit()

    print(f"Connection established with: {address}\n")

    # KEY GENERATION - - - - - - - - - - - - - - - - - - - - - -

    private_key = ec.generate_private_key(
        curve=ec.SECP256R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()

    print(f"Private key: {private_key}")
    print(f"Public key: {public_key}\n")

    # SERIALIZATION - - - - - - - - - - - - - - - - - - - - - - -

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(f"Serialized Public Key: {serialized_public}\n")

    # SEND / RECEIVE KEY - - - - - - - - - - - - - - - - - - - -

    alice_public_key_serialized = send_message(serialized_public)

    alice_public_key = serialization.load_pem_public_key(
        data=alice_public_key_serialized,
        backend=default_backend()
    )

    print(f"Serialized Alice Public Key: {alice_public_key_serialized}")
    print(f"Alice Public Key: {alice_public_key}\n")

    # DIFFIE-HELLMAN - - - - - - - - - - - - - - - - - - - - - -

    shared_secret = private_key.exchange(
        algorithm=ec.ECDH(),
        peer_public_key=alice_public_key
    )

    print(f"Shared Secret: {shared_secret}\n")

    # SESSION KEY - - - - - - - - - - - - - - - - - - - - - - - -

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"session_key",
        backend=default_backend()
    )

    session_key = hkdf.derive(shared_secret)

    print(f"Session Key: {session_key}\n")

    # AES-128 GCM - - - - - - - - - - - - - - - - - - - - - - - -

    nonce = b"\x00" * 12  # os.urandom(12)

    cipher = Cipher(
        algorithm=algorithms.AES(session_key),
        mode=modes.GCM(nonce),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # CHATTING - - - - - - - - - - - - - - - - - - - - - - - - -

    while 1:
        prompt = input(">> ")
        if prompt == "exit()":
            break

        message = prompt.encode("ascii")
        ciphertext = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag

        print(f"\nMessage: {message}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Tag: {tag}\n")

        received_ciphertext = send_message(ciphertext)
        received_tag = send_message(tag)

        print(f"Ciphertext from Alice: {received_ciphertext}")
        print(f"Tag from Alice: {received_tag}\n")

        decryptor.authenticate_additional_data(b"")
        received_message = decryptor.update(received_ciphertext) + decryptor.finalize_with_tag(received_tag)

        print(f"Message from Alice: {received_message}\n")

    server_socket.close()
