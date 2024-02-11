
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def send_message(message):

    data = client_socket.recv(1024)

    received_message = data

    msg = message

    client_socket.send(msg)

    return received_message


if __name__ == '__main__':

    print("Welcome, Alice")

    # SOCKET SETUP - - - - - - - - - - - - - - - - - - - - - - -

    client_socket = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_STREAM
    )

    host = '192.168.72.52'  # socket.gethostname()
    port = 12345

    client_socket.connect((host, port))

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

    bob_public_key_serialized = send_message(serialized_public)

    bob_public_key = serialization.load_pem_public_key(
        data=bob_public_key_serialized,
        backend=default_backend()
    )

    print(f"Serialized Bob Public Key: {bob_public_key_serialized}")
    print(f"Bob Public Key: {bob_public_key}\n")

    # DIFFIE-HELLMAN - - - - - - - - - - - - - - - - - - - - - -

    shared_secret = private_key.exchange(
        algorithm=ec.ECDH(),
        peer_public_key=bob_public_key
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

    # CHATTING - - - - - - - - - - - - - - - - - - - - - - - - -

    while 1:
        prompt = input(">> ")
        if prompt == "exit()":
            break

        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()

        message = prompt.encode("ascii")
        ciphertext = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag

        print(f"\nMessage: {message}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Tag: {tag}\n")

        received_ciphertext = send_message(ciphertext)
        received_tag = send_message(tag)

        print(f"Ciphertext from Bob: {received_ciphertext}")
        print(f"Tag from Bob: {received_tag}\n")

        decryptor.authenticate_additional_data(b"")
        received_message = decryptor.update(received_ciphertext)  + decryptor.finalize_with_tag(received_tag)

        print(f"Message from Bob: {received_message}\n")

    client_socket.close()
