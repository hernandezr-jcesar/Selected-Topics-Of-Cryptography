
import base64
import os
import pickle
import socket
from utils import Point, EllipticCurve
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def send_message(msg):

    data = client_socket.recv(1024)

    received_message = data

    client_socket.send(msg)

    return received_message


if __name__ == '__main__':

    print("Welcome, Alice")

    # SOCKET SETUP - - - - - - - - - - - - - - - - - - - - - - -

    client_socket = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_STREAM
    )

    host = socket.gethostname()  # '172.100.72.140'
    port = 12346

    client_socket.connect((host, port))

    # KEY GENERATION - - - - - - - - - - - - - - - - - - - - - -

    p_256 = EllipticCurve(
        a=115792089210356248762697446949407573530086143415290314195533631308867097853948,
        b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
        p=115792089210356248762697446949407573530086143415290314195533631308867097853951
    )

    G = Point(
        x=48439561293906451759052585252797914202762949526041747995844080717082404635286,
        y=36134250956749795798585127919587881956611106672985015071877198253568414405109,
        curve=p_256
    )

    while True:
        try:
            private_key = int.from_bytes(os.urandom(4), byteorder='big')
            yA = G.multiply(private_key)
            break
        except ValueError:
            pass

    print(f"\nMy Private Key: {private_key}")
    print(f"My Partial Key: {yA}")

    # KEY EXCHANGE - - - - - - - - - - - - - - - - - - - - - -

    received = client_socket.recv(1024)
    yB: Point = pickle.loads(received)

    msg = pickle.dumps(yA)
    client_socket.send(msg)

    print(f"\nReceived Partial Key: {yB}")

    # DIFFIE-HELLMAN - - - - - - - - - - - - - - - - - - - - - -

    K = yB.multiply(private_key)

    print(f"\nShared Secret: {K}")

    # SESSION KEY - - - - - - - - - - - - - - - - - - - - - - - -

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"session_key",
        backend=default_backend()
    )

    session_key = hkdf.derive(K.to_bytes())

    print(f"\nSession Key: {base64.b64encode(session_key).decode('utf-8')}")

    # AES-128 GCM - - - - - - - - - - - - - - - - - - - - - - - -

    nonce = os.urandom(12)
    send_message(nonce)
    print(f"\nIV: {base64.b64encode(nonce).decode('utf-8')}\n")

    cipher = Cipher(
        algorithm=algorithms.AES(session_key),
        mode=modes.GCM(nonce),
        backend=default_backend()
    )

    # CHATTING - - - - - - - - - - - - - - - - - - - - - - - - -

    while 1:
        message = input(">> ")
        if message == "exit()":
            break

        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()

        # encrypt
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag

        # exchange messages
        recv_ciphertext = send_message(ciphertext)
        recv_tag = send_message(tag)

        # decrypt
        decryptor.authenticate_additional_data(b"")
        recv_message = decryptor.update(recv_ciphertext) + decryptor.finalize_with_tag(recv_tag)

        print(f"\nSent ciphertext: {base64.b64encode(ciphertext).decode('utf-8')}")
        print(f"Sent tag: {base64.b64encode(tag).decode('utf-8')}")
        print(f"\nReceived ciphertext: {base64.b64encode(recv_ciphertext).decode('utf-8')}")
        print(f"Received tag: {base64.b64encode(recv_tag).decode('utf-8')}")

        print(f"\n<< {recv_message.decode('utf-8')}\n")

    # end

    client_socket.close()
