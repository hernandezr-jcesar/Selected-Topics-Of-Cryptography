
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import utils
from typing import List


def generate_key_pair(private_key_path: str, public_key_path: str):

    # KEY GENERATION

    private_key = ec.generate_private_key(
        curve=ec.SECP256R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # STORE KEYS

    with open(private_key_path, "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    with open(public_key_path, "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)


def sign_file(private_key_path: str, file_path: str, signature_path: str):

    # LOAD PRIVATE KEY

    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            data=private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    # READ FILE

    with open(file_path, "rb") as file:
        data = file.read()

    # CREATE SIGNATURE

    signature = private_key.sign(
        data=data,
        signature_algorithm=ec.ECDSA(hashes.SHA256())  # utils.Prehashed()
    )

    with open(signature_path, "wb") as signature_file:
        signature_file.write(base64.b64encode(signature))


def verify_signature(public_key_path: str, file_path: str, signature_path: str):

    # LOAD PUBLIC KEY

    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            data=public_key_file.read(),
            backend=default_backend()
        )

    # LOAD FILE

    with open(file_path, "rb") as file:
        data = file.read()

    # LOAD SIGNATURE

    with open(signature_path, "rb") as signature_file:
        signature = signature_file.read()

    # VERIFY SIGNATURE

    try:
        public_key.verify(
            signature=base64.b64decode(signature),
            data=data,
            signature_algorithm=ec.ECDSA(hashes.SHA256())
        )
        print("Valid signature")
    except InvalidSignature:
        print("Invalid signature")


if __name__ == "__main__":

    running = True
    working_directory = "./"

    while running:

        prompt: str = input("$ ")
        cmd: List[str] = prompt.split(" ")
        args = len(cmd)

        if cmd[0] == "exit":
            running = False

        elif cmd[0] == "setdir":
            working_directory = cmd[1]

        elif cmd[0] == "newpair":
            # default names
            pub_key_path = working_directory + "public.pem"
            priv_key_path = working_directory + "private.pem"

            # check if user specific
            if args > 1 and cmd[1] == "as":
                pub_key_path = working_directory + cmd[2] + "_public.pem"
                priv_key_path = working_directory + cmd[2] + "_private.pem"

            # generate
            generate_key_pair(
                private_key_path=priv_key_path,
                public_key_path=pub_key_path
            )

        elif cmd[0] == "sign":
            # set paths
            file_path = working_directory + cmd[1]
            priv_key_path = working_directory + cmd[3]

            # sign
            sign_file(
                private_key_path=priv_key_path,
                file_path=file_path,
                signature_path=f"{file_path}.sign"
            )

        elif cmd[0] == "verify":
            # set paths
            file_path = working_directory + cmd[1]
            pub_key_path = working_directory + cmd[3]

            # verify
            verify_signature(
                public_key_path=pub_key_path,
                file_path=file_path,
                signature_path=f"{file_path}.sign"
            )

        elif cmd[0] == "help":
            print("\n - - - Commands Syntax - - - \n")
            print("newpair [as <prefix>]")
            print("sign <file> with <key>")
            print("verify <file> with <key>")
            print("setdir <path>")
            print("exit\n")

        else:
            print("Invalid Command. Try Again.")
