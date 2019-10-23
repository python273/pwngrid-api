from __future__ import annotations
import binascii
import hashlib
import os
import typing
from typing import Union, Tuple

import requests
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_sha256_hexdigest(b):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(b)
    return binascii.b2a_hex(digest.finalize())


def get_pub_key_pem(public_key):
    pub_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).strip()

    pub_key_pem = pub_key_pem.replace(
        b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN RSA PUBLIC KEY-----"
    ).replace(b"-----END PUBLIC KEY-----", b"-----END RSA PUBLIC KEY-----")

    return pub_key_pem.decode("ascii")


def get_pub_key_pem_b64(*args, **kwargs):
    pub_key_pem = get_pub_key_pem(*args, **kwargs)
    pub_key_pem_b64 = binascii.b2a_base64(pub_key_pem.encode("ascii")).strip()
    return pub_key_pem_b64.decode("ascii")


def sign(private_key, data):
    return private_key.sign(
        data,
        padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=16),
        algorithm=hashes.SHA256(),
    )


def sign_b64(*args, **kwargs):
    return binascii.b2a_base64(sign(*args, **kwargs)).decode("ascii").strip()


def get_fingerprint_from_pem(public_key_pem):
    return get_sha256_hexdigest(public_key_pem.strip()).decode("ascii")


def get_fingerprint(public_key):
    return get_fingerprint_from_pem(get_pub_key_pem(public_key).encode("ascii"))


def encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()

    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)


def decrypt(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    return decryptor.update(ciphertext) + decryptor.finalize()


class Unit:
    def __init__(self, hostname, public_key, private_key=None):
        self.hostname = hostname
        self.public_key = public_key
        self.private_key = private_key

    @property
    def fingerprint(self) -> str:
        return get_fingerprint(self.public_key)

    @property
    def identity(self) -> str:
        return f"{self.hostname}@{self.fingerprint}"

    @classmethod
    def from_api_data(cls, fingerprint: str, data: dict) -> Unit:
        data_public_key_fingerprint = get_fingerprint_from_pem(
            data["public_key"].encode("ascii")
        )

        if fingerprint != data_public_key_fingerprint:
            raise Exception("MITM")

        public_key = serialization.load_pem_public_key(
            data["public_key"]
            .encode("ascii")
            .replace(b" RSA PUBLIC KEY", b" PUBLIC KEY"),
            backend=default_backend(),
        )

        return Unit(hostname=data["name"], public_key=public_key)

    def sign(self, data: bytes) -> bytes:
        if not self.private_key:
            raise Exception("No private key")

        return self.private_key.sign(
            data,
            padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=16),
            algorithm=hashes.SHA256(),
        )

    def verify(self, signature: bytes, message: bytes):
        """Raises an exception if invalid or other reasons."""
        self.public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=16),
            hashes.SHA256(),
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.private_key:
            raise Exception("No private key")

        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt_message(self, from_unit: Unit, data: bytes, signature: bytes) -> bytes:
        if not self.private_key:
            raise Exception("No private key")

        from_unit.verify(signature, data)

        iv = data[0:12]
        key_buffer_len = int.from_bytes(data[12 : 12 + 4], byteorder="little")
        key_buffer = data[12 + 4 : 12 + 4 + key_buffer_len]
        ciphertext = data[12 + 4 + key_buffer_len : -16]
        tag = data[-16:]

        key = self.decrypt(key_buffer)

        plaintext = decrypt(
            key=key, associated_data=b"", iv=iv, ciphertext=ciphertext, tag=tag
        )

        return plaintext

    def encrypt_message(self, to_unit: Unit, plaintext: bytes) -> Tuple[bytes, bytes]:
        if not self.private_key:
            raise Exception("No private key")

        key = os.urandom(16)
        key_encrypted = to_unit.encrypt(key)

        iv, ciphertext, tag = encrypt(key=key, plaintext=plaintext, associated_data=b"")

        data = (
            iv
            + len(key_encrypted).to_bytes(4, byteorder="little")
            + key_encrypted
            + ciphertext
            + tag
        )

        signature = self.sign(data)

        return data, signature

    def __str__(self):
        return f"<Unit {self.identity}>"


class PwngridSession:
    def __init__(self, token=None):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "pwngrid-api-client"

        if token:
            self.set_token(token)

    def set_token(self, token):
        self.session.headers.update({"Authorization": f"token {token}"})

    def __call__(self, method, path, *args, **kwargs):
        url = f"https://api.pwnagotchi.ai/api/{path}"
        return self.session.request(method, url, **kwargs).json()


class PwngridClient:
    def __init__(self, hostname: str, private_key):
        self.hostname = hostname
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.unit = Unit(hostname, self.public_key, self.private_key)

        self.session = PwngridSession()

    def enroll(self):
        enroll_data = {
            "identity": self.unit.identity,
            "public_key": get_pub_key_pem_b64(self.unit.public_key),
            "signature": sign_b64(self.private_key, self.unit.identity.encode("ascii")),
            "data": {"dunno": 1},
        }

        r = self.session("POST", "v1/unit/enroll", json=enroll_data)
        token = r["token"]

        self.session.set_token(token)

    def get_units(self, page: int = None) -> dict:
        return self.session("GET", "v1/units", params={"p": page})

    def get_units_by_country(self) -> list:
        return self.session("GET", "v1/units/by_country")

    def get_inbox(self, page: int = None) -> dict:
        return self.session("GET", "v1/unit/inbox", params={"p": page})

    def mark_message(self, id: int, mark: str) -> dict:
        return self.session("GET", "v1/unit/inbox/{id}/{mark}")

    def report_ap(self, essid: str, bssid: str):
        return self.session(
            "POST", "v1/unit/report/ap", json={"essid": essid, "bssid": bssid}
        )

    def get_unit_by_fingerprint(self, fingerprint: str) -> Unit:
        r = self.session("GET", f"v1/unit/{fingerprint}")
        return Unit.from_api_data(fingerprint, r)

    def read_message(self, id: int) -> Tuple[dict, bytes]:
        r = self.session("GET", f"v1/unit/inbox/{id}")
        message = r

        data = binascii.a2b_base64(message["data"])
        signature = binascii.a2b_base64(message["signature"])

        sender = self.get_unit_by_fingerprint(message["sender"])
        plaintext = self.unit.decrypt_message(sender, data, signature)

        return message, plaintext

    def send_message(self, recipient: Union[str, Unit], cleartext: bytes) -> dict:
        if not isinstance(recipient, Unit):
            recipient = self.get_unit_by_fingerprint(recipient)

        ciphertext, signature = self.unit.encrypt_message(recipient, cleartext)

        r = self.session(
            "POST",
            f"v1/unit/{recipient.fingerprint}/inbox",
            json={
                "data": binascii.b2a_base64(ciphertext).decode("ascii"),
                "signature": binascii.b2a_base64(signature).decode("ascii"),
            },
        )
        return r
