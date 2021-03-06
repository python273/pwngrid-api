from __future__ import annotations
import binascii
import os
from typing import Any, Union, Tuple, Dict
import enum

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pwngrid_api.version import version


def get_sha256_hexdigest(b: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(b)
    return binascii.b2a_hex(digest.finalize())


def get_pub_key_pem(public_key: RSAPublicKey) -> str:
    pub_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).strip()

    pub_key_pem = pub_key_pem.replace(
        b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN RSA PUBLIC KEY-----"
    ).replace(b"-----END PUBLIC KEY-----", b"-----END RSA PUBLIC KEY-----")

    return pub_key_pem.decode("ascii")


def get_pub_key_pem_b64(*args, **kwargs) -> str:
    pub_key_pem = get_pub_key_pem(*args, **kwargs)
    pub_key_pem_b64 = binascii.b2a_base64(pub_key_pem.encode("ascii")).strip()
    return pub_key_pem_b64.decode("ascii")


def sign(private_key: RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=16),
        algorithm=hashes.SHA256(),
    )


def sign_b64(*args, **kwargs) -> str:
    return binascii.b2a_base64(sign(*args, **kwargs)).decode("ascii").strip()


def get_fingerprint_from_pem(public_key_pem) -> str:
    return get_sha256_hexdigest(public_key_pem.strip()).decode("ascii")


def get_fingerprint(public_key: RSAPublicKey) -> str:
    return get_fingerprint_from_pem(get_pub_key_pem(public_key).encode("ascii"))


def encrypt(
    key: bytes, plaintext: bytes, associated_data: bytes
) -> Tuple[bytes, bytes, bytes]:
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()

    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


def decrypt(
    key: bytes, associated_data: bytes, iv: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    return decryptor.update(ciphertext) + decryptor.finalize()


class MessageMark(enum.Enum):
    SEEN = "seen"
    UNSEEN = "unseen"
    DELETED = "deleted"
    RESTORED = "restored"


class PwngridException(Exception):
    pass


class PwngridSecurityError(PwngridException):
    pass


class PwngridClientError(PwngridException):
    def __init__(self, message: str, error: Any, response: Any):
        super().__init__(message)

        self.error = error
        self.response = response


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
    def from_api_data(cls, fingerprint: str, data: dict):
        data_public_key_fingerprint = get_fingerprint_from_pem(
            data["public_key"].encode("ascii")
        )

        if fingerprint != data_public_key_fingerprint:
            raise PwngridSecurityError(
                "Public key fingerprint DOES NOT match requested fingerprint!"
                " Possible MITM?"
            )

        public_key = serialization.load_pem_public_key(
            data["public_key"]
            .encode("ascii")
            .replace(b" RSA PUBLIC KEY", b" PUBLIC KEY"),
            backend=default_backend(),
        )

        return Unit(hostname=data["name"], public_key=public_key)

    def sign(self, data: bytes) -> bytes:
        if not self.private_key:
            raise PwngridException("No private key")

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
            raise PwngridException("No private key")

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
            raise PwngridException("No private key")

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
            raise PwngridException("No private key")

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
    def __init__(self, token=None, refresh_token_fn=None):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"pwngrid-api python ({version})"

        if token:
            self.set_token(token)

        self.refresh_token_fn = refresh_token_fn

    def set_token(self, token: str):
        self.session.headers.update({"Authorization": f"token {token}"})

    def __call__(self, method: str, path: str, *args, **kwargs) -> Any:
        url = f"https://api.pwnagotchi.ai/api/{path}"
        response = self.session.request(method, url, **kwargs)

        try:
            json_data = response.json()
        except:
            json_data = None

        not_ok = not response.ok or (
            isinstance(json_data, dict) and "error" in json_data
        )
        if not_ok:
            if response.status_code == 401 and self.refresh_token_fn:
                self.refresh_token_fn()
                return self(method, path, *args, **kwargs)

            error = json_data.get("error") if isinstance(json_data, dict) else None
            code = error if error else "error (no error key in response)"
            raise PwngridClientError(
                f"[{response.status_code}] {code}", error=error, response=response
            )

        if json_data is None:
            text = response.text[:50]
            dots = "" if len(response.text) <= 50 else "..."
            raise PwngridClientError(
                f'no json data: "{text}{dots}"', error="no JSON data", response=response
            )

        return json_data


class PwngridClient:
    _units_cache: Dict[str, Unit] = {}

    def __init__(self, hostname: str, private_key: RSAPrivateKey):
        self.hostname = hostname
        self.unit = Unit(hostname, private_key.public_key(), private_key)
        self.session = PwngridSession(refresh_token_fn=self._refresh_session_token)

    def clear_units_cache(self):
        self._units_cache = {}

    def enroll(self, data=None):
        """Register or get a new token for a unit."""
        if data is None:
            data = {}

        enroll_data = {
            "identity": self.unit.identity,
            "public_key": get_pub_key_pem_b64(self.unit.public_key),
            "signature": sign_b64(
                self.unit.private_key, self.unit.identity.encode("ascii")
            ),
            "data": data,
        }

        r = self.session("POST", "v1/unit/enroll", json=enroll_data)
        token = r["token"]

        self.session.set_token(token)

    def _refresh_session_token(self):
        self.enroll()

    def get_units(self, page: int = None) -> dict:
        return self.session("GET", "v1/units", params={"p": page})

    def get_units_by_country(self) -> list:
        return self.session("GET", "v1/units/by_country")

    def get_inbox(self, page: int = None) -> dict:
        return self.session("GET", "v1/unit/inbox", params={"p": page})

    def mark_message(self, message_id: int, mark: Union[str, MessageMark]) -> dict:
        """Mark a message as seen/deleted/etc."""
        if isinstance(mark, MessageMark):
            mark = mark.value

        return self.session("GET", f"v1/unit/inbox/{message_id}/{mark}")

    def report_ap(self, essid: str, bssid: str) -> dict:
        return self.session(
            "POST", "v1/unit/report/ap", json={"essid": essid, "bssid": bssid}
        )

    def get_unit_by_fingerprint(
        self, fingerprint: str, ignore_cache: bool = False
    ) -> Unit:
        """Load unit data by fingerprint. Units are cached in `self._unit_cache`,
        if you want to ignore cached units, use `ignore_cache` argument.
        """
        if "@" in fingerprint:
            fingerprint = fingerprint.split("@", 1)[-1]

        if not ignore_cache:
            cached_unit = self._units_cache.get(fingerprint)
            if cached_unit:
                return cached_unit

        unit_data = self.session("GET", f"v1/unit/{fingerprint}")
        unit = Unit.from_api_data(fingerprint, unit_data)
        self._units_cache[fingerprint] = unit
        return unit

    def read_message(self, message_id: int) -> Tuple[Any, bytes, Unit]:
        """Read an e2e encrypted message."""
        message = self.session("GET", f"v1/unit/inbox/{message_id}")

        data = binascii.a2b_base64(message["data"])
        signature = binascii.a2b_base64(message["signature"])

        sender = self.get_unit_by_fingerprint(message["sender"])
        plaintext = self.unit.decrypt_message(sender, data, signature)

        return message, plaintext, sender

    def send_message(self, recipient: Union[str, Unit], cleartext: bytes) -> dict:
        """Send an e2e encrypted message to a unit."""
        if not isinstance(recipient, Unit):
            recipient = self.get_unit_by_fingerprint(recipient)

        ciphertext, signature = self.unit.encrypt_message(recipient, cleartext)

        response = self.session(
            "POST",
            f"v1/unit/{recipient.fingerprint}/inbox",
            json={
                "data": binascii.b2a_base64(ciphertext).decode("ascii"),
                "signature": binascii.b2a_base64(signature).decode("ascii"),
            },
        )
        return response
