"""
Cryptographic utilities for SOCP protocol
Implements RSA-4096, AES-256-GCM, and required signature schemes
"""

import base64
import hashlib
import json
import os
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(data: str) -> bytes:
    pad = '=' * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)

def sha256_b64url(data: bytes) -> str:
    return b64url_encode(hashlib.sha256(data).digest())

def sha256_hash(data: bytes) -> str:
    # For debugging only (do NOT put hex into JSON if the spec requires base64url)
    return hashlib.sha256(data).hexdigest()

def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _ensure_rsa4096(key_obj):
    # Works for both private and public key objects
    try:
        size = key_obj.key_size  # private keys have this
    except AttributeError:
        size = key_obj.public_numbers().n.bit_length()  # public key
    if size != 4096:
        raise ValueError(f"RSA key size must be 4096 bits, got {size}")


class RSACrypto:
    """RSA-4096 cryptographic operations (RSA-OAEP SHA-256, RSASSA-PSS SHA-256)."""

    def __init__(self, private_key: Optional[RSAPrivateKey] = None):
        self.private_key: Optional[RSAPrivateKey] = None
        self.public_key: Optional[RSAPublicKey] = None
        if private_key is not None:
            _ensure_rsa4096(private_key)
            self.private_key = private_key
            self.public_key = private_key.public_key()

    @classmethod
    def generate_keypair(cls) -> 'RSACrypto':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        return cls(private_key)

    @classmethod
    def from_private_pem(cls, pem_data: str, password: Optional[bytes] = None) -> 'RSACrypto':
        private_key = serialization.load_pem_private_key(pem_data.encode(), password=password)
        _ensure_rsa4096(private_key)
        return cls(private_key)

    @classmethod
    def from_public_b64url(cls, b64url_key: str) -> 'RSACrypto':
        key_data = b64url_decode(b64url_key)
        public_key = serialization.load_der_public_key(key_data)
        _ensure_rsa4096(public_key)
        obj = cls()
        obj.public_key = public_key
        return obj

    def get_public_key_b64url(self) -> str:
        if not self.public_key:
            raise ValueError("Public key not set")
        der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return b64url_encode(der)

    def get_private_key_pem(self, password: Optional[bytes] = None) -> str:
        if not self.private_key:
            raise ValueError("Private key not set")
        enc = serialization.NoEncryption() if not password else serialization.BestAvailableEncryption(password)
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )
        return pem.decode()

    def sign_pss(self, data: bytes) -> str:
        if not self.private_key:
            raise ValueError("Private key required for signing")
        sig = self.private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return b64url_encode(sig)

    def verify_pss(self, data: bytes, signature_b64url: str) -> bool:
        if not self.public_key:
            raise ValueError("Public key not set")
        try:
            sig = b64url_decode(signature_b64url)
            self.public_key.verify(
                sig,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def encrypt_oaep(self, data: bytes) -> str:
        if not self.public_key:
            raise ValueError("Public key not set")
        ct = self.public_key.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return b64url_encode(ct)

    def decrypt_oaep(self, ciphertext_b64url: str) -> bytes:
        if not self.private_key:
            raise ValueError("Private key required for decryption")
        ct = b64url_decode(ciphertext_b64url)
        return self.private_key.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )


class AESCrypto:
    """AES-256-GCM operations"""

    def __init__(self, key: Optional[bytes] = None):
        if key:
            if len(key) != 32:
                raise ValueError("AES key must be 32 bytes")
            self.key = key
        else:
            self.key = AESGCM.generate_key(bit_length=256)

    @classmethod
    def from_b64url(cls, key_b64url: str) -> 'AESCrypto':
        """Load from base64url key"""
        key = b64url_decode(key_b64url)
        return cls(key)

    def get_key_b64url(self) -> str:
        """Export key as base64url"""
        return b64url_encode(self.key)

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[str, str, str]:
        """
        Encrypt with AES-256-GCM
        Returns: (ciphertext_b64url, iv_b64url, tag_b64url)
        """
        iv = os.urandom(12)  # 96-bit IV for GCM
        aesgcm = AESGCM(self.key)

        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        return (
            b64url_encode(ciphertext),
            b64url_encode(iv),
            b64url_encode(tag)
        )

    def decrypt(self, ciphertext_b64url: str, iv_b64url: str, tag_b64url: str,
                associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt with AES-256-GCM"""
        ciphertext = b64url_decode(ciphertext_b64url)
        iv = b64url_decode(iv_b64url)
        tag = b64url_decode(tag_b64url)

        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, associated_data)
        return plaintext




def create_content_signature_data(message_type: str, **kwargs) -> bytes:
    """
    Return bytes to be signed with RSASSA-PSS (SHA-256).
    SOCP v1.3 RSA-only design: no AES IVs, tags, or wrapped keys.
    """
    if message_type == "MSG_DIRECT":
        required = ['ciphertext', 'from', 'to', 'ts']
    elif message_type == "MSG_PUBLIC_CHANNEL":
        required = ['ciphertext', 'from', 'ts']
    elif message_type == "PUBLIC_CHANNEL_KEY_SHARE":
        required = ['shares', 'creator_pub']
    else:
        raise ValueError(f"Unknown message type: {message_type}")
    return '|'.join(str(kwargs[k]) for k in required).encode('utf-8')


class SOCPCrypto:
    """
    SOCP v1.3 RSA-only cryptographic operations
    Replaces hybrid AES+RSA approach with pure RSA-4096
    """

    def __init__(self, private_key: Optional[RSAPrivateKey] = None):
        self.rsa_crypto = RSACrypto(private_key)

    def encrypt_message_content(self, plaintext: str, recipient_pubkey_b64url: str) -> str:
        """
        Encrypt message content using RSA-4096 OAEP only (SOCP v1.3)
        Returns base64url encoded ciphertext
        """
        recipient_crypto = RSACrypto.from_public_b64url(recipient_pubkey_b64url)
        return recipient_crypto.encrypt_oaep(plaintext.encode('utf-8'))

    def decrypt_message_content(self, ciphertext_b64url: str) -> str:
        """
        Decrypt message content using RSA-4096 OAEP only (SOCP v1.3)
        Returns plaintext string
        """
        plaintext_bytes = self.rsa_crypto.decrypt_oaep(ciphertext_b64url)
        return plaintext_bytes.decode('utf-8')

    def sign_message_content(self, message_type: str, **kwargs) -> str:
        """
        Create content signature for message using RSASSA-PSS SHA-256
        """
        content_data = create_content_signature_data(message_type, **kwargs)
        return self.rsa_crypto.sign_pss(content_data)

    def verify_message_content(self, message_type: str, signature_b64url: str, sender_pubkey_b64url: str, **kwargs) -> bool:
        """
        Verify content signature using sender's public key
        """
        sender_crypto = RSACrypto.from_public_b64url(sender_pubkey_b64url)
        content_data = create_content_signature_data(message_type, **kwargs)
        return sender_crypto.verify_pss(content_data, signature_b64url)


def encrypt_file_chunk_rsa_only(chunk_data: bytes, recipient_pubkey_b64url: str) -> str:
    """
    SOCP v1.3: Encrypt file chunk using RSA-4096 OAEP only
    Returns base64url encoded ciphertext
    """
    recipient_crypto = RSACrypto.from_public_b64url(recipient_pubkey_b64url)
    return recipient_crypto.encrypt_oaep(chunk_data)


def decrypt_file_chunk_rsa_only(ciphertext_b64url: str, private_crypto: RSACrypto) -> bytes:
    """
    SOCP v1.3: Decrypt file chunk using RSA-4096 OAEP only
    Returns original chunk data
    """
    return private_crypto.decrypt_oaep(ciphertext_b64url)