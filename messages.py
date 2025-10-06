"""
Message protocol definitions and JSON envelope handling for SOCP - Concise Version
"""

import json
import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

from crypto import RSACrypto, canonical_json_bytes


class MessageType(Enum):
    """SOCP protocol message types"""
    # Server <-> Server
    SERVER_HELLO_JOIN = "SERVER_HELLO_JOIN"
    SERVER_WELCOME = "SERVER_WELCOME"
    SERVER_ANNOUNCE = "SERVER_ANNOUNCE"
    USER_ADVERTISE = "USER_ADVERTISE"
    USER_REMOVE = "USER_REMOVE"
    SERVER_DELIVER = "SERVER_DELIVER"
    HEARTBEAT = "HEARTBEAT"

    # User <-> Server
    USER_HELLO = "USER_HELLO"
    MSG_DIRECT = "MSG_DIRECT"
    MSG_PUBLIC_CHANNEL = "MSG_PUBLIC_CHANNEL"
    USER_DELIVER = "USER_DELIVER"
    PUBLIC_CHANNEL_ADD = "PUBLIC_CHANNEL_ADD"
    PUBLIC_CHANNEL_UPDATED = "PUBLIC_CHANNEL_UPDATED"
    PUBLIC_CHANNEL_KEY_SHARE = "PUBLIC_CHANNEL_KEY_SHARE"

    # File Transfer
    FILE_START = "FILE_START"
    FILE_CHUNK = "FILE_CHUNK"
    FILE_END = "FILE_END"

    # Control
    ACK = "ACK"
    ERROR = "ERROR"
    CTRL_CLOSE = "CTRL_CLOSE"


class ErrorCode(Enum):
    """Standard SOCP error codes"""
    USER_NOT_FOUND = "USER_NOT_FOUND"
    INVALID_SIG = "INVALID_SIG"
    BAD_KEY = "BAD_KEY"
    TIMEOUT = "TIMEOUT"
    UNKNOWN_TYPE = "UNKNOWN_TYPE"
    NAME_IN_USE = "NAME_IN_USE"


@dataclass
class MessageEnvelope:
    """SOCP JSON message envelope"""
    type: str
    from_: str
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageEnvelope':
        """Parse from dictionary"""
        return cls(
            type=data["type"],
            from_=data["from"],
            to=data["to"],
            ts=data["ts"],
            payload=data["payload"],
            sig=data.get("sig")
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "type": self.type,
            "from": self.from_,
            "to": self.to,
            "ts": self.ts,
            "payload": self.payload
        }
        if self.sig:
            result["sig"] = self.sig
        return result

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_json(cls, json_str: str) -> 'MessageEnvelope':
        """Parse from JSON"""
        return cls.from_dict(json.loads(json_str))

    def sign(self, rsa_crypto: RSACrypto) -> None:
        """Sign payload with RSA-PSS"""
        payload_bytes = canonical_json_bytes(self.payload)
        self.sig = rsa_crypto.sign_pss(payload_bytes)

    def verify_signature(self, rsa_crypto: RSACrypto) -> bool:
        """Verify payload signature"""
        if not self.sig:
            return False
        payload_bytes = canonical_json_bytes(self.payload)
        return rsa_crypto.verify_pss(payload_bytes, self.sig)


def create_message(msg_type: MessageType, from_id: str, to_id: str,
                  payload: Dict[str, Any], rsa_crypto: Optional[RSACrypto] = None) -> MessageEnvelope:
    """Create message envelope with optional signature"""
    envelope = MessageEnvelope(
        type=msg_type.value,
        from_=from_id,
        to=to_id,
        ts=int(time.time() * 1000),
        payload=payload
    )

    if rsa_crypto:
        envelope.sign(rsa_crypto)

    return envelope


# Server Protocol Messages

def create_server_hello_join(server_id: str, introducer_addr: str,
                           host: str, port: int, pubkey: str) -> MessageEnvelope:
    """Create SERVER_HELLO_JOIN message"""
    return create_message(MessageType.SERVER_HELLO_JOIN, server_id, introducer_addr,
                         {"host": host, "port": port, "pubkey": pubkey})


def create_server_welcome(from_server: str, to_server: str, assigned_id: str,
                         clients: List[Dict[str, Any]], rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create SERVER_WELCOME message"""
    return create_message(MessageType.SERVER_WELCOME, from_server, to_server,
                         {"assigned_id": assigned_id, "clients": clients}, rsa_crypto)


def create_server_announce(server_id: str, host: str, port: int,
                          pubkey: str, rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create SERVER_ANNOUNCE message"""
    return create_message(MessageType.SERVER_ANNOUNCE, server_id, "*",
                         {"host": host, "port": port, "pubkey": pubkey}, rsa_crypto)


def create_user_advertise(server_id: str, user_id: str, server_for_user: str,
                         meta: Dict[str, Any], rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create USER_ADVERTISE message"""
    return create_message(MessageType.USER_ADVERTISE, server_id, "*",
                         {"user_id": user_id, "server_id": server_for_user, "meta": meta}, rsa_crypto)


def create_user_remove(server_id: str, user_id: str, server_for_user: str,
                      rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create USER_REMOVE message"""
    return create_message(MessageType.USER_REMOVE, server_id, "*",
                         {"user_id": user_id, "server_id": server_for_user}, rsa_crypto)


def create_server_deliver(sender_server: str, recipient_server: str, user_id: str,
                         ciphertext: str, sender: str, sender_pub: str, content_sig: str,
                         rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create SERVER_DELIVER message (SOCP v1.3 RSA-only)"""
    return create_message(MessageType.SERVER_DELIVER, sender_server, recipient_server, {
        "user_id": user_id, "ciphertext": ciphertext, "sender": sender,
        "sender_pub": sender_pub, "content_sig": content_sig
    }, rsa_crypto)


def create_heartbeat(from_server: str, to_server: str,
                    rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create HEARTBEAT message"""
    return create_message(MessageType.HEARTBEAT, from_server, to_server, {}, rsa_crypto)


# User Protocol Messages

def create_user_hello(user_id: str, server_id: str, client_info: str,
                     pubkey: str, enc_pubkey: str,
                     rsa_crypto: Optional[RSACrypto] = None) -> MessageEnvelope:
    """Create USER_HELLO message"""
    return create_message(MessageType.USER_HELLO, user_id, server_id, {
        "client": client_info, "pubkey": pubkey, "enc_pubkey": enc_pubkey
    }, rsa_crypto)


def create_msg_direct(sender: str, recipient: str, ciphertext: str, iv: str, tag: str,
                     wrapped_key: str, sender_pub: str, content_sig: str) -> MessageEnvelope:
    """Create MSG_DIRECT message with AES encryption"""
    return create_message(MessageType.MSG_DIRECT, sender, recipient, {
        "ciphertext": ciphertext, "iv": iv, "tag": tag, "wrapped_key": wrapped_key,
        "sender_pub": sender_pub, "content_sig": content_sig
    })


def create_user_deliver(server_id: str, recipient: str, ciphertext: str, iv: str, tag: str,
                       wrapped_key: str, sender: str, sender_pub: str, content_sig: str,
                       rsa_crypto: RSACrypto) -> MessageEnvelope:
    """Create USER_DELIVER message with AES encryption"""
    return create_message(MessageType.USER_DELIVER, server_id, recipient, {
        "ciphertext": ciphertext, "iv": iv, "tag": tag, "wrapped_key": wrapped_key,
        "sender": sender, "sender_pub": sender_pub, "content_sig": content_sig
    }, rsa_crypto)


def create_msg_public_channel(sender: str, channel_id: str, ciphertext: str, iv: str, tag: str,
                            sender_pub: str, content_sig: str) -> MessageEnvelope:
    """Create MSG_PUBLIC_CHANNEL message with AES encryption"""
    return create_message(MessageType.MSG_PUBLIC_CHANNEL, sender, channel_id, {
        "ciphertext": ciphertext, "iv": iv, "tag": tag, "sender_pub": sender_pub, "content_sig": content_sig
    })


# File Transfer Messages

def create_file_start(sender: str, recipient: str, file_id: str, name: str,
                     size: int, sha256_hash: str, mode: str) -> MessageEnvelope:
    """Create FILE_START message"""
    return create_message(MessageType.FILE_START, sender, recipient, {
        "file_id": file_id, "name": name, "size": size, "sha256": sha256_hash, "mode": mode
    })


def create_file_chunk(sender: str, recipient: str, file_id: str, index: int,
                     ciphertext: str) -> MessageEnvelope:
    """Create FILE_CHUNK message (SOCP v1.3 RSA-only)"""
    payload = {"file_id": file_id, "index": index, "ciphertext": ciphertext}
    return create_message(MessageType.FILE_CHUNK, sender, recipient, payload)


def create_file_end(sender: str, recipient: str, file_id: str) -> MessageEnvelope:
    """Create FILE_END message"""
    return create_message(MessageType.FILE_END, sender, recipient, {"file_id": file_id})


# Control Messages

def create_ack(from_id: str, to_id: str, msg_ref: str,
              rsa_crypto: Optional[RSACrypto] = None) -> MessageEnvelope:
    """Create ACK message"""
    return create_message(MessageType.ACK, from_id, to_id, {"msg_ref": msg_ref}, rsa_crypto)


def create_error(from_id: str, to_id: str, error_code: ErrorCode,
                detail: str, rsa_crypto: Optional[RSACrypto] = None) -> MessageEnvelope:
    """Create ERROR message"""
    return create_message(MessageType.ERROR, from_id, to_id, {
        "code": error_code.value, "detail": detail
    }, rsa_crypto)


def create_ctrl_close(from_id: str, to_id: str, reason: str = "Normal closure",
                     rsa_crypto: Optional[RSACrypto] = None) -> MessageEnvelope:
    """Create CTRL_CLOSE message (SOCP v1.3 transport requirement)"""
    return create_message(MessageType.CTRL_CLOSE, from_id, to_id, {
        "reason": reason
    }, rsa_crypto)


# Validation Functions

def validate_message_envelope(envelope: MessageEnvelope) -> bool:
    """Validate basic message envelope structure"""
    try:
        if not envelope.type or not envelope.from_ or not envelope.to:
            return False

        try:
            MessageType(envelope.type)
        except ValueError:
            return False

        now = int(time.time() * 1000)
        if abs(envelope.ts - now) > 24 * 60 * 60 * 1000:  # 24 hours
            return False

        return True
    except Exception:
        return False


def validate_user_id(user_id: str) -> bool:
    """Validate user ID format (UUID)"""
    try:
        uuid.UUID(user_id)
        return True
    except ValueError:
        return False


def validate_server_id(server_id: str) -> bool:
    """Validate server ID format (UUID)"""
    try:
        uuid.UUID(server_id)
        return True
    except ValueError:
        return False


class MessageRouter:
    """Message routing and validation"""

    def __init__(self, server_keys: Dict[str, RSACrypto], user_keys: Dict[str, RSACrypto]):
        self.server_keys = server_keys
        self.user_keys = user_keys

    def validate_and_route(self, envelope: MessageEnvelope) -> bool:
        """Validate signature and route message"""
        if not validate_message_envelope(envelope):
            return False

        # Server messages
        server_msg_types = [
            MessageType.SERVER_WELCOME.value, MessageType.SERVER_ANNOUNCE.value,
            MessageType.USER_ADVERTISE.value, MessageType.USER_REMOVE.value,
            MessageType.SERVER_DELIVER.value, MessageType.HEARTBEAT.value
        ]

        if envelope.type in server_msg_types:
            if envelope.from_ in self.server_keys:
                return envelope.verify_signature(self.server_keys[envelope.from_])

        # User messages
        user_msg_types = [MessageType.MSG_DIRECT.value, MessageType.MSG_PUBLIC_CHANNEL.value]

        if envelope.type in user_msg_types:
            if envelope.from_ in self.user_keys:
                return envelope.verify_signature(self.user_keys[envelope.from_])

        # Messages that may not require signatures
        return envelope.type in [MessageType.SERVER_HELLO_JOIN.value, MessageType.USER_HELLO.value]


# Utility Functions

def generate_message_id() -> str:
    """Generate unique message ID"""
    return str(uuid.uuid4())


def is_broadcast_message(envelope: MessageEnvelope) -> bool:
    """Check if message is broadcast (to="*")"""
    return envelope.to == "*"


def extract_content_from_encrypted_message(envelope: MessageEnvelope,
                                          recipient_rsa: RSACrypto) -> Optional[bytes]:
    """Extract and decrypt content from encrypted message with AES"""
    try:
        if envelope.type not in [MessageType.MSG_DIRECT.value, MessageType.USER_DELIVER.value]:
            return None

        payload = envelope.payload
        ciphertext = payload.get("ciphertext")
        iv = payload.get("iv")
        tag = payload.get("tag")
        wrapped_key = payload.get("wrapped_key")

        if not all([ciphertext, iv, tag, wrapped_key]):
            return None

        # Decrypt AES key with RSA
        aes_key = recipient_rsa.decrypt_oaep(wrapped_key)

        # Decrypt content with AES
        from crypto import AESCrypto
        aes_crypto = AESCrypto(aes_key)
        plaintext = aes_crypto.decrypt(ciphertext, iv, tag)
        return plaintext

    except Exception:
        return None