"""
Database layer for SOCP server - Concise Version
Implements user management, group management, and persistent storage
"""

import sqlite3
import json
import hashlib
import uuid
import argon2
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path

from crypto import RSACrypto, AESCrypto


@dataclass
class User:
    user_id: str
    pubkey: str
    privkey_store: str
    pake_password: str
    meta: Optional[Dict[str, Any]] = None
    version: int = 1


@dataclass
class Group:
    group_id: str
    creator_id: str
    created_at: int
    meta: Optional[Dict[str, Any]] = None
    version: int = 1


@dataclass
class GroupMember:
    group_id: str
    member_id: str
    role: str = "member"
    wrapped_key: str = ""
    added_at: int = 0


class Database:
    """SOCP database implementation using SQLite"""

    def __init__(self, db_path: str = "socp.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()
        self.ph = argon2.PasswordHasher()

    def _init_tables(self):
        """Initialize database tables"""
        cursor = self.conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                privkey_store TEXT NOT NULL,
                pake_password TEXT NOT NULL,
                meta TEXT,
                version INTEGER NOT NULL DEFAULT 1
            )
        ''')

        # Groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                creator_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                meta TEXT,
                version INTEGER NOT NULL DEFAULT 1
            )
        ''')

        # Group members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                wrapped_key TEXT NOT NULL,
                added_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, member_id)
            )
        ''')

        # Username mapping table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usernames (
                username TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')

        # Server state table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
        ''')

        self.conn.commit()

    def close(self):
        """Close database connection"""
        self.conn.close()

    # User management

    def register_user(self, user_id: str, password: str, rsa_keypair: RSACrypto,
                     meta: Optional[Dict[str, Any]] = None, username: Optional[str] = None) -> bool:
        """Register a new user with password-protected private key"""
        try:
            if self.get_user(user_id):
                return False

            # Check if username is already taken
            if username and self.get_user_id_by_username(username):
                return False

            # SOCP v1.3: Create PAKE verifier/salted hash using Argon2
            pake_password = self.ph.hash(password)
            # Derive key for private key encryption using PBKDF2
            password_key = self._derive_key_from_password(password, user_id)
            aes_crypto = AESCrypto(password_key)

            private_pem = rsa_keypair.get_private_key_pem()
            ciphertext, iv, tag = aes_crypto.encrypt(private_pem.encode())

            privkey_store = json.dumps({"ciphertext": ciphertext, "iv": iv, "tag": tag})
            pubkey = rsa_keypair.get_public_key_b64url()

            # Insert user
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, pubkey, privkey_store, pake_password,
                  json.dumps(meta) if meta else None, 1))

            # Insert username mapping if provided
            if username:
                cursor.execute('''
                    INSERT INTO usernames (username, user_id)
                    VALUES (?, ?)
                ''', (username, user_id))

            self.conn.commit()
            return True

        except Exception:
            return False

    def authenticate_user(self, user_id: str, password: str) -> Optional[RSACrypto]:
        """Authenticate user and return their RSA keypair"""
        try:
            user = self.get_user(user_id)
            if not user:
                return None

            # SOCP v1.3: Verify password against PAKE verifier/salted hash
            self.ph.verify(user.pake_password, password)

            # Decrypt private key
            password_key = self._derive_key_from_password(password, user_id)
            aes_crypto = AESCrypto(password_key)

            privkey_data = json.loads(user.privkey_store)
            private_pem = aes_crypto.decrypt(
                privkey_data["ciphertext"],
                privkey_data["iv"],
                privkey_data["tag"]
            ).decode()

            return RSACrypto.from_private_pem(private_pem)

        except Exception:
            return None

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()

        if row:
            return User(
                user_id=row['user_id'],
                pubkey=row['pubkey'],
                privkey_store=row['privkey_store'],
                pake_password=row['pake_password'],
                meta=json.loads(row['meta']) if row['meta'] else None,
                version=row['version']
            )
        return None

    def get_user_pubkey(self, user_id: str) -> Optional[str]:
        """Get user's public key"""
        user = self.get_user(user_id)
        return user.pubkey if user else None

    def list_users(self) -> List[str]:
        """List all user IDs"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT user_id FROM users ORDER BY user_id')
        return [row['user_id'] for row in cursor.fetchall()]

    def get_user_id_by_username(self, username: str) -> Optional[str]:
        """Get user ID by username"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT user_id FROM usernames WHERE username = ?', (username,))
        row = cursor.fetchone()
        return row['user_id'] if row else None

    def get_username_by_user_id(self, user_id: str) -> Optional[str]:
        """Get username by user ID"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT username FROM usernames WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        return row['username'] if row else None

    def authenticate_user_by_username(self, username: str, password: str) -> Optional[RSACrypto]:
        """Authenticate user by username and return their RSA keypair"""
        user_id = self.get_user_id_by_username(username)
        if not user_id:
            return None
        return self.authenticate_user(user_id, password)

    # Group management

    def create_group(self, group_id: str, creator_id: str,
                    meta: Optional[Dict[str, Any]] = None) -> bool:
        """Create a new group"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                VALUES (?, ?, ?, ?, ?)
            ''', (group_id, creator_id, int(time.time() * 1000),
                  json.dumps(meta) if meta else None, 1))
            self.conn.commit()
            return True
        except Exception:
            return False

    def get_group(self, group_id: str) -> Optional[Group]:
        """Get group by ID"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM groups WHERE group_id = ?', (group_id,))
        row = cursor.fetchone()

        if row:
            return Group(
                group_id=row['group_id'],
                creator_id=row['creator_id'],
                created_at=row['created_at'],
                meta=json.loads(row['meta']) if row['meta'] else None,
                version=row['version']
            )
        return None

    def add_group_member(self, group_id: str, member_id: str, wrapped_key: str,
                        role: str = "member") -> bool:
        """Add member to group"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO group_members
                (group_id, member_id, role, wrapped_key, added_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (group_id, member_id, role, wrapped_key, int(time.time() * 1000)))

            # Bump group version
            cursor.execute('UPDATE groups SET version = version + 1 WHERE group_id = ?', (group_id,))
            self.conn.commit()
            return True
        except Exception:
            return False

    def get_group_members(self, group_id: str) -> List[GroupMember]:
        """Get all members of a group"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM group_members WHERE group_id = ? ORDER BY added_at', (group_id,))

        return [GroupMember(
            group_id=row['group_id'],
            member_id=row['member_id'],
            role=row['role'],
            wrapped_key=row['wrapped_key'],
            added_at=row['added_at']
        ) for row in cursor.fetchall()]

    def get_member_wrapped_key(self, group_id: str, member_id: str) -> Optional[str]:
        """Get member's wrapped group key"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT wrapped_key FROM group_members
            WHERE group_id = ? AND member_id = ?
        ''', (group_id, member_id))
        row = cursor.fetchone()
        return row['wrapped_key'] if row else None

    def is_group_member(self, group_id: str, member_id: str) -> bool:
        """Check if user is member of group"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT 1 FROM group_members WHERE group_id = ? AND member_id = ?
        ''', (group_id, member_id))
        return cursor.fetchone() is not None

    # Public channel management

    def init_public_channel(self, server_id: str) -> bool:
        """Initialize public channel for this server"""
        return self.create_group(
            group_id="public",
            creator_id="system",
            meta={"title": "Public Channel", "type": "public"}
        )

    def add_user_to_public_channel(self, user_id: str, wrapped_key: str) -> bool:
        """Add user to public channel"""
        return self.add_group_member("public", user_id, wrapped_key, "member")

    def get_public_channel_members(self) -> List[str]:
        """Get all public channel members"""
        members = self.get_group_members("public")
        return [m.member_id for m in members]

    # Server state management

    def set_server_state(self, key: str, value: Any) -> bool:
        """Set server state value"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO server_state (key, value, updated_at)
                VALUES (?, ?, ?)
            ''', (key, json.dumps(value), int(time.time() * 1000)))
            self.conn.commit()
            return True
        except Exception:
            return False

    def get_server_state(self, key: str) -> Optional[Any]:
        """Get server state value"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT value FROM server_state WHERE key = ?', (key,))
        row = cursor.fetchone()
        return json.loads(row['value']) if row else None

    def get_server_id(self) -> Optional[str]:
        """Get this server's ID"""
        return self.get_server_state('server_id')

    def set_server_id(self, server_id: str) -> bool:
        """Set this server's ID"""
        return self.set_server_state('server_id', server_id)

    # Utility methods

    def _derive_key_from_password(self, password: str, salt: str) -> bytes:
        """Derive AES key from password using PBKDF2"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)

    def get_pubkey(self, user_id: str) -> Optional[Tuple[str, str]]:
        """Get user public key with directory signature"""
        user = self.get_user(user_id)
        return (user.pubkey, "") if user else None

    # Statistics

    def get_user_count(self) -> int:
        """Get total user count"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM users')
        return cursor.fetchone()['count']

    def get_group_count(self) -> int:
        """Get total group count"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM groups')
        return cursor.fetchone()['count']


def create_database(db_path: str = "socp.db") -> Database:
    """Create and initialize SOCP database"""
    db = Database(db_path)

    # Initialize public channel if it doesn't exist
    if not db.get_group("public"):
        db.init_public_channel("system")

    return db


def create_test_users(db: Database, count: int = 3) -> List[Tuple[str, RSACrypto]]:
    """Create test users for development"""
    users = []

    for i in range(count):
        user_id = str(uuid.uuid4())
        password = f"password{i}"
        keypair = RSACrypto.generate_keypair()

        meta = {
            "display_name": f"TestUser{i}",
            "pronouns": "they/them" if i % 2 else "she/her",
            "age": 20 + i,
            "extras": {"test": True}
        }

        if db.register_user(user_id, password, keypair, meta):
            users.append((user_id, keypair))

    return users


if __name__ == "__main__":
    # Test the database
    db = create_database("test.db")
    test_users = create_test_users(db, 2)
    print(f"Created {len(test_users)} test users")

    for user_id, keypair in test_users:
        print(f"User: {user_id}")
        user = db.get_user(user_id)
        print(f"  Meta: {user.meta}")

        # Test authentication
        auth_keypair = db.authenticate_user(user_id, f"password{test_users.index((user_id, keypair))}")
        print(f"  Auth: {'SUCCESS' if auth_keypair else 'FAILED'}")

    db.close()