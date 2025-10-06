#!/usr/bin/env python3
"""
SOCP Web Client - Browser-based interface for secure messaging
"""

from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_socketio import SocketIO, emit
import asyncio
import websockets
import json
import threading
import queue
import time
from datetime import datetime
import os
import uuid
import hashlib
import base64
import mimetypes
from typing import Optional, Dict, Any
from werkzeug.utils import secure_filename
import argon2

from crypto import RSACrypto, AESCrypto, create_content_signature_data
from messages import *
from database import create_database
import re

def validate_password_server(password: str) -> list:
    """
    Server-side password validation - matches frontend requirements
    Returns list of error messages, empty list if valid
    """
    errors = []

    # Minimum length requirement
    if len(password) < 8:
        errors.append('at least 8 characters')

    # Maximum length to prevent DoS
    if len(password) > 128:
        errors.append('no more than 128 characters')

    # Must contain at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append('one uppercase letter')

    # Must contain at least one lowercase letter
    if not re.search(r'[a-z]', password):
        errors.append('one lowercase letter')

    # Must contain at least one number
    if not re.search(r'[0-9]', password):
        errors.append('one number')

    # Must contain at least one special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append('one special character (!@#$%^&*()_+-=[]{};\':"|,.<>?/)')

    return errors

app = Flask(__name__)
app.config['SECRET_KEY'] = 'socp-web-client-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

class UserSession:
    """Individual user session with dedicated SOCP connection"""
    def __init__(self, user_id: str, user_keypair: RSACrypto, socket_id: str, client_ref=None):
        self.user_id = user_id
        self.user_keypair = user_keypair
        self.socket_id = socket_id
        self.last_activity = time.time()
        self.socp_websocket = None  # Individual SOCP connection
        self.connected_to_socp = False
        self.message_queue = queue.Queue()
        self.client_ref = client_ref  # Reference to the global client

    async def connect_to_socp(self, host: str, port: int):
        """Create individual SOCP connection for this user"""
        try:
            import websockets
            self.socp_websocket = await websockets.connect(f"ws://{host}:{port}")

            # Send USER_HELLO for this specific user
            hello_message = {
                "type": "USER_HELLO",
                "from": self.user_id,
                "to": "server",
                "ts": int(time.time() * 1000),
                "payload": {
                    "client": "web-v1",
                    "pubkey": self.user_keypair.get_public_key_b64url(),
                    "enc_pubkey": self.user_keypair.get_public_key_b64url()
                },
                "sig": ""
            }

            await self.socp_websocket.send(json.dumps(hello_message))
            print(f"✅ {self.user_id} connected to SOCP server")
            self.connected_to_socp = True

            # Start listening for messages
            asyncio.create_task(self.listen_for_messages())

        except Exception as e:
            print(f"❌ {self.user_id} failed to connect to SOCP: {e}")
            self.connected_to_socp = False

    async def listen_for_messages(self):
        """Listen for messages from SOCP server"""
        try:
            async for message in self.socp_websocket:
                data = json.loads(message)
                print(f"📨 {self.user_id} received: {data.get('type')} from {data.get('from')}")

                # Handle different message types
                msg_type = data.get('type')

                if msg_type == 'MSG_PUBLIC_CHANNEL':
                    # Public messages broadcast to ALL users
                    socketio.emit('new_message', data)
                elif msg_type in ['USER_DELIVER', 'MSG_DIRECT']:
                    # Direct messages only to this user
                    socketio.emit('new_message', data, room=self.socket_id)
                elif msg_type == 'USER_ADVERTISE':
                    # User presence updates broadcast to all
                    user_id = data.get('payload', {}).get('user_id')
                    if user_id and self.client_ref:
                        self.client_ref.connected_users.add(user_id)
                        socketio.emit('user_joined', {'user_id': user_id})
                        socketio.emit('user_list', {'users': list(self.client_ref.connected_users)})
                elif msg_type == 'USER_REMOVE':
                    # User removal broadcast to all
                    user_id = data.get('payload', {}).get('user_id')
                    if user_id and self.client_ref:
                        self.client_ref.connected_users.discard(user_id)
                        socketio.emit('user_left', {'user_id': user_id})
                        socketio.emit('user_list', {'users': list(self.client_ref.connected_users)})
                else:
                    # Other message types to specific user
                    socketio.emit('new_message', data, room=self.socket_id)

        except Exception as e:
            print(f"❌ {self.user_id} listen error: {e}")
            self.connected_to_socp = False

    async def send_message(self, message_data: dict):
        """Send message via this user's SOCP connection"""
        if self.connected_to_socp and self.socp_websocket:
            await self.socp_websocket.send(json.dumps(message_data))
        else:
            print(f"❌ {self.user_id} not connected to SOCP")

class SOCPWebClient:
    def __init__(self):
        self.server_host = "localhost"
        self.server_port = 8082
        self.websocket = None
        self.user_directory: Dict[str, str] = {}  # user_id -> server_location
        self.online_users: set = set()  # track online users from SOCP server
        self.active_sessions: Dict[str, UserSession] = {}  # socket_id -> UserSession
        self.user_to_socket: Dict[str, str] = {}  # user_id -> socket_id
        self.connected_users: set = set()  # Global set of all connected users
        self.connected = False
        self.db = create_database("socp.db")
        self.message_queue = queue.Queue()
        self.loop = None
        self.websocket_task = None

    async def connect_to_server(self):
        """Connect to SOCP server"""
        try:
            self.websocket = await websockets.connect(f"ws://{self.server_host}:{self.server_port}")
            self.connected = True
            print(f"🔗 Connected to SOCP server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    async def send_user_hello(self, user_session: UserSession):
        """Send USER_HELLO message to register with SOCP server"""
        if not user_session.user_id or not user_session.user_keypair:
            return

        hello_message = {
            "type": "USER_HELLO",
            "from": user_session.user_id,
            "to": "server",
            "ts": int(time.time() * 1000),  # SOCP uses milliseconds
            "payload": {
                "client": "web-v1",
                "pubkey": user_session.user_keypair.get_public_key_b64url(),
                "enc_pubkey": user_session.user_keypair.get_public_key_b64url()
            },
            "sig": ""  # Optional on first frame
        }

        await self.send_message(hello_message)
        print(f"Sent USER_HELLO for {user_session.user_id}")

        # Add to online users tracking
        self.online_users.add(user_session.user_id)

    def add_user_session(self, socket_id: str, user_id: str, user_keypair: RSACrypto):
        """Add a new user session - simplified approach"""
        user_session = UserSession(user_id, user_keypair, socket_id, client_ref=self)
        self.active_sessions[socket_id] = user_session
        self.user_to_socket[user_id] = socket_id
        self.connected_users.add(user_id)  # Add to global connected users
        print(f"👤 Added user session: {user_id} (socket: {socket_id})")

        # For now, just broadcast user list immediately
        # We'll implement a simpler connection approach
        socketio.emit('user_list', {'users': self.get_all_active_users()})

        return user_session

    def remove_user_session(self, socket_id: str):
        """Remove a user session and completely clean up all associated data"""
        if socket_id in self.active_sessions:
            user_session = self.active_sessions[socket_id]
            user_id = user_session.user_id

            # Close the SOCP WebSocket connection gracefully with CTRL_CLOSE
            if user_session.socp_websocket:
                try:
                    # Send CTRL_CLOSE message before closing (SOCP v1.3 compliance)
                    import json
                    close_msg = {
                        "type": "CTRL_CLOSE",
                        "from": user_id,
                        "to": "server",
                        "ts": int(time.time() * 1000),
                        "payload": {"reason": "User logout"},
                        "sig": ""
                    }
                    asyncio.create_task(user_session.socp_websocket.send(json.dumps(close_msg)))
                    asyncio.create_task(user_session.socp_websocket.close(code=1000))
                except Exception as e:
                    print(f"⚠️ Error closing SOCP connection for {user_id}: {e}")

            # Complete session cleanup
            del self.active_sessions[socket_id]
            if user_id in self.user_to_socket:
                del self.user_to_socket[user_id]
            self.online_users.discard(user_id)
            self.connected_users.discard(user_id)

            # Clear any cached messages or state for this user
            user_session.message_queue = queue.Queue()  # Clear message queue
            user_session.last_activity = 0
            user_session.connected_to_socp = False

            print(f"🧹 Completely removed user session: {user_id} (socket: {socket_id})")

            # Broadcast updated user list to remaining users
            socketio.emit('user_list', {'users': list(self.connected_users)})

    def get_user_session(self, socket_id: str) -> Optional[UserSession]:
        """Get user session by socket ID"""
        return self.active_sessions.get(socket_id)

    def get_all_active_users(self) -> list:
        """Get list of all active user display names"""
        active_users = []
        for session in self.active_sessions.values():
            if hasattr(session, 'display_name'):
                active_users.append(session.display_name)
        return active_users

    async def send_message(self, message_data):
        """Send message to server"""
        if self.websocket and self.connected:
            await self.websocket.send(json.dumps(message_data))

    async def listen_for_messages(self):
        """Listen for incoming messages"""
        try:
            async for message in self.websocket:
                data = json.loads(message)

                # Handle user presence updates
                if data.get('type') == 'USER_ADVERTISE':
                    user_id = data.get('payload', {}).get('user_id')
                    if user_id:
                        self.online_users.add(user_id)
                        self.user_directory[user_id] = data.get('payload', {}).get('server_id', 'unknown')
                        # Emit user list update
                        socketio.emit('user_list', {'users': list(self.online_users)})

                elif data.get('type') == 'USER_REMOVE':
                    user_id = data.get('payload', {}).get('user_id')
                    if user_id:
                        self.online_users.discard(user_id)
                        self.user_directory.pop(user_id, None)
                        # Emit user list update
                        socketio.emit('user_list', {'users': list(self.online_users)})

                elif data.get('type') == 'CLIENT_LIST_REPLY':
                    # Handle list response
                    users = data.get('payload', {}).get('users', [])
                    self.online_users.update(users)
                    socketio.emit('user_list', {'users': list(self.online_users)})


                # Handle regular messages
                elif data.get('type') in ['MSG_PUBLIC_CHANNEL', 'MSG_DIRECT', 'USER_DELIVER']:
                    print(f"📨 Received message: {data.get('type')} from {data.get('from')}")
                    self.message_queue.put(data)

                    # Only broadcast public channel messages to all clients
                    if data.get('type') == 'MSG_PUBLIC_CHANNEL':
                        socketio.emit('new_message', data)
                    # For direct messages and user delivers, route to specific recipient only
                    elif data.get('type') in ['MSG_DIRECT', 'USER_DELIVER']:
                        recipient_id = data.get('to')
                        if recipient_id in self.user_to_socket:
                            recipient_socket = self.user_to_socket[recipient_id]
                            socketio.emit('new_message', data, room=recipient_socket)
                            print(f"✅ Routed message to {recipient_id}")
                        else:
                            print(f"❌ Recipient {recipient_id} not found locally")

                # Handle other messages (user lists, etc.)
                elif data.get('type') in ['USER_LIST', 'USER_ADVERTISE', 'USER_REMOVE']:
                    print(f"👥 User management: {data.get('type')}")
                    self.message_queue.put(data)

        except Exception as e:
            print(f"Listen error: {e}")
            self.connected = False

# Global client instance
client = SOCPWebClient()

@app.route('/')
def index():
    """Main chat interface"""
    return render_template('chat.html')

# File upload/download configuration
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'mp3', 'wav', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'}

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return True  # Allow all file types

def get_file_type(filename):
    """Determine file type for UI display"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext in {'png', 'jpg', 'jpeg', 'gif'}:
        return 'image'
    elif ext in {'mp4', 'avi', 'mov'}:
        return 'video'
    elif ext in {'mp3', 'wav'}:
        return 'audio'
    elif ext in {'pdf'}:
        return 'pdf'
    elif ext in {'doc', 'docx'}:
        return 'document'
    elif ext in {'zip', 'rar'}:
        return 'archive'
    elif ext in {'exe', 'bat', 'sh', 'app', 'dmg'}:
        return 'executable'
    else:
        return 'file'

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['file']
    recipient = request.form.get('recipient', 'public')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and allowed_file(file.filename):
        # Generate unique filename
        file_id = str(uuid.uuid4())
        original_filename = secure_filename(file.filename)
        filename = f"{file_id}_{original_filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        # Save file
        file.save(filepath)

        # Calculate file hash
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        file_size = os.path.getsize(filepath)
        file_type = get_file_type(original_filename)

        print(f"📁 File uploaded: {original_filename} ({file_size} bytes)")

        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': original_filename,
            'size': file_size,
            'hash': file_hash,
            'type': file_type,
            'download_url': f'/download/{file_id}'
        })

    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/download/<file_id>')
def download_file(file_id):
    """Handle file download"""
    try:
        # Find file in uploads directory
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file_id}_"):
                original_filename = filename[37:]  # Remove UUID prefix
                filepath = os.path.join(UPLOAD_FOLDER, filename)

                # Get mimetype
                mimetype = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'

                return send_file(
                    filepath,
                    as_attachment=True,
                    download_name=original_filename,
                    mimetype=mimetype
                )

        abort(404)
    except Exception as e:
        print(f"❌ Download error: {e}")
        abort(500)

@app.route('/preview/<file_id>')
def preview_file(file_id):
    """Handle file preview (for images)"""
    try:
        # Find file in uploads directory
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file_id}_"):
                original_filename = filename[37:]  # Remove UUID prefix
                filepath = os.path.join(UPLOAD_FOLDER, filename)

                # Only allow preview for images
                file_type = get_file_type(original_filename)
                if file_type != 'image':
                    abort(404)

                # Get mimetype
                mimetype = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'

                return send_file(
                    filepath,
                    mimetype=mimetype
                )

        abort(404)
    except Exception as e:
        print(f"❌ Preview error: {e}")
        abort(500)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    socket_id = request.sid
    print(f'🔌 Client connected (socket: {socket_id})')
    emit('status', {'connected': client.connected})

    # Don't send user list until user is authenticated
    # User list will be sent after successful login/registration

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    socket_id = request.sid
    print(f'🔌 Client disconnected (socket: {socket_id})')

    # Remove user session if exists
    client.remove_user_session(socket_id)

    # Broadcast updated user list to all clients
    active_users = client.get_all_active_users()
    socketio.emit('user_list', {'users': active_users})

@socketio.on('connect_server')
def handle_connect_server(data):
    """Connect to SOCP server"""
    client.server_host = data.get('host', 'localhost')
    client.server_port = data.get('port', 8082)

    async def connect_async():
        success = await client.connect_to_server()
        if success:
            # Start listening task
            client.websocket_task = asyncio.create_task(client.listen_for_messages())
            socketio.emit('connection_result', {'success': True, 'message': 'Connected to SOCP server'})
        else:
            socketio.emit('connection_result', {'success': False, 'message': 'Failed to connect to SOCP server'})

    # Run in new event loop
    def run_connect():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(connect_async())
        except Exception as e:
            print(f"Connection error: {e}")
            socketio.emit('connection_result', {'success': False, 'message': f'Connection error: {str(e)}'})

    threading.Thread(target=run_connect, daemon=True).start()

@socketio.on('register_user')
def handle_register_user(data):
    """Register new user"""
    socket_id = request.sid
    try:
        username = data['username']
        password = data['password']
        display_name = data.get('display_name', username)

        # Validate password requirements
        password_errors = validate_password_server(password)
        if password_errors:
            emit('registration_result', {
                'success': False,
                'message': f'Password requirements: {", ".join(password_errors)}'
            })
            return

        # Generate UUID v4 for user_id as required by SOCP v1.3
        import uuid
        user_id = str(uuid.uuid4())

        # Check if username is already taken using the new username mapping system
        if client.db.get_user_id_by_username(username):
            emit('registration_result', {
                'success': False,
                'message': f'Username "{username}" is already taken'
            })
            return

        # Check if username display name is already taken in active sessions
        if username in [session.display_name for session in client.active_sessions.values() if hasattr(session, 'display_name')]:
            emit('registration_result', {
                'success': False,
                'message': f'Display name "{username}" is already taken in active sessions'
            })
            return

        # Generate keypair for this user
        user_keypair = RSACrypto.generate_keypair()

        # Store in database using SOCP secure password storage
        try:
            # Use secure database implementation with Argon2 hashing
            if hasattr(client, 'db') and client.db:
                success = client.db.register_user(user_id, password, user_keypair, {'display_name': username}, username)
                if not success:
                    raise Exception("Database registration failed")
            else:
                # Fallback with proper password hashing
                import sqlite3
                conn = sqlite3.connect("web_client.db")
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        pubkey TEXT NOT NULL,
                        privkey_store TEXT NOT NULL,
                        pake_password TEXT NOT NULL,
                        meta TEXT,
                        version INTEGER NOT NULL DEFAULT 1
                    )
                """)

                # Hash password with Argon2 (SOCP v1.3 compliant)
                ph = argon2.PasswordHasher()
                hashed_password = ph.hash(password)

                # Encrypt private key with password-derived key
                password_key = hashlib.pbkdf2_hmac('sha256', password.encode(), user_id.encode(), 100000, 32)
                aes_crypto = AESCrypto(password_key)
                private_pem = user_keypair.get_private_key_pem()
                ciphertext, iv, tag = aes_crypto.encrypt(private_pem.encode())
                privkey_store = json.dumps({"ciphertext": ciphertext, "iv": iv, "tag": tag})

                meta_json = json.dumps({'display_name': username})
                cursor.execute("""
                    INSERT OR REPLACE INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, user_keypair.get_public_key_b64url(),
                      privkey_store, hashed_password, meta_json, 1))
                conn.commit()
                conn.close()
        except Exception as db_error:
            emit('registration_result', {
                'success': False,
                'message': f'Database error: {str(db_error)}'
            })
            return

        # Create user session with UUID user_id
        user_session = client.add_user_session(socket_id, user_id, user_keypair)

        # Store display name for UI purposes
        user_session.display_name = username

        # Individual SOCP connection is automatically created by add_user_session

        # Broadcast updated user list to all clients
        active_users = client.get_all_active_users()
        emit('registration_result', {
            'success': True,
            'user_id': user_id,
            'display_name': username,
            'message': 'User registered and connecting to server...'
        })

        # Use socketio.emit for broadcasting after response is sent
        def broadcast_user_list():
            socketio.emit('user_list', {'users': active_users})
        socketio.start_background_task(broadcast_user_list)

    except Exception as e:
        emit('registration_result', {
            'success': False,
            'message': f'Registration failed: {str(e)}'
        })

@socketio.on('request_user_list')
def handle_request_user_list():
    """Request list of online users from server"""
    socket_id = request.sid
    user_session = client.get_user_session(socket_id)

    if not user_session or not user_session.connected_to_socp:
        emit('error', {'message': 'Not connected or logged in'})
        return

    try:
        # Send CLIENT_LIST message to server
        message_data = {
            'type': 'CLIENT_LIST',
            'from': user_session.user_id,
            'to': 'server',
            'ts': int(time.time()),
            'payload': {}
        }

        # Send async via user's individual connection
        def send_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(user_session.send_message(message_data))

        threading.Thread(target=send_async, daemon=True).start()

    except Exception as e:
        emit('error', {'message': f'Failed to request user list: {str(e)}'})

@socketio.on('login_user')
def handle_login_user(data):
    """Login existing user"""
    socket_id = request.sid
    try:
        username = data['username']
        password = data['password']

        # Check if user is already logged in from another session (by display name)
        for session in client.active_sessions.values():
            if hasattr(session, 'display_name') and session.display_name == username:
                emit('login_result', {
                    'success': False,
                    'message': f'User "{username}" is already logged in from another session'
                })
                return

        # Try secure database authentication
        user_keypair = None
        actual_user_id = None
        display_name = None

        # Try username authentication first using the new system
        user_keypair = client.db.authenticate_user_by_username(username, password)
        if user_keypair:
            actual_user_id = client.db.get_user_id_by_username(username)
            user = client.db.get_user(actual_user_id)
            if user and user.meta:
                display_name = user.meta.get('display_name', username)
            else:
                display_name = username
        else:
            # Fallback: Check for legacy users stored by display name in metadata
            import sqlite3
            conn = sqlite3.connect("socp.db")
            cursor = conn.cursor()

            # Search for user by display name in metadata
            cursor.execute("SELECT user_id, pubkey, privkey_store, pake_password, meta FROM users WHERE json_extract(meta, '$.display_name') = ? OR user_id = ?", (username, username))
            user_record = cursor.fetchone()
            conn.close()

        if user_keypair:
            # Username authentication succeeded
            pass  # actual_user_id and user_keypair are already set
        elif user_record:
            actual_user_id = user_record[0]
            # Check if this is an Argon2 hash or plaintext password
            if user_record[3].startswith('$argon2'):
                # This is an Argon2 hash - use secure verification
                try:
                    ph = argon2.PasswordHasher()
                    ph.verify(user_record[3], password)

                    # Decrypt private key
                    password_key = hashlib.pbkdf2_hmac('sha256', password.encode(), actual_user_id.encode(), 100000, 32)
                    aes_crypto = AESCrypto(password_key)

                    privkey_data = json.loads(user_record[2])
                    private_pem = aes_crypto.decrypt(
                        privkey_data["ciphertext"],
                        privkey_data["iv"],
                        privkey_data["tag"]
                    ).decode()
                    user_keypair = RSACrypto.from_private_pem(private_pem)

                    # Get display name
                    meta = json.loads(user_record[4]) if user_record[4] else {}
                    display_name = meta.get('display_name', username)

                except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHash, Exception):
                    # Argon2 password verification failed
                    user_keypair = None
            else:
                # This is a plaintext password (legacy format)
                if user_record[3] == password:
                    # Old plaintext password - load directly but this is insecure
                    user_keypair = RSACrypto.from_private_pem(user_record[2])
                    meta = json.loads(user_record[4]) if user_record[4] else {}
                    display_name = meta.get('display_name', username)
                else:
                    user_keypair = None

        if user_keypair and actual_user_id:
            # Create user session using the actual user_id from database
            user_session = client.add_user_session(socket_id, actual_user_id, user_keypair)

            # Store display name for UI purposes
            user_session.display_name = display_name

            # Individual SOCP connection is automatically created by add_user_session

            # Broadcast updated user list to all clients
            active_users = client.get_all_active_users()
            emit('login_result', {
                'success': True,
                'user_id': user_session.display_name,
                'message': 'Login successful'
            })

            # Use socketio.emit for broadcasting after response is sent
            def broadcast_user_list():
                socketio.emit('user_list', {'users': active_users})
            socketio.start_background_task(broadcast_user_list)
        else:
            emit('login_result', {
                'success': False,
                'message': 'Invalid username or password'
            })

    except Exception as e:
        print(f"Login error: {e}")
        emit('login_result', {
            'success': False,
            'message': f'Login failed: {str(e)}'
        })

@socketio.on('send_message')
def handle_send_message(data):
    """Send chat message - Direct SocketIO implementation for immediate functionality"""
    socket_id = request.sid
    user_session = client.get_user_session(socket_id)

    if not user_session:
        emit('error', {'message': 'Not logged in'})
        return

    try:
        message_type = data['type']  # 'all' or 'tell'
        content = data['content']
        recipient = data.get('recipient')

        # Validate direct message recipient
        if message_type == 'tell':
            if not recipient:
                emit('error', {'message': 'Recipient is required for direct messages'})
                return

            # Check if recipient exists in connected users (by display name)
            recipient_session = None
            for session in client.active_sessions.values():
                if hasattr(session, 'display_name') and session.display_name == recipient:
                    recipient_session = session
                    break

            if not recipient_session:
                emit('error', {'message': f'User "{recipient}" is not online or does not exist'})
                return

            # Don't allow messaging yourself
            if recipient == user_session.display_name:
                emit('error', {'message': 'Cannot send message to yourself'})
                return

        # Create message data for broadcasting
        timestamp_ms = int(time.time() * 1000)

        if message_type == 'all':
            # Public channel message using SOCP v1.3 format (RSA-only encryption)
            print(f"📢 Broadcasting public message from {user_session.user_id}: {content}")

            # For simplicity in web client demo, we'll send as plaintext but structure correctly
            # In production, this would be encrypted with RSA-OAEP using recipient keys
            ciphertext = content  # Should be RSA-OAEP encrypted in real implementation

            # SOCP v1.3 spec: For Public Channel: SHA256(ciphertext || from || ts)
            content_for_sig = ciphertext + user_session.user_id + str(timestamp_ms)
            content_sig = user_session.user_keypair.sign_pss(content_for_sig.encode('utf-8'))

            message_data = {
                'type': 'MSG_PUBLIC_CHANNEL',
                'from': user_session.display_name,
                'to': 'public',
                'ts': timestamp_ms,
                'payload': {
                    'ciphertext': ciphertext,
                    'sender_pub': user_session.user_keypair.get_public_key_b64url(),
                    'content_sig': content_sig
                },
                'sig': ''  # Would contain server signature in real implementation
            }

            # Broadcast to ALL connected web clients
            socketio.emit('new_message', message_data)
            print(f"✅ Broadcasted public message to all clients")

        else:
            # Direct message using SOCP v1.3 format (RSA-OAEP encryption)
            print(f"💬 Sending direct message from {user_session.user_id} to {recipient}: {content}")

            # For simplicity in web client demo, we'll send as plaintext but structure correctly
            # In production, this would be encrypted with RSA-OAEP using recipient's public key
            ciphertext = content  # Should be RSA-OAEP encrypted in real implementation

            # SOCP v1.3 spec: For DM: SHA256(ciphertext || from || to || ts)
            content_for_sig = ciphertext + user_session.user_id + recipient_session.user_id + str(timestamp_ms)
            content_sig = user_session.user_keypair.sign_pss(content_for_sig.encode('utf-8'))

            message_data = {
                'type': 'MSG_DIRECT',
                'from': user_session.display_name,
                'to': recipient_session.display_name,
                'ts': timestamp_ms,
                'payload': {
                    'ciphertext': ciphertext,
                    'sender_pub': user_session.user_keypair.get_public_key_b64url(),
                    'content_sig': content_sig
                },
                'sig': ''  # Optional client->server link sig
            }

            # Use the recipient session we already found
            recipient_socket = recipient_session.socket_id

            # Send to recipient's socket if they're connected
            if recipient_socket:
                socketio.emit('new_message', message_data, room=recipient_socket)
                print(f"✅ Sent direct message to {recipient}")

            # Also send back to sender for confirmation
            emit('new_message', message_data)

        emit('message_sent', {'success': True})

    except Exception as e:
        print(f"❌ Send message error: {e}")
        emit('error', {'message': f'Send failed: {str(e)}'})


@socketio.on('logout_user')
def handle_logout_user():
    """Handle user logout"""
    socket_id = request.sid
    user_session = client.get_user_session(socket_id)

    if user_session:
        print(f"👋 User {user_session.user_id} logging out")

        # Remove user session (this also closes SOCP connection)
        client.remove_user_session(socket_id)

        # Broadcast updated user list to all clients
        active_users = client.get_all_active_users()
        socketio.emit('user_list', {'users': active_users})

        emit('logout_result', {'success': True, 'message': 'Logged out successfully'})
    else:
        emit('logout_result', {'success': False, 'message': 'No active session found'})

@socketio.on('send_file_message')
def handle_send_file_message(data):
    """Simplified file sharing - single unified approach"""
    try:
        socket_id = request.sid
        user_session = client.get_user_session(socket_id)

        if not user_session:
            emit('error', {'message': 'Not logged in'})
            return

        file_id = data['file_id']
        filename = data['filename']
        file_size = data['size']
        file_type = data['type']
        download_url = data['download_url']
        recipient = data.get('recipient', 'public')
        message_type = data.get('message_type', 'all')

        print(f"📁 Sharing file: {filename} ({file_size} bytes) to {recipient}")

        # Validate recipient for direct messages
        if message_type == 'tell':
            # Check if recipient exists by display name
            recipient_session = None
            for session in client.active_sessions.values():
                if hasattr(session, 'display_name') and session.display_name == recipient:
                    recipient_session = session
                    break

            if not recipient_session:
                emit('error', {'message': f'User "{recipient}" is not online'})
                return

        # Create simplified file message
        timestamp_ms = int(time.time() * 1000)
        file_message = {
            'type': 'MSG_DIRECT' if message_type == 'tell' else 'MSG_PUBLIC_CHANNEL',
            'from': user_session.user_id,
            'to': recipient if message_type == 'tell' else 'public',
            'ts': timestamp_ms,
            'payload': {
                'ciphertext': f"📎 {filename}",
                'is_file': True,
                'file_id': file_id,
                'filename': filename,
                'size': file_size,
                'type': file_type,
                'download_url': download_url,
                'sender_pub': user_session.user_keypair.get_public_key_b64url()
            }
        }

        # Send to appropriate recipients
        if message_type == 'all':
            socketio.emit('new_message', file_message)
            print(f"✅ Broadcasted file to all users")
        else:
            # Send to sender and recipient
            emit('new_message', file_message)
            # Use the recipient session we already found during validation
            if recipient_session:
                socketio.emit('new_message', file_message, room=recipient_session.socket_id)
                print(f"✅ Sent file to {recipient}")

        emit('file_upload_status', {'status': 'completed', 'file_id': file_id})

    except Exception as e:
        print(f"❌ File share error: {e}")
        emit('error', {'message': f'File share failed: {str(e)}'})

if __name__ == '__main__':
    # Create templates directory
    os.makedirs('templates', exist_ok=True)

    port = 5003
    print("🌐 SOCP Web Client starting...")
    print(f"📍 Open your browser to: http://localhost:{port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)