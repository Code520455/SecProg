"""
SOCP Server Implementation - Concise Version
"""

import asyncio
import time
import uuid
import yaml
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import websockets
try:
    from websockets.server import WebSocketServerProtocol
except ImportError:
    from websockets import WebSocketServerProtocol
import signal
import logging

from crypto import RSACrypto
from messages import *
from database import create_database


@dataclass
class ServerInfo:
    server_id: str
    host: str
    port: int
    pubkey: str
    websocket: Optional[WebSocketServerProtocol] = None
    last_heartbeat: float = 0


@dataclass
class UserInfo:
    user_id: str
    websocket: WebSocketServerProtocol
    pubkey: str
    connected_at: float


class SOCPServer:
    def __init__(self, host: str, port: int, db_path: str = "socp.db"):
        self.host, self.port = host, port
        self.server_id = str(uuid.uuid4())
        self.server_keypair = RSACrypto.generate_keypair()
        self.db = create_database(db_path)

        # SOCP v1.3 Required In-Memory Tables (Section 5.2)
        self.servers: Dict[str, WebSocketServerProtocol] = {}  # server_id -> Link (WebSocket)
        self.server_addrs: Dict[str, Tuple[str, int]] = {}  # server_id -> (host, port)
        self.local_users: Dict[str, WebSocketServerProtocol] = {}  # user_id -> Link (to client)
        self.user_locations: Dict[str, str] = {}  # user_id -> "local" | f"server_{id}"

        # Additional server state for implementation
        self.server_info: Dict[str, ServerInfo] = {}  # server_id -> ServerInfo
        self.user_info: Dict[str, UserInfo] = {}  # user_id -> UserInfo

        self.running = False
        self.bootstrap_servers = []
        self.websocket_server = None
        self.logger = logging.getLogger(f"SOCP-{self.server_id[:8]}")

    async def start(self, bootstrap_file: Optional[str] = None):
        """Start server"""
        self.logger.info(f"Starting server on {self.host}:{self.port}")

        if bootstrap_file:
            with open(bootstrap_file, 'r') as f:
                config = yaml.safe_load(f)
                self.bootstrap_servers = config.get('bootstrap_servers', [])

        self.websocket_server = await websockets.serve(self._handle_connection, self.host, self.port)
        self.running = True

        # Start background tasks
        asyncio.create_task(self._heartbeat_task())
        if self.bootstrap_servers:
            asyncio.create_task(self._bootstrap_into_network())

    async def stop(self):
        """Stop server with proper SOCP v1.3 closure"""
        self.running = False

        # Send CTRL_CLOSE to all users before closing (SOCP v1.3 transport)
        for user_id, user_websocket in self.local_users.items():
            await self._close_connection_gracefully(user_websocket, user_id, "Server shutdown")

        # Send CTRL_CLOSE to all servers before closing (SOCP v1.3 transport)
        for server_id, server_websocket in self.servers.items():
            await self._close_connection_gracefully(server_websocket, server_id, "Server shutdown")

        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()
        self.db.close()

    async def _handle_connection(self, websocket, path=None):
        """Handle new connection"""
        try:
            raw_message = await websocket.recv()
            envelope = MessageEnvelope.from_json(raw_message)

            if envelope.type == MessageType.SERVER_HELLO_JOIN.value:
                await self._handle_server_hello(websocket, envelope)
            elif envelope.type == MessageType.USER_HELLO.value:
                await self._handle_user_hello(websocket, envelope)
            else:
                await self._close_connection_gracefully(websocket, "unknown", "Unknown message type", code=1002)
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            await self._close_connection_gracefully(websocket, "unknown", "Connection error", code=1002)

    async def _handle_server_hello(self, websocket: WebSocketServerProtocol, envelope: MessageEnvelope):
        """Handle server connection"""
        server_id = envelope.from_
        payload = envelope.payload

        if not validate_server_id(server_id):
            await self._close_connection_gracefully(websocket, server_id, "Invalid server ID", code=1002)
            return

        # Register server
        # SOCP v1.3: Update required tables
        self.servers[server_id] = websocket  # server_id -> Link
        self.server_addrs[server_id] = (payload["host"], payload["port"])  # server_id -> (host, port)

        # Keep additional info for implementation
        server_info = ServerInfo(
            server_id=server_id,
            host=payload["host"],
            port=payload["port"],
            pubkey=payload["pubkey"],
            websocket=websocket,
            last_heartbeat=time.time()
        )
        self.server_info[server_id] = server_info

        # Send welcome if this is bootstrap
        if envelope.to == f"{self.host}:{self.port}":
            server_list = [{"user_id": sid, "host": info.host, "port": info.port, "pubkey": info.pubkey}
                          for sid, info in self.servers.items()]
            welcome = create_server_welcome(self.server_id, server_id, server_id, server_list, self.server_keypair)
            await websocket.send(welcome.to_json())

        asyncio.create_task(self._handle_server_messages(websocket, server_id))

    async def _handle_user_hello(self, websocket: WebSocketServerProtocol, envelope: MessageEnvelope):
        """Handle user connection"""
        user_id = envelope.from_
        payload = envelope.payload

        if not validate_user_id(user_id) or user_id in self.local_users:
            await self._close_connection_gracefully(websocket, user_id, "Invalid or duplicate user ID", code=1002)
            return

        # Register user
        # SOCP v1.3: Update required tables
        self.local_users[user_id] = websocket  # user_id -> Link
        self.user_locations[user_id] = "local"  # user_id -> "local" | f"server_{id}"

        # Keep additional info for implementation
        user_info = UserInfo(
            user_id=user_id,
            websocket=websocket,
            pubkey=payload["pubkey"],
            connected_at=time.time()
        )
        self.user_info[user_id] = user_info

        # Broadcast presence to other servers
        advertise = create_user_advertise(self.server_id, user_id, self.server_id, {}, self.server_keypair)
        await self._broadcast_to_servers(advertise)

        # Also broadcast to local users so they can see who's online
        await self._broadcast_to_local_users(advertise)

        # Send list of currently online users to the new user
        for existing_user_id in self.local_users.keys():
            if existing_user_id != user_id:  # Don't send the user their own presence
                existing_advertise = create_user_advertise(self.server_id, existing_user_id, self.server_id, {}, self.server_keypair)
                try:
                    await websocket.send(existing_advertise.to_json())
                except:
                    pass

        asyncio.create_task(self._handle_user_messages(websocket, user_id))

    async def _handle_user_messages(self, websocket: WebSocketServerProtocol, user_id: str):
        """Handle user messages"""
        try:
            async for raw_message in websocket:
                envelope = MessageEnvelope.from_json(raw_message)
                envelope.from_ = user_id
                await self._route_user_message(envelope)
        except:
            pass
        finally:
            await self._user_disconnect(user_id)

    async def _handle_server_messages(self, websocket: WebSocketServerProtocol, server_id: str):
        """Handle server messages"""
        try:
            async for raw_message in websocket:
                envelope = MessageEnvelope.from_json(raw_message)
                await self._route_server_message(envelope, server_id)
        except:
            pass
        finally:
            await self._server_disconnect(server_id)

    async def _route_user_message(self, envelope: MessageEnvelope):
        """Route user message"""
        if envelope.type == MessageType.MSG_DIRECT.value:
            await self._handle_direct_message(envelope)
        elif envelope.type == MessageType.MSG_PUBLIC_CHANNEL.value:
            await self._broadcast_to_servers(envelope)
            await self._broadcast_to_local_users(envelope)

    async def _route_server_message(self, envelope: MessageEnvelope, from_server: str):
        """Route server message"""
        msg_type = envelope.type
        payload = envelope.payload

        if msg_type == MessageType.USER_ADVERTISE.value:
            # SOCP v1.3: user_id -> "server_{id}" format
            self.user_locations[payload["user_id"]] = f"server_{payload['server_id']}"
        elif msg_type == MessageType.USER_REMOVE.value:
            user_id = payload["user_id"]
            if self.user_locations.get(user_id) == f"server_{payload['server_id']}":
                del self.user_locations[user_id]
        elif msg_type == MessageType.SERVER_DELIVER.value:
            await self._handle_server_deliver(envelope)
        elif msg_type == MessageType.HEARTBEAT.value:
            if from_server in self.server_info:
                self.server_info[from_server].last_heartbeat = time.time()

    async def _handle_direct_message(self, envelope: MessageEnvelope):
        """Handle direct message"""
        recipient = envelope.to

        if recipient not in self.user_locations:
            error = create_error(self.server_id, envelope.from_, ErrorCode.USER_NOT_FOUND,
                                "User not found", self.server_keypair)
            await self._send_to_user(envelope.from_, error)
            return

        location = self.user_locations[recipient]

        if location == "local":
            # Deliver locally
            deliver = create_user_deliver(
                self.server_id, recipient,
                envelope.payload["ciphertext"], envelope.payload["iv"],
                envelope.payload["tag"], envelope.payload["wrapped_key"],
                envelope.from_, envelope.payload["sender_pub"],
                envelope.payload["content_sig"], self.server_keypair
            )
            await self._send_to_user(recipient, deliver)
        else:
            # Forward to server
            server_id = location.replace("server_", "")  # Extract server_id from "server_{id}"
            if server_id in self.servers:
                server_deliver = create_server_deliver(
                    self.server_id, server_id, recipient,
                    envelope.payload["ciphertext"],
                    envelope.from_, envelope.payload["sender_pub"],
                    envelope.payload["content_sig"], self.server_keypair
                )
                await self.servers[server_id].send(server_deliver.to_json())

    async def _handle_server_deliver(self, envelope: MessageEnvelope):
        """Handle server deliver"""
        user_id = envelope.payload["user_id"]
        if user_id in self.local_users:
            deliver = create_user_deliver(
                self.server_id, user_id,
                envelope.payload["ciphertext"], envelope.payload["iv"],
                envelope.payload["tag"], envelope.payload["wrapped_key"],
                envelope.payload["sender"], envelope.payload["sender_pub"],
                envelope.payload["content_sig"], self.server_keypair
            )
            await self._send_to_user(user_id, deliver)

    async def _bootstrap_into_network(self):
        """Bootstrap into network"""
        for bootstrap_server in self.bootstrap_servers:
            try:
                host, port = bootstrap_server["host"], bootstrap_server["port"]
                uri = f"ws://{host}:{port}"

                async with websockets.connect(uri) as websocket:
                    join_msg = create_server_hello_join(
                        self.server_id, f"{host}:{port}",
                        self.host, self.port, self.server_keypair.get_public_key_b64url()
                    )
                    await websocket.send(join_msg.to_json())

                    response = await websocket.recv()
                    welcome = MessageEnvelope.from_json(response)

                    if welcome.type == MessageType.SERVER_WELCOME.value:
                        # Connect to other servers
                        for client in welcome.payload.get("clients", []):
                            asyncio.create_task(self._connect_to_server(
                                client["user_id"], client["host"],
                                client["port"], client["pubkey"]
                            ))
                        break
            except Exception as e:
                self.logger.warning(f"Bootstrap failed with {host}:{port}: {e}")

    async def _connect_to_server(self, server_id: str, host: str, port: int, pubkey: str):
        """Connect to remote server"""
        try:
            uri = f"ws://{host}:{port}"
            websocket = await websockets.connect(uri)

            announce = create_server_announce(
                self.server_id, self.host, self.port,
                self.server_keypair.get_public_key_b64url(), self.server_keypair
            )
            await websocket.send(announce.to_json())

            # SOCP v1.3: Update required tables
            self.servers[server_id] = websocket
            self.server_addrs[server_id] = (host, port)

            # Keep additional info
            server_info = ServerInfo(server_id, host, port, pubkey, websocket, time.time())
            self.server_info[server_id] = server_info

            asyncio.create_task(self._handle_server_messages(websocket, server_id))
        except Exception as e:
            self.logger.error(f"Failed to connect to {server_id}: {e}")

    async def _heartbeat_task(self):
        """Heartbeat background task"""
        while self.running:
            try:
                current_time = time.time()

                # Send heartbeats
                for server_id, server in self.servers.items():
                    if server.websocket:
                        heartbeat = create_heartbeat(self.server_id, server_id, self.server_keypair)
                        await server.websocket.send(heartbeat.to_json())

                # Check timeouts
                dead_servers = [sid for sid, server in self.server_info.items()
                               if current_time - server.last_heartbeat > 45]

                for server_id in dead_servers:
                    if server_id in self.servers:
                        await self.servers[server_id].close()
                        del self.servers[server_id]
                        if server_id in self.server_addrs:
                            del self.server_addrs[server_id]
                        if server_id in self.server_info:
                            del self.server_info[server_id]

                await asyncio.sleep(15)
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")

    async def _broadcast_to_servers(self, envelope: MessageEnvelope):
        """Broadcast to all servers"""
        for server in self.servers.values():
            if server.websocket:
                try:
                    await server.websocket.send(envelope.to_json())
                except:
                    pass

    async def _broadcast_to_local_users(self, envelope: MessageEnvelope):
        """Broadcast to local users"""
        for user in self.local_users.values():
            try:
                await user.websocket.send(envelope.to_json())
            except:
                pass

    async def _send_to_user(self, user_id: str, envelope: MessageEnvelope):
        """Send to specific user"""
        if user_id in self.local_users:
            try:
                await self.local_users[user_id].send(envelope.to_json())
            except:
                pass

    async def _user_disconnect(self, user_id: str):
        """Handle user disconnect"""
        if user_id in self.local_users:
            del self.local_users[user_id]
        if user_id in self.user_locations and self.user_locations[user_id] == "local":
            del self.user_locations[user_id]

        # Broadcast removal to other servers
        remove = create_user_remove(self.server_id, user_id, self.server_id, self.server_keypair)
        await self._broadcast_to_servers(remove)

        # Also broadcast to local users so they can see who went offline
        await self._broadcast_to_local_users(remove)

    async def _server_disconnect(self, server_id: str):
        """Handle server disconnect"""
        # SOCP v1.3: Clean up all tables
        if server_id in self.servers:
            del self.servers[server_id]
        if server_id in self.server_addrs:
            del self.server_addrs[server_id]
        if server_id in self.server_info:
            del self.server_info[server_id]

        # Remove users from that server
        users_to_remove = [uid for uid, loc in self.user_locations.items() if loc == f"server_{server_id}"]
        for user_id in users_to_remove:
            del self.user_locations[user_id]

    async def _close_connection_gracefully(self, websocket: WebSocketServerProtocol,
                                         connection_id: str, reason: str = "Normal closure",
                                         code: int = 1000):
        """SOCP v1.3 compliant graceful connection closure"""
        try:
            # Send CTRL_CLOSE message before closing (optional per spec)
            close_msg = create_ctrl_close(self.server_id, connection_id, reason)
            await websocket.send(close_msg.to_json())
            await asyncio.sleep(0.1)  # Brief delay to ensure message is sent
        except Exception:
            pass  # Ignore errors when sending close message

        try:
            # Use proper WebSocket closure code (1000 = normal, 1002 = protocol error)
            await websocket.close(code=code)
        except Exception:
            pass  # Connection may already be closed


async def main():
    host = "localhost"
    port = 8080
    database = "socp.db"
    bootstrap = None

    server = SOCPServer(host, port, database)

    def signal_handler(signum, frame):
        asyncio.create_task(server.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await server.start(bootstrap)
        print(f"✅ SOCP Server started successfully on {host}:{port}")
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\n🛑 Server shutting down...")
    except Exception as e:
        print(f"❌ Server error: {e}")
    finally:
        await server.stop()
        print("🔴 Server stopped")


if __name__ == "__main__":
    asyncio.run(main())