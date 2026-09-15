"""
ReconPro v8.5 — Real-Time Multi-Operator Collaboration

WebSocket-like collaboration server and client using stdlib
(select + socket). Enables multiple operators to share findings,
claim tasks, and communicate in real-time.

Exports:
    CollabMessage    – message dataclass
    CollabServer    – collaboration server
    CollabClient    – collaboration client
"""

from __future__ import annotations

import json
import select
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ── Protocol framing ──────────────────────────────────────────────
# Simple length-prefixed JSON protocol:
#   [4 bytes big-endian length][JSON payload]

def _frame_send(sock: socket.socket, payload: dict) -> bool:
    """Send a framed JSON message. Returns True on success."""
    try:
        data = json.dumps(payload, default=str).encode("utf-8")
        header = struct.pack(">I", len(data))
        sock.sendall(header + data)
        return True
    except (OSError, BrokenPipeError, ConnectionResetError):
        return False


def _frame_recv(sock: socket.socket) -> Optional[dict]:
    """Receive a framed JSON message. Returns dict or None."""
    try:
        header = _recv_exact(sock, 4)
        if not header:
            return None
        length = struct.unpack(">I", header)[0]
        if length > 10 * 1024 * 1024:  # 10MB safety limit
            return None
        data = _recv_exact(sock, length)
        if not data:
            return None
        return json.loads(data.decode("utf-8"))
    except (OSError, json.JSONDecodeError, struct.error, UnicodeDecodeError):
        return None


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ══════════════════════════════════════════════════════════════════════
# CollabMessage
# ══════════════════════════════════════════════════════════════════════

@dataclass
class CollabMessage:
    """A single collaboration message."""
    type: str = "message"  # message, finding, claim, join, leave, system
    operator: str = ""
    color: str = "#00ffcc"
    content: str = ""
    timestamp: str = ""
    finding_id: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CollabMessage:
        return cls(
            type=data.get("type", "message"),
            operator=data.get("operator", ""),
            color=data.get("color", "#00ffcc"),
            content=data.get("content", ""),
            timestamp=data.get("timestamp", ""),
            finding_id=data.get("finding_id", ""),
            extra=data.get("extra", {}),
        )


# ══════════════════════════════════════════════════════════════════════
# CollabServer
# ══════════════════════════════════════════════════════════════════════

class CollabServer:
    """WebSocket-like collaboration server using select + socket.

    Runs in its own thread, managing connected operators, message
    history, and finding claims.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9876) -> None:
        self._host = host
        self._port = port
        self._server_socket: Optional[socket.socket] = None
        self._clients: Dict[socket.socket, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._history: List[dict] = []
        self._max_history = 500
        self._claimed_findings: Dict[str, str] = {}  # finding_id -> operator
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def address(self) -> str:
        return f"{self._host}:{self._port}"

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self, background: bool = True) -> None:
        """Start the collaboration server.

        If *background* is True, runs in a daemon thread.
        """
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(20)
        self._server_socket.settimeout(1.0)
        self._running = True

        if background:
            self._thread = threading.Thread(target=self._serve_loop, daemon=True)
            self._thread.start()
        else:
            self._serve_loop()

    def stop(self) -> None:
        """Stop the server and disconnect all clients."""
        self._running = False
        with self._lock:
            for sock in list(self._clients.keys()):
                try:
                    sock.close()
                except OSError:
                    pass
            self._clients.clear()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def _serve_loop(self) -> None:
        """Main select loop accepting connections and dispatching messages."""
        while self._running:
            try:
                readable, _, _ = select.select(
                    [self._server_socket] + list(self._clients.keys()),
                    [],
                    [],
                    1.0,
                )
            except (OSError, ValueError):
                continue

            for sock in readable:
                if sock is self._server_socket:
                    self._accept_client()
                else:
                    self._handle_client_data(sock)

    def _accept_client(self) -> None:
        """Accept a new client connection."""
        try:
            client_sock, addr = self._server_socket.accept()  # type: ignore
            client_sock.settimeout(5.0)
            # Wait for join message
            msg = _frame_recv(client_sock)
            client_sock.settimeout(None)

            if not msg or msg.get("type") != "join":
                client_sock.close()
                return

            operator_name = msg.get("operator", f"anon-{addr[1]}")
            operator_color = msg.get("color", "#00ffcc")

            with self._lock:
                self._clients[client_sock] = {
                    "name": operator_name,
                    "color": operator_color,
                    "address": f"{addr[0]}:{addr[1]}",
                    "joined": datetime.now(timezone.utc).isoformat(),
                }

            # Send history to the new operator
            history_msgs = self.get_recent_history(100)
            for h in history_msgs:
                _frame_send(client_sock, h)

            # Announce join
            join_msg = CollabMessage(
                type="system",
                operator="server",
                content=f"{operator_name} joined the session.",
                extra={"event": "join", "operator": operator_name, "color": operator_color},
            )
            self._broadcast(join_msg.to_dict())

        except (OSError, socket.timeout):
            pass

    def _handle_client_data(self, sock: socket.socket) -> None:
        """Process data from a connected client."""
        msg = _frame_recv(sock)
        if msg is None:
            self._disconnect_client(sock)
            return

        msg_type = msg.get("type", "message")

        if msg_type == "message" or msg_type == "finding":
            with self._lock:
                client_info = self._clients.get(sock)
                if client_info:
                    msg["operator"] = client_info["name"]
                    msg["color"] = client_info["color"]
                self._history.append(msg)
                if len(self._history) > self._max_history:
                    self._history = self._history[-self._max_history:]
            self._broadcast(msg)

        elif msg_type == "claim":
            finding_id = msg.get("finding_id", "")
            with self._lock:
                client_info = self._clients.get(sock)
                operator = client_info["name"] if client_info else "unknown"
                self._claimed_findings[finding_id] = operator
                msg["operator"] = operator
                if client_info:
                    msg["color"] = client_info["color"]
                self._history.append(msg)
            self._broadcast(msg)

    def _disconnect_client(self, sock: socket.socket) -> None:
        """Remove a client and announce their departure."""
        with self._lock:
            client_info = self._clients.pop(sock, None)
        try:
            sock.close()
        except OSError:
            pass

        if client_info:
            leave_msg = CollabMessage(
                type="system",
                operator="server",
                content=f"{client_info['name']} left the session.",
                extra={"event": "leave", "operator": client_info["name"]},
            )
            self._broadcast(leave_msg.to_dict())

    def _broadcast(self, message: dict) -> None:
        """Send *message* to all connected clients."""
        with self._lock:
            dead = []
            for sock in self._clients:
                if not _frame_send(sock, message):
                    dead.append(sock)
            for sock in dead:
                self._disconnect_client(sock)

    # ── Public API ──────────────────────────────────────────────────

    def handle_operator_join(self, name: str, color: str = "#00ffcc") -> List[CollabMessage]:
        """Register an operator and return recent history (for in-process use).

        Note: for network use, operators connect via CollabClient.
        This method is for embedding the server in-process.
        """
        join_msg = CollabMessage(
            type="system",
            operator="server",
            content=f"{name} joined the session.",
            extra={"event": "join", "operator": name, "color": color},
        )
        with self._lock:
            self._history.append(join_msg.to_dict())
        self._broadcast(join_msg.to_dict())

        history = self.get_recent_history(100)
        return [CollabMessage.from_dict(h) for h in history]

    def broadcast_finding(self, finding: Dict[str, Any], operator: str) -> None:
        """Broadcast a finding to all connected operators."""
        msg = CollabMessage(
            type="finding",
            operator=operator,
            content=f"Finding: {finding.get('title', 'Unknown')}",
            finding_id=finding.get("id", finding.get("title", str(uuid.uuid4()))),
            extra={"finding": finding},
        )
        with self._lock:
            self._history.append(msg.to_dict())
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
        self._broadcast(msg.to_dict())

    def broadcast_message(self, msg_text: str, operator: str, color: str = "#00ffcc") -> None:
        """Broadcast a text message from *operator* to all clients."""
        msg = CollabMessage(
            type="message",
            operator=operator,
            color=color,
            content=msg_text,
        )
        with self._lock:
            self._history.append(msg.to_dict())
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
        self._broadcast(msg.to_dict())

    def claim_finding(self, finding_id: str, operator: str) -> None:
        """Claim a finding so other operators know it's being handled."""
        with self._lock:
            self._claimed_findings[finding_id] = operator
        msg = CollabMessage(
            type="claim",
            operator=operator,
            content=f"{operator} claimed finding {finding_id}",
            finding_id=finding_id,
        )
        with self._lock:
            self._history.append(msg.to_dict())
        self._broadcast(msg.to_dict())

    def get_active_operators(self) -> List[Dict[str, Any]]:
        """Return list of currently connected operators."""
        with self._lock:
            return [
                {
                    "name": info["name"],
                    "color": info["color"],
                    "address": info["address"],
                    "joined": info["joined"],
                }
                for info in self._clients.values()
            ]

    def get_recent_history(self, limit: int = 50) -> List[dict]:
        """Return the most recent messages from history."""
        with self._lock:
            return list(self._history[-limit:])

    def get_claimed_findings(self) -> Dict[str, str]:
        """Return {finding_id: operator_name} for all claimed findings."""
        with self._lock:
            return dict(self._claimed_findings)


# ══════════════════════════════════════════════════════════════════════
# CollabClient
# ══════════════════════════════════════════════════════════════════════

class CollabClient:
    """Client that connects to a CollabServer and sends/receives messages.

    Uses a background reader thread to receive messages, which are
    buffered in an internal queue for polling.
    """

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._name = ""
        self._color = "#00ffcc"
        self._buffer: List[CollabMessage] = []
        self._lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        self._connected = False
        self._max_buffer = 1000

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self, server_url: str, name: str, color: str = "#00ffcc") -> None:
        """Connect to a CollabServer and register as *name*.

        *server_url* format: ``host:port`` (e.g. "localhost:9876").
        Starts a background reader thread for incoming messages.
        """
        if ":" in server_url:
            host, port_str = server_url.rsplit(":", 1)
            port = int(port_str)
        else:
            host = server_url
            port = 9876

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(10.0)
        self._sock.connect((host, port))
        self._sock.settimeout(None)
        self._name = name
        self._color = color
        self._connected = True
        self._running = True

        # Send join message
        join = CollabMessage(
            type="join",
            operator=name,
            color=color,
            content=f"{name} joining session.",
        )
        _frame_send(self._sock, join.to_dict())

        # Start reader thread
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    def disconnect(self) -> None:
        """Gracefully disconnect from the server."""
        self._running = False
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _reader_loop(self) -> None:
        """Background loop that receives messages and buffers them."""
        while self._running and self._sock:
            try:
                msg_dict = _frame_recv(self._sock)
                if msg_dict is None:
                    self._connected = False
                    break
                msg = CollabMessage.from_dict(msg_dict)
                with self._lock:
                    self._buffer.append(msg)
                    if len(self._buffer) > self._max_buffer:
                        self._buffer = self._buffer[-self._max_buffer:]
            except (OSError, ConnectionResetError, BrokenPipeError):
                self._connected = False
                break

    def send_message(self, text: str) -> bool:
        """Send a text message to the server. Returns True on success."""
        if not self._sock or not self._connected:
            return False
        msg = CollabMessage(
            type="message",
            operator=self._name,
            color=self._color,
            content=text,
        )
        return _frame_send(self._sock, msg.to_dict())

    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """Send a finding to the server. Returns True on success."""
        if not self._sock or not self._connected:
            return False
        msg = CollabMessage(
            type="finding",
            operator=self._name,
            color=self._color,
            content=f"Finding: {finding.get('title', 'Unknown')}",
            finding_id=finding.get("id", finding.get("title", "")),
            extra={"finding": finding},
        )
        return _frame_send(self._sock, msg.to_dict())

    def claim_finding(self, finding_id: str) -> bool:
        """Claim a finding. Returns True on success."""
        if not self._sock or not self._connected:
            return False
        msg = CollabMessage(
            type="claim",
            operator=self._name,
            color=self._color,
            content=f"{self._name} claimed {finding_id}",
            finding_id=finding_id,
        )
        return _frame_send(self._sock, msg.to_dict())

    def receive_messages(self) -> List[CollabMessage]:
        """Poll for and return all buffered messages since last call.

        This is non-blocking — returns an empty list if no new messages.
        """
        with self._lock:
            msgs = list(self._buffer)
            self._buffer.clear()
        return msgs

    def receive_messages_since(self, timestamp: str) -> List[CollabMessage]:
        """Return messages received after *timestamp* (ISO format)."""
        with self._lock:
            msgs = [
                m for m in self._buffer
                if m.timestamp > timestamp
            ]
            remaining = [
                m for m in self._buffer
                if m.timestamp <= timestamp
            ]
            self._buffer = remaining
        return msgs


# Module-level convenience exports
default_server = CollabServer()
default_client = CollabClient()
