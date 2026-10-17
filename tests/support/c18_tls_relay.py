"""Bounded C18 QA TLS relay; never a Gateway or protocol-success simulator.

This controlled local network-fault proxy terminates client TLS and opens a new
verified TLS connection to the real Gateway. It does NOT demonstrate a client
socket reaching Gateway without TLS termination. Both legs use the same synthetic
leaf certificate, CA, hostname (127.0.0.1), ALPN (pushgo-tcp), and SHA256 leaf pin.
Only the caller's isolated QA client process should trust that synthetic CA; this
module changes neither system trust nor production trust. No ACK is synthesized.
The caller supplies the synthetic private key in memory. Its sole loading path is
an anonymous pipe exposed via /dev/fd; no key file or key logging is performed.

output is a fresh results directory (frames.jsonl must not already exist).
full_frame_bytes excludes the four-byte length prefix; stream_bytes includes it.
Raw captures are complete encoded frame bodies, never reencoded protocol data.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import threading
from typing import Any


class _LimitError(RuntimeError):
    pass


class _SocketOperation:
    """FIFO operation lock: a timed recv cannot jump a queued send or close.

    SSL recv may itself write TLS records. Serialize *all* operations on each
    SSLSocket, rather than assuming one reader and one writer are independent.
    Each recv holds this lock for at most its configured socket timeout (0.5s
    during frame forwarding). Callers never hold two socket operation locks.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._next = 0
        self._serving = 0

    def __enter__(self) -> _SocketOperation:
        with self._condition:
            ticket = self._next
            self._next += 1
            self._condition.wait_for(lambda: self._serving == ticket)
        return self

    def __exit__(self, *_: Any) -> None:
        with self._condition:
            self._serving += 1
            self._condition.notify_all()


class FramedTlsRelay:
    MAX_CONNECTIONS = 4  # Total lifetime accepts, also bounding all worker objects.
    MAX_ENTRIES = 256
    MAX_RAW_BYTES = 4 * 1024 * 1024
    RAW_LIMITS = {4: 8, 8: 8, 9: 16}
    ALPN = "pushgo-tcp"

    def __init__(self, upstream: tuple[str, int], cert_pem: Path,
                 ca_pem: Path, key_pem: bytes, pin: str, output: Path):
        if upstream[0] != "127.0.0.1":
            raise ValueError("C18 requires upstream hostname 127.0.0.1")
        self._pin = pin.lower().removeprefix("sha256:").replace(":", "")
        if len(self._pin) != 64 or any(c not in "0123456789abcdef" for c in self._pin):
            raise ValueError("pin must be the SHA256 leaf digest as 64 hexadecimal digits")
        leaf_text = Path(cert_pem).read_text(encoding="ascii")
        leaf_text = leaf_text[:leaf_text.index("-----END CERTIFICATE-----")
                              + len("-----END CERTIFICATE-----")]
        leaf_der = ssl.PEM_cert_to_DER_cert(leaf_text)
        if hashlib.sha256(leaf_der).hexdigest() != self._pin:
            raise ValueError("relay server leaf certificate does not match pin")
        self._server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._server_ctx.set_alpn_protocols([self.ALPN])
        self._load_key_from_pipe(self._server_ctx, Path(cert_pem), key_pem)
        self._client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._client_ctx.load_verify_locations(cafile=str(ca_pem))
        self._client_ctx.set_alpn_protocols([self.ALPN])
        # PROTOCOL_TLS_CLIENT retains CERT_REQUIRED and check_hostname=True.
        self._upstream = upstream
        self._output = Path(output)
        self._output.mkdir(parents=True, exist_ok=True)
        self._raw_dir = self._output / "raw"
        self._raw_dir.mkdir(exist_ok=True)
        self._journal = (self._output / "frames.jsonl").open("x", encoding="utf-8")
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._drop = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._workers: list[threading.Thread] = []
        self._sockets: set[socket.socket] = set()
        self._socket_operations: dict[socket.socket, _SocketOperation] = {}
        self._session_done: dict[int, threading.Event] = {}
        self._stats: dict[str, Any] = dict(accepted=0, active=0, dropped_acks=0,
            forwarded_acks=0, deliveries=0, welcome_count=0, errors=[])
        self._entries = 0
        self._raw_bytes = 0
        self._raw_seen: dict[int, set[str]] = {t: set() for t in self.RAW_LIMITS}
        self._tls: list[dict[str, Any]] = []
        self._closed = False
        self.port = 0

    @staticmethod
    def _load_key_from_pipe(ctx: ssl.SSLContext, cert: Path, key: bytes) -> None:
        if not isinstance(key, bytes) or not key or len(key) > 65536:
            raise ValueError("synthetic key must be nonempty bytes, at most 65536 bytes")
        read_fd, write_fd = os.pipe()
        failures: list[BaseException] = []

        def write_key() -> None:
            try:
                view = memoryview(key)
                while view:
                    count = os.write(write_fd, view)
                    view = view[count:]
            except BaseException as exc:
                failures.append(exc)
            finally:
                os.close(write_fd)

        writer = threading.Thread(target=write_key, name="c18-key-pipe")
        writer.start()
        try:
            # Explicit callback prevents an interactive prompt for encrypted keys.
            ctx.load_cert_chain(str(cert), f"/dev/fd/{read_fd}", password=lambda: b"")
        finally:
            os.close(read_fd)
            writer.join(timeout=5)
        if writer.is_alive():
            raise RuntimeError("anonymous key pipe writer did not terminate")
        if failures:
            raise RuntimeError("anonymous key pipe write failed") from failures[0]

    def start(self) -> None:
        with self._lock:
            if self._closed or self._listener is not None:
                raise RuntimeError("relay must be started exactly once before close")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(self.MAX_CONNECTIONS)
            listener.settimeout(0.25)
            self._listener = listener
            self.port = listener.getsockname()[1]
            self._accept_thread = threading.Thread(target=self._accept, name="c18-accept")
            self._accept_thread.start()

    def arm_ack_drop(self) -> None:
        self._drop.set()

    def allow_ack(self) -> None:
        self._drop.clear()

    def _error(self, seq: int, stage: str, exc: BaseException) -> None:
        with self._lock:
            errors = self._stats["errors"]
            if len(errors) < 32:
                errors.append(dict(connection_seq=seq, stage=stage,
                                   error=f"{type(exc).__name__}: {exc}"[:512]))

    def _accept(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            with self._lock:
                if self._stats["accepted"] >= self.MAX_CONNECTIONS:
                    return
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    self._error(0, "accept", exc)
                return
            with self._lock:
                if self._stop.is_set():
                    self._shutdown(client)
                    return
                self._stats["accepted"] += 1
                seq = self._stats["accepted"]
                self._stats["active"] += 1
                self._sockets.add(client)
                done = threading.Event()
                self._session_done[seq] = done
                worker = threading.Thread(target=self._session, args=(client, seq, done),
                                          name=f"c18-session-{seq}")
                self._workers.append(worker)
                worker.start()

    def _replace_socket(self, old: socket.socket, new: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(old)
            self._sockets.add(new)

    def _operation(self, sock: socket.socket) -> _SocketOperation:
        with self._lock:
            return self._socket_operations.setdefault(sock, _SocketOperation())

    def _shutdown(self, sock: socket.socket) -> None:
        with self._operation(sock):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _session(self, client: socket.socket, seq: int, done: threading.Event) -> None:
        owned = [client]
        pumps: list[threading.Thread] = []
        stage = "client_tls"
        try:
            client.settimeout(5)
            downstream = self._server_ctx.wrap_socket(client, server_side=True,
                                                      do_handshake_on_connect=False)
            self._replace_socket(client, downstream)
            owned.append(downstream)
            with self._operation(downstream):
                downstream.do_handshake()
            if done.is_set() or self._stop.is_set():
                return
            if downstream.selected_alpn_protocol() != self.ALPN:
                raise ssl.SSLError("client did not negotiate pushgo-tcp ALPN")
            stage = "upstream_connect"
            upstream_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_raw.settimeout(5)
            with self._lock:
                self._sockets.add(upstream_raw)
            owned.append(upstream_raw)
            with self._operation(upstream_raw):
                upstream_raw.connect(self._upstream)
            stage = "upstream_tls_verify"
            upstream = self._client_ctx.wrap_socket(upstream_raw, server_hostname="127.0.0.1",
                                                   do_handshake_on_connect=False)
            self._replace_socket(upstream_raw, upstream)
            owned.append(upstream)
            with self._operation(upstream):
                upstream.do_handshake()
            if upstream.selected_alpn_protocol() != self.ALPN:
                raise ssl.SSLError("Gateway did not negotiate pushgo-tcp ALPN")
            digest = hashlib.sha256(upstream.getpeercert(binary_form=True)).hexdigest()
            if digest != self._pin:
                raise ssl.SSLError("Gateway leaf SHA256 pin mismatch")
            with self._lock:
                self._tls.append(dict(connection_seq=seq, alpn=self.ALPN,
                    downstream_version=downstream.version(), upstream_version=upstream.version(),
                    upstream_leaf_sha256=digest, hostname="127.0.0.1", pkix_verified=True))
            for sock in (downstream, upstream):
                sock.settimeout(0.5)
            for direction, src, dst in (("client_to_server", downstream, upstream),
                                        ("server_to_client", upstream, downstream)):
                pump = threading.Thread(target=self._pump,
                    args=(src, dst, seq, direction, done), name=f"c18-{seq}-{direction}")
                pumps.append(pump)
                pump.start()
            for pump in pumps:
                pump.join()
        except (OSError, ValueError, RuntimeError) as exc:
            if not self._stop.is_set() and not done.is_set():
                self._error(seq, stage, exc)
        finally:
            done.set()
            for sock in owned:
                self._shutdown(sock)
            for pump in pumps:
                pump.join(timeout=2)
                if pump.is_alive():
                    self._error(seq, "join", RuntimeError("frame pump did not terminate"))
            with self._lock:
                for sock in owned:
                    self._sockets.discard(sock)
                self._session_done.pop(seq, None)
                self._stats["active"] -= 1

    def _read_exact(self, src: socket.socket, count: int,
                    done: threading.Event) -> bytes | None:
        data = bytearray()
        while len(data) < count:
            if self._stop.is_set() or done.is_set():
                return None
            try:
                with self._operation(src):
                    if self._stop.is_set() or done.is_set():
                        return None
                    chunk = src.recv(count - len(data))
            except socket.timeout:
                continue
            if not chunk:
                # Boundary or partial-frame half EOF is a transport disconnect.
                return None
            data.extend(chunk)
        return bytes(data)

    def _record(self, seq: int, direction: str, frame: bytes, dropped: bool) -> None:
        frame_type = frame[0]
        digest = hashlib.sha256(frame).hexdigest()
        with self._lock:
            if self._entries >= self.MAX_ENTRIES:
                raise _LimitError("frame metadata budget exhausted (256 entries)")
            raw_path = None
            if frame_type in self.RAW_LIMITS:
                seen = self._raw_seen[frame_type]
                if digest not in seen:
                    if len(seen) >= self.RAW_LIMITS[frame_type]:
                        raise _LimitError(f"raw capture count budget exhausted for type {frame_type}")
                    if self._raw_bytes + len(frame) > self.MAX_RAW_BYTES:
                        raise _LimitError("raw capture byte budget exhausted (4 MiB)")
                    path = self._raw_dir / f"{digest}.bin"
                    if not path.exists():
                        with path.open("xb") as raw:
                            raw.write(frame)
                    seen.add(digest)
                    self._raw_bytes += len(frame)
                raw_path = f"raw/{digest}.bin"
            # An observed non-dropped frame is not a successful forward or a
            # Gateway COMMIT receipt; forwarding counters increment after send.
            record = dict(direction=direction, type=frame_type, flags=frame[1],
                full_frame_bytes=len(frame), stream_bytes=len(frame) + 4, sha256=digest,
                connection_seq=seq, dropped=dropped, raw_file=raw_path)
            self._journal.write(json.dumps(record, sort_keys=True) + "\n")
            self._journal.flush()
            self._entries += 1
            if direction == "client_to_server" and frame_type == 9 and dropped:
                self._stats["dropped_acks"] += 1

    def _pump(self, src: socket.socket, dst: socket.socket, seq: int,
              direction: str, done: threading.Event) -> None:
        try:
            while not done.is_set() and not self._stop.is_set():
                prefix = self._read_exact(src, 4, done)
                if prefix is None:
                    return
                size = int.from_bytes(prefix, "big")
                if not 2 <= size <= 131072:
                    raise ValueError(f"invalid encoded full-frame length {size}; allowed 2..131072")
                frame = self._read_exact(src, size, done)
                if frame is None:
                    return
                dropped = direction == "client_to_server" and frame[0] == 9 and self._drop.is_set()
                self._record(seq, direction, frame, dropped)
                if dropped:
                    continue
                # Preserve the exact received prefix and full frame, with no decoding/reencoding.
                with self._operation(dst):
                    if self._stop.is_set() or done.is_set():
                        return
                    dst.sendall(prefix)
                    dst.sendall(frame)
                with self._lock:
                    if direction == "client_to_server" and frame[0] == 9:
                        self._stats["forwarded_acks"] += 1
                    if direction == "server_to_client" and frame[0] == 8:
                        self._stats["deliveries"] += 1
                    if direction == "server_to_client" and frame[0] == 4:
                        self._stats["welcome_count"] += 1
        except (OSError, ValueError, RuntimeError) as exc:
            if not self._stop.is_set() and not done.is_set():
                self._error(seq, direction, exc)
        finally:
            done.set()
            self._shutdown(src)
            self._shutdown(dst)

    def cut(self) -> None:
        """Cut current connections; keep accepting within the lifetime budget."""
        with self._lock:
            for done in self._session_done.values():
                done.set()
            sockets = list(self._sockets)
        for sock in sockets:
            self._shutdown(sock)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(**{k: list(v) if isinstance(v, list) else v
                           for k, v in self._stats.items()}, port=self.port,
                frame_entries=self._entries, raw_bytes=self._raw_bytes,
                ack_drop_armed=self._drop.is_set(), tls=[dict(t) for t in self._tls],
                frames_jsonl=str(self._output / "frames.jsonl"),
                raw_directory=str(self._raw_dir), connection_limit=self.MAX_CONNECTIONS,
                tls_scope="QA TLS termination and verified TLS reconnection to real Gateway")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            listener = self._listener
        if listener is not None:
            self._shutdown(listener)
        self.cut()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)
            if self._accept_thread.is_alive():
                self._error(0, "join", RuntimeError("accept thread did not terminate"))
        for worker in self._workers:
            worker.join(timeout=7)
            if worker.is_alive():
                self._error(0, "join", RuntimeError("session thread did not terminate"))
        with self._lock:
            self._journal.close()
