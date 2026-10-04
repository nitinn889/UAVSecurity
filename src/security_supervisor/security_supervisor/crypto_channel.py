"""ChaCha20-Poly1305 secure channel for the /security/* control plane (Phase 9).

SecureChannel is a plain Python class (no ROS 2 dependency) so it can be unit
tested standalone, matching trust_engine.py / anomaly_detector.py.

What this protects
------------------
The two links that actually cross the PC<->Pi wire:
  sensor_monitor (PC) --/security/sensor_snapshot--> supervisor (Pi)
  supervisor (Pi) --/security/mitigation_intent--> actuator (PC)
Both carry JSON over plain DDS, which is unauthenticated and in the clear on
the wire. Anyone on that link could read the vehicle's full sensor state or
forge a mitigation intent (e.g. inject COMMAND_LAND).

AEAD, not a bare stream cipher
------------------------------
ChaCha20 alone is a stream cipher: it gives confidentiality but no integrity,
and flipping a ciphertext bit flips the corresponding plaintext bit
undetected -- an attacker could silently alter an altitude or a command
parameter without ever decrypting it. ChaCha20-Poly1305 adds the Poly1305
MAC, so tampering is detected on open(). For a system whose entire purpose is
detecting sensor/command tampering, shipping the unauthenticated variant
would be self-defeating.

Key handling
------------
A 32-byte root key is shared out-of-band (key file or UAV_SEC_KEY env var).
Per-epoch message keys are derived with HKDF-SHA256, so rotation needs no key
exchange: the epoch number travels in the (authenticated) envelope header and
the receiver derives the same key from root_key + epoch. This is what wires
the pre-existing ROTATE_ENCRYPTION_KEY response action (response_engine.py)
to something real.

Replay
------
Each sender stamps a monotonic sequence number plus a per-process session id,
both bound into the AEAD's associated data. The receiver tracks the highest
sequence seen per (sender, session, epoch) and reports anything at or below it
as a replay. Whether a replay is dropped or merely reported is the caller's
choice -- see drop_replayed in security_config.yaml for why the default
forwards.

The session id is what makes a restart distinguishable from an attack. A
sender that is restarted legitimately begins counting at 1 again, which
against a receiver that remembered the previous process's high-water mark
looks exactly like a replay -- in practice it made every node restart
produce a flood of false replay alarms, and would have made the system stop
accepting telemetry entirely under drop_replayed=true. A fresh session id
gives the restarted process its own replay window. It cannot be abused: the
session id is covered by the AEAD tag, so an attacker cannot mint a new one
without the key, and replaying captured envelopes verbatim preserves the
original session id and sequence number and is still caught.
"""
import base64
import json
import os
import threading
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENVELOPE_VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12
HKDF_SALT = b'uav-security-supervisor/chacha20-poly1305/v1'

ENV_KEY_VAR = 'UAV_SEC_KEY'


class CryptoError(Exception):
    """Base for every failure that makes a payload untrustworthy."""


class MalformedEnvelopeError(CryptoError):
    """Payload was not a well-formed envelope (wrong shape, bad base64, ...)."""


class AuthenticationError(CryptoError):
    """Poly1305 tag did not verify: forged, tampered, or wrong key/epoch."""


class ReplayError(CryptoError):
    """Envelope's sequence number was already seen for this (sender, epoch)."""

    def __init__(self, message, sender, epoch, seq, last_seq):
        super().__init__(message)
        self.sender = sender
        self.epoch = epoch
        self.seq = seq
        self.last_seq = last_seq


def generate_root_key() -> bytes:
    return os.urandom(KEY_BYTES)


def load_root_key(key_file: Optional[str] = None) -> bytes:
    """Resolve the root key from $UAV_SEC_KEY, else a hex key file.

    The env var wins so a deployment can supply the key without it ever
    touching the filesystem.
    """
    from_env = os.environ.get(ENV_KEY_VAR)
    if from_env:
        key = bytes.fromhex(from_env.strip())
        if len(key) != KEY_BYTES:
            raise ValueError(f'{ENV_KEY_VAR} must be {KEY_BYTES} bytes ({KEY_BYTES*2} hex chars)')
        return key

    if not key_file:
        raise ValueError(f'No key available: set ${ENV_KEY_VAR} or pass key_file')

    path = os.path.expanduser(key_file)
    with open(path, 'r') as handle:
        key = bytes.fromhex(handle.read().strip())
    if len(key) != KEY_BYTES:
        raise ValueError(f'{path} must contain {KEY_BYTES} bytes ({KEY_BYTES*2} hex chars)')
    return key


def derive_epoch_key(root_key: bytes, epoch: int) -> bytes:
    """HKDF-SHA256(root_key, info='epoch:<n>') -> 32-byte ChaCha20 key.

    Rotation is therefore a pure function of the (authenticated) epoch in the
    header: no key material is ever transmitted.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=HKDF_SALT,
        info=f'epoch:{int(epoch)}'.encode(),
    ).derive(root_key)


def _aad(version: int, epoch: int, sender: str, session: str, seq: int) -> bytes:
    """Associated data binding the cleartext header to the ciphertext, so
    epoch/sender/session/seq cannot be edited in flight without failing the
    tag."""
    return f'{version}|{epoch}|{sender}|{session}|{seq}'.encode()


class SecureChannel:
    """Seals and opens /security/* payloads.

    One instance per node. Thread-safe: rclpy may deliver callbacks on
    multiple executor threads (supervisor_node uses a MultiThreadedExecutor),
    and both the send counter and the replay table must not tear.
    """

    def __init__(self, root_key: bytes, sender_id: str, epoch: int = 0,
                 track_replay: bool = True, session_id: Optional[str] = None):
        if len(root_key) != KEY_BYTES:
            raise ValueError(f'root key must be {KEY_BYTES} bytes')
        self._root_key = root_key
        self.sender_id = sender_id
        self.epoch = int(epoch)
        self.track_replay = track_replay
        # New per process, so this run's sequence numbers live in their own
        # replay window and a restart is not mistaken for a replay.
        self.session_id = session_id or os.urandom(8).hex()

        self._lock = threading.Lock()
        self._seq = 0
        self._cipher_cache = {}
        self._last_seq_seen = {}  # (sender, session, epoch) -> highest seq accepted

        # Counters for the Phase 9 crypto metrics.
        self.sealed_count = 0
        self.opened_count = 0
        self.auth_failures = 0
        self.replays_detected = 0
        self.malformed_count = 0

    # ------------------------------------------------------------------
    def _cipher(self, epoch: int) -> ChaCha20Poly1305:
        cipher = self._cipher_cache.get(epoch)
        if cipher is None:
            cipher = ChaCha20Poly1305(derive_epoch_key(self._root_key, epoch))
            self._cipher_cache[epoch] = cipher
        return cipher

    def rotate(self, new_epoch: Optional[int] = None) -> int:
        """Advance to a new key epoch. Returns the epoch now in use.

        Receivers need no notification: the epoch rides in the next
        envelope's header and they derive the matching key from it.
        """
        with self._lock:
            self.epoch = int(new_epoch) if new_epoch is not None else self.epoch + 1
            return self.epoch

    # ------------------------------------------------------------------
    def seal(self, plaintext: str) -> str:
        with self._lock:
            self._seq += 1
            seq = self._seq
            epoch = self.epoch

        nonce = os.urandom(NONCE_BYTES)
        aad = _aad(ENVELOPE_VERSION, epoch, self.sender_id, self.session_id, seq)
        ciphertext = self._cipher(epoch).encrypt(nonce, plaintext.encode(), aad)

        envelope = {
            'v': ENVELOPE_VERSION,
            'e': epoch,
            's': self.sender_id,
            'sid': self.session_id,
            'n': seq,
            'iv': base64.b64encode(nonce).decode(),
            'ct': base64.b64encode(ciphertext).decode(),
        }
        self.sealed_count += 1
        return json.dumps(envelope, separators=(',', ':'))

    def open(self, payload: str) -> str:
        """Verify and decrypt an envelope.

        Raises MalformedEnvelopeError, AuthenticationError, or ReplayError.
        A ReplayError still carries a decrypted, authentic payload -- the
        bytes are genuine, they are just old -- so a caller that chooses to
        forward replays can recover it via open_with_status().
        """
        plaintext, error = self._open_inner(payload)
        if error is not None:
            raise error
        return plaintext

    def open_with_status(self, payload: str):
        """Like open(), but returns (plaintext_or_None, error_or_None).

        Lets a caller forward a replayed-but-authentic payload instead of
        dropping it, without swallowing genuine auth failures.
        """
        return self._open_inner(payload)

    def _open_inner(self, payload: str):
        try:
            envelope = json.loads(payload)
            version = int(envelope['v'])
            epoch = int(envelope['e'])
            sender = str(envelope['s'])
            session = str(envelope['sid'])
            seq = int(envelope['n'])
            nonce = base64.b64decode(envelope['iv'])
            ciphertext = base64.b64decode(envelope['ct'])
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            self.malformed_count += 1
            return None, MalformedEnvelopeError(f'not a valid envelope: {exc}')

        if version != ENVELOPE_VERSION:
            self.malformed_count += 1
            return None, MalformedEnvelopeError(f'unsupported envelope version {version}')
        if len(nonce) != NONCE_BYTES:
            self.malformed_count += 1
            return None, MalformedEnvelopeError('bad nonce length')

        aad = _aad(version, epoch, sender, session, seq)
        try:
            plaintext = self._cipher(epoch).decrypt(nonce, ciphertext, aad).decode()
        except Exception:
            # cryptography raises InvalidTag; anything here means the payload
            # is not authentic under the key for this epoch.
            self.auth_failures += 1
            return None, AuthenticationError(
                f'authentication failed (sender={sender}, epoch={epoch}, seq={seq})')

        if self.track_replay:
            key = (sender, session, epoch)
            with self._lock:
                last = self._last_seq_seen.get(key)
                if last is not None and seq <= last:
                    self.replays_detected += 1
                    return plaintext, ReplayError(
                        f'replayed envelope (sender={sender}, session={session}, '
                        f'epoch={epoch}, seq={seq} <= last {last})',
                        sender, epoch, seq, last)
                self._last_seq_seen[key] = seq

        self.opened_count += 1
        return plaintext, None

    # ------------------------------------------------------------------
    def stats(self) -> dict:
        return {
            'sealed': self.sealed_count,
            'opened': self.opened_count,
            'auth_failures': self.auth_failures,
            'replays_detected': self.replays_detected,
            'malformed': self.malformed_count,
            'epoch': self.epoch,
        }


class NullChannel:
    """Pass-through used when crypto.enabled is false.

    Keeps call sites identical so the encrypted and plaintext configurations
    are the same code path -- which is also what makes the Phase 9
    communication-overhead comparison an A/B of one config flag.
    """

    def __init__(self, sender_id: str = 'plaintext'):
        self.sender_id = sender_id
        self.epoch = 0

    def seal(self, plaintext: str) -> str:
        return plaintext

    def open(self, payload: str) -> str:
        return payload

    def open_with_status(self, payload: str):
        return payload, None

    def rotate(self, new_epoch=None) -> int:
        return 0

    def stats(self) -> dict:
        return {'sealed': 0, 'opened': 0, 'auth_failures': 0,
                'replays_detected': 0, 'malformed': 0, 'epoch': 0}
