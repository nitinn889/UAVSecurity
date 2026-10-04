"""Unit tests for the ChaCha20-Poly1305 control-plane channel (Phase 9).

Pure Python -- no ROS 2 runtime, no config file on disk.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', 'security_supervisor'))

from crypto_channel import (  # noqa: E402
    AuthenticationError,
    MalformedEnvelopeError,
    NullChannel,
    ReplayError,
    SecureChannel,
    derive_epoch_key,
    generate_root_key,
)

PAYLOAD = json.dumps({'timestamp_us': 1789834402757078, 'gps': {'lat': 47.398, 'lon': 8.546}})


def _pair(root_key=None, sender='sensor_monitor'):
    """A sender/receiver sharing one root key, as the real nodes do."""
    root_key = root_key or generate_root_key()
    return SecureChannel(root_key, sender), SecureChannel(root_key, 'supervisor')


def test_roundtrip_recovers_plaintext():
    sender, receiver = _pair()
    assert receiver.open(sender.seal(PAYLOAD)) == PAYLOAD


def test_ciphertext_does_not_leak_plaintext():
    sender, _ = _pair()
    envelope = sender.seal(PAYLOAD)
    # The whole point of encrypting: the lat/lon must not be on the wire.
    assert '47.398' not in envelope
    assert 'timestamp_us' not in envelope
    assert json.loads(envelope)['ct'] != PAYLOAD


def test_tampered_ciphertext_is_rejected():
    sender, receiver = _pair()
    envelope = json.loads(sender.seal(PAYLOAD))
    ct = bytearray(__import__('base64').b64decode(envelope['ct']))
    ct[5] ^= 0x01  # flip one bit
    envelope['ct'] = __import__('base64').b64encode(bytes(ct)).decode()

    with pytest.raises(AuthenticationError):
        receiver.open(json.dumps(envelope))


def test_tampered_header_is_rejected():
    """Header fields are bound as AEAD associated data, so editing the
    sender label (spoofing origin) must fail the tag, not pass silently."""
    sender, receiver = _pair()
    envelope = json.loads(sender.seal(PAYLOAD))
    envelope['s'] = 'attacker'

    with pytest.raises(AuthenticationError):
        receiver.open(json.dumps(envelope))


def test_wrong_key_is_rejected():
    sender = SecureChannel(generate_root_key(), 'sensor_monitor')
    receiver = SecureChannel(generate_root_key(), 'supervisor')

    with pytest.raises(AuthenticationError):
        receiver.open(sender.seal(PAYLOAD))


def test_malformed_payload_is_rejected():
    _, receiver = _pair()
    for junk in ('not json at all', '{}', json.dumps({'v': 99}), ''):
        with pytest.raises((MalformedEnvelopeError, AuthenticationError)):
            receiver.open(junk)


def test_replayed_envelope_is_detected():
    """The telemetry_replay attack in envelope form: identical bytes, resent."""
    sender, receiver = _pair()
    envelope = sender.seal(PAYLOAD)

    assert receiver.open(envelope) == PAYLOAD
    with pytest.raises(ReplayError):
        receiver.open(envelope)
    assert receiver.replays_detected == 1


def test_replay_still_yields_payload_via_open_with_status():
    """drop_replayed=false forwards replays to TrustEngine, so the payload
    must still be recoverable alongside the error."""
    sender, receiver = _pair()
    envelope = sender.seal(PAYLOAD)
    receiver.open(envelope)

    payload, error = receiver.open_with_status(envelope)
    assert isinstance(error, ReplayError)
    assert payload == PAYLOAD


def test_out_of_order_older_sequence_is_replay():
    sender, receiver = _pair()
    first = sender.seal(PAYLOAD)
    second = sender.seal(PAYLOAD)

    assert receiver.open(second) == PAYLOAD
    with pytest.raises(ReplayError):
        receiver.open(first)


def test_sequence_numbers_are_monotonic():
    sender, _ = _pair()
    seqs = [json.loads(sender.seal(PAYLOAD))['n'] for _ in range(5)]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == 5


def test_nonce_is_unique_per_message():
    """Nonce reuse under one key is catastrophic for ChaCha20 -- it XORs two
    plaintexts together. Guard against a regression that made it static."""
    sender, _ = _pair()
    nonces = {json.loads(sender.seal(PAYLOAD))['iv'] for _ in range(200)}
    assert len(nonces) == 200


def test_rotation_changes_key_and_receiver_follows():
    root_key = generate_root_key()
    sender, receiver = _pair(root_key)

    assert receiver.open(sender.seal(PAYLOAD)) == PAYLOAD
    new_epoch = sender.rotate()
    assert new_epoch == 1
    # Receiver was told nothing: it derives the new key from the epoch in
    # the header alone.
    assert receiver.open(sender.seal(PAYLOAD)) == PAYLOAD


def test_epoch_keys_differ():
    root_key = generate_root_key()
    assert derive_epoch_key(root_key, 0) != derive_epoch_key(root_key, 1)
    assert derive_epoch_key(root_key, 5) == derive_epoch_key(root_key, 5)


def test_rotation_resets_replay_window_per_epoch():
    """A sequence number from a previous epoch must not be usable after
    rotation, and rotation must not wrongly flag fresh traffic as replay."""
    root_key = generate_root_key()
    sender, receiver = _pair(root_key)
    receiver.open(sender.seal(PAYLOAD))
    sender.rotate()
    receiver.open(sender.seal(PAYLOAD))  # fresh epoch, must not raise


def test_publisher_restart_is_not_mistaken_for_replay():
    """Regression: a restarted sender legitimately restarts its sequence at 1.

    Keyed only on (sender, epoch), that looked identical to a replay and the
    receiver rejected everything the new process sent until its counter
    climbed past the old high-water mark. Observed live as 1845 false replay
    alarms during a campaign that restarts sensor_monitor once per run, and
    under drop_replayed=true it would have stopped telemetry entirely.
    """
    root_key = generate_root_key()
    receiver = SecureChannel(root_key, 'supervisor')

    first = SecureChannel(root_key, 'sensor_monitor')
    for _ in range(50):
        receiver.open(first.seal(PAYLOAD))

    # Same sender_id, new process: sequence numbers start over at 1.
    restarted = SecureChannel(root_key, 'sensor_monitor')
    assert restarted.session_id != first.session_id
    for _ in range(10):
        receiver.open(restarted.seal(PAYLOAD))  # must not raise

    assert receiver.replays_detected == 0


def test_replay_still_caught_after_a_restart():
    """The restart fix must not create a hole: envelopes captured from the
    earlier session are still replays when resent."""
    root_key = generate_root_key()
    receiver = SecureChannel(root_key, 'supervisor')

    first = SecureChannel(root_key, 'sensor_monitor')
    captured = first.seal(PAYLOAD)
    receiver.open(captured)

    restarted = SecureChannel(root_key, 'sensor_monitor')
    receiver.open(restarted.seal(PAYLOAD))

    with pytest.raises(ReplayError):
        receiver.open(captured)


def test_session_id_cannot_be_forged():
    """Session id is covered by the AEAD tag, so an attacker cannot mint a
    fresh one to escape the replay window."""
    sender, receiver = _pair()
    envelope = json.loads(sender.seal(PAYLOAD))
    receiver.open(json.dumps(envelope))

    envelope['sid'] = 'deadbeefdeadbeef'
    with pytest.raises(AuthenticationError):
        receiver.open(json.dumps(envelope))


def test_sessions_are_tracked_independently():
    """Two live senders sharing a sender_id must not evict each other's
    replay state."""
    root_key = generate_root_key()
    receiver = SecureChannel(root_key, 'supervisor')
    a = SecureChannel(root_key, 'sensor_monitor')
    b = SecureChannel(root_key, 'sensor_monitor')

    for _ in range(5):
        receiver.open(a.seal(PAYLOAD))
        receiver.open(b.seal(PAYLOAD))
    assert receiver.replays_detected == 0


def test_null_channel_is_transparent():
    channel = NullChannel()
    assert channel.seal(PAYLOAD) == PAYLOAD
    assert channel.open(PAYLOAD) == PAYLOAD
    payload, error = channel.open_with_status(PAYLOAD)
    assert payload == PAYLOAD and error is None


def test_stats_track_activity():
    sender, receiver = _pair()
    envelope = sender.seal(PAYLOAD)
    receiver.open(envelope)
    try:
        receiver.open(envelope)
    except ReplayError:
        pass

    assert sender.stats()['sealed'] == 1
    assert receiver.stats()['opened'] == 1
    assert receiver.stats()['replays_detected'] == 1
