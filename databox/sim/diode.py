"""Simulated data diode.

A real diode is hardware: fibre with the transmitter removed on one side, so
light physically cannot flow back. Software cannot enforce that. Here it is kept
by structure: a DiodeSender only ever sends and a DiodeReceiver only ever
receives. Nothing can travel back to ask for a resend, so senders transmit every
datagram more than once, as real diodes do with redundancy.
"""
from __future__ import annotations

import socket

LOCALHOST = "127.0.0.1"


class DiodeSender:
    def __init__(self, target: tuple[str, int], copies: int = 2):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._target = target
        self.copies = copies

    def send(self, data: bytes) -> None:
        for _ in range(self.copies):
            self._sock.sendto(data, self._target)

    def close(self) -> None:
        self._sock.close()


class DiodeReceiver:
    def __init__(self, port: int = 0, timeout_s: float = 0.2, host: str = LOCALHOST):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._sock.settimeout(timeout_s)

    @property
    def address(self) -> tuple[str, int]:
        return self._sock.getsockname()

    def receive(self) -> bytes | None:
        """One datagram, or None if nothing arrived before the timeout."""
        try:
            data, _ = self._sock.recvfrom(65535)
        except TimeoutError:
            return None
        return data

    def close(self) -> None:
        self._sock.close()
