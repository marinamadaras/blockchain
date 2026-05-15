from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TypeAlias

from ipv8.community import Community
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import dataclass as payload_dataclass
from ipv8.peer import Peer


@payload_dataclass(msg_id=1)
class RegisterPayload:
    # Wire format: three varlenH byte fields, in the canonical order used later for signatures.
    member1_key: bytes
    member2_key: bytes
    member3_key: bytes


@payload_dataclass(msg_id=2)
class RegisterResponsePayload:
    # Wire format: bool, varlenHutf8 group_id, varlenHutf8 status message.
    success: bool
    group_id: str
    message: str


@payload_dataclass(msg_id=3)
class ChallengeRequestPayload:
    # Server message: ask for the current challenge for this registered group.
    group_id: str


@payload_dataclass(msg_id=4)
class ChallengeResponsePayload:
    # Server message: nonce starts/continues the timed round budget.
    nonce: bytes
    round_number: int
    deadline: float


@payload_dataclass(msg_id=5)
class SignatureBundlePayload:
    # Server message: signatures must be in the same order as registration.
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes


@payload_dataclass(msg_id=6)
class RoundResultPayload:
    # Server message: reply to bundle submission or early challenge-request rejection.
    success: bool
    round_number: int
    rounds_completed: int
    message: str


@payload_dataclass(msg_id=100)
class GroupMessagePayload:
    # Group-internal message for teammate-to-teammate traffic inside the same Lab 2 community.
    message: str


@payload_dataclass(msg_id=101)
class NonceToSignPayload:
    # Group-internal message: submitter sends the server nonce to teammates.
    group_id: str
    round_number: int
    nonce: bytes
    deadline: float


@payload_dataclass(msg_id=102)
class SignatureSharePayload:
    # Group-internal message: teammate returns their raw-nonce signature to the submitter.
    group_id: str
    round_number: int
    nonce: bytes
    signature: bytes


@dataclass(frozen=True)
class RegistrationResult:
    success: bool
    group_id: str
    message: str


@dataclass(frozen=True)
class ChallengeResponse:
    nonce: bytes
    round_number: int
    deadline: float


@dataclass(frozen=True)
class RoundResult:
    success: bool
    round_number: int
    rounds_completed: int
    message: str


ChallengeRequestOutcome: TypeAlias = ChallengeResponse | RoundResult


@dataclass(frozen=True)
class GroupMessage:
    sender_public_key: bytes
    sender_mid: bytes
    message: str


@dataclass(frozen=True)
class NonceToSign:
    sender_public_key: bytes
    sender_mid: bytes
    group_id: str
    round_number: int
    nonce: bytes
    deadline: float


@dataclass(frozen=True)
class SignatureShare:
    sender_public_key: bytes
    sender_mid: bytes
    group_id: str
    round_number: int
    nonce: bytes
    signature: bytes


class LabGroupSigningCommunity(Community):
    community_id = b"Lab2GroupSigning2026"

    def __init__(self, settings) -> None:
        # IPv8 constructs settings first and then copies "initialize" config fields onto it.
        self.community_id = settings.community_id
        self.member_public_keys: tuple[bytes, ...] = tuple(getattr(settings, "member_public_keys", ()))
        super().__init__(settings)
        self.add_message_handler(RegisterResponsePayload, self.on_register_response)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)
        self.add_message_handler(GroupMessagePayload, self.on_group_message)
        self.add_message_handler(NonceToSignPayload, self.on_nonce_to_sign)
        self.add_message_handler(SignatureSharePayload, self.on_signature_share)
        self._registration_response: asyncio.Future[RegistrationResult] | None = None
        self._challenge_response: asyncio.Future[ChallengeRequestOutcome] | None = None
        self._round_result: asyncio.Future[RoundResult] | None = None
        # These buffers avoid dropping a fast peer message that arrives just before the runner awaits it.
        self._nonce_to_sign: asyncio.Future[NonceToSign] | None = None
        self._pending_nonces_to_sign: list[NonceToSign] = []
        self._signature_share_queue: asyncio.Queue[SignatureShare] | None = None
        self._pending_signature_shares: list[SignatureShare] = []
        self._expected_server_public_key: bytes | None = None
        self.received_group_messages: list[GroupMessage] = []

    async def register_group(
        self,
        server_peer: Peer,
        member_public_keys: tuple[bytes, bytes, bytes],
        timeout: float,
    ) -> RegistrationResult:
        # Store the pending response future before sending, so a fast server reply cannot be missed.
        self._registration_response = asyncio.get_running_loop().create_future()
        self._expected_server_public_key = server_peer.public_key.key_to_bin()

        # The discovered Peer already carries both the verified server key and its current UDP address.
        self.ez_send(server_peer, RegisterPayload(*member_public_keys))

        try:
            return await asyncio.wait_for(self._registration_response, timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"Timed out waiting for registration response after {timeout:.2f} seconds") from exc
        finally:
            self._registration_response = None
            self._expected_server_public_key = None

    async def request_challenge(
        self,
        server_peer: Peer,
        group_id: str,
        timeout: float,
    ) -> ChallengeRequestOutcome:
        # The server may answer msg_id=4 with a nonce or msg_id=6 with an early rejection.
        self._challenge_response = asyncio.get_running_loop().create_future()
        self._expected_server_public_key = server_peer.public_key.key_to_bin()
        self.ez_send(server_peer, ChallengeRequestPayload(group_id))

        try:
            return await asyncio.wait_for(self._challenge_response, timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"Timed out waiting for challenge response after {timeout:.2f} seconds") from exc
        finally:
            self._challenge_response = None
            self._expected_server_public_key = None

    async def submit_signature_bundle(
        self,
        server_peer: Peer,
        group_id: str,
        round_number: int,
        signatures: tuple[bytes, bytes, bytes],
        timeout: float,
    ) -> RoundResult:
        self._round_result = asyncio.get_running_loop().create_future()
        self._expected_server_public_key = server_peer.public_key.key_to_bin()
        # ez_send signs this packet; the server uses the auth header to identify the submitter.
        self.ez_send(server_peer, SignatureBundlePayload(group_id, round_number, *signatures))

        try:
            return await asyncio.wait_for(self._round_result, timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"Timed out waiting for round result after {timeout:.2f} seconds") from exc
        finally:
            self._round_result = None
            self._expected_server_public_key = None

    def sign_nonce(self, nonce: bytes) -> bytes:
        if len(nonce) != 32:
            raise ValueError(f"challenge nonce must be 32 bytes, got {len(nonce)}")
        # Server spec requires an Ed25519/LibNaCL signature over the raw nonce bytes.
        return default_eccrypto.create_signature(self.my_peer.key, nonce)

    def find_server_peer(self, server_public_key: bytes) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == server_public_key:
                return peer
        return None

    def get_discovered_peers(self) -> list[Peer]:
        return self.get_peers()

    def find_member_peers(self, member_public_keys: tuple[bytes, bytes, bytes]) -> dict[bytes, Peer]:
        member_key_set = set(member_public_keys)
        return {
            peer.public_key.key_to_bin(): peer
            for peer in self.get_peers()
            if peer.public_key.key_to_bin() in member_key_set
        }

    def send_group_message(self, peer: Peer, message: str) -> None:
        self.ez_send(peer, GroupMessagePayload(message))

    def send_nonce_to_sign(
        self,
        peer: Peer,
        group_id: str,
        round_number: int,
        nonce: bytes,
        deadline: float,
    ) -> None:
        # Internal packets are also authenticated with ez_send, so teammates can verify who sent the nonce.
        self.ez_send(peer, NonceToSignPayload(group_id, round_number, nonce, deadline))

    def send_signature_share(
        self,
        peer: Peer,
        group_id: str,
        round_number: int,
        nonce: bytes,
        signature: bytes,
    ) -> None:
        # The signature itself covers the raw nonce; ez_send separately authenticates the transport packet.
        self.ez_send(peer, SignatureSharePayload(group_id, round_number, nonce, signature))

    async def wait_for_nonce_to_sign(self, timeout: float) -> NonceToSign:
        self._nonce_to_sign = asyncio.get_running_loop().create_future()
        if self._pending_nonces_to_sign:
            self._nonce_to_sign.set_result(self._pending_nonces_to_sign.pop(0))

        try:
            return await asyncio.wait_for(self._nonce_to_sign, timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"Timed out waiting for nonce-to-sign after {timeout:.2f} seconds") from exc
        finally:
            self._nonce_to_sign = None

    def prepare_signature_share_queue(self) -> None:
        # Submitters call this before sending nonces so incoming shares are queued immediately.
        self._signature_share_queue = asyncio.Queue()
        while self._pending_signature_shares:
            self._signature_share_queue.put_nowait(self._pending_signature_shares.pop(0))

    async def wait_for_signature_share(self, timeout: float) -> SignatureShare:
        if self._signature_share_queue is None:
            self.prepare_signature_share_queue()

        try:
            return await asyncio.wait_for(self._signature_share_queue.get(), timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"Timed out waiting for signature share after {timeout:.2f} seconds") from exc

    def clear_signature_share_queue(self) -> None:
        self._signature_share_queue = None

    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer: Peer, payload: RegisterResponsePayload) -> None:
        # lazy_wrapper already verifies the packet signature; this check ensures it was the server's key.
        if peer.public_key.key_to_bin() != self._expected_server_public_key:
            return
        if self._registration_response and not self._registration_response.done():
            self._registration_response.set_result(
                RegistrationResult(
                    success=payload.success,
                    group_id=payload.group_id,
                    message=payload.message,
                )
            )

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
        if peer.public_key.key_to_bin() != self._expected_server_public_key:
            return
        if self._challenge_response and not self._challenge_response.done():
            self._challenge_response.set_result(
                ChallengeResponse(
                    nonce=payload.nonce,
                    round_number=payload.round_number,
                    deadline=payload.deadline,
                )
            )

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload: RoundResultPayload) -> None:
        if peer.public_key.key_to_bin() != self._expected_server_public_key:
            return

        result = RoundResult(
            success=payload.success,
            round_number=payload.round_number,
            rounds_completed=payload.rounds_completed,
            message=payload.message,
        )
        if self._challenge_response and not self._challenge_response.done():
            self._challenge_response.set_result(result)
        if self._round_result and not self._round_result.done():
            self._round_result.set_result(result)

    @lazy_wrapper(GroupMessagePayload)
    def on_group_message(self, peer: Peer, payload: GroupMessagePayload) -> None:
        sender_public_key = peer.public_key.key_to_bin()
        if self.member_public_keys and sender_public_key not in self.member_public_keys:
            print(f"Ignored group message from non-member peer: {sender_public_key.hex()}")
            return

        self.received_group_messages.append(
            GroupMessage(
                sender_public_key=sender_public_key,
                sender_mid=peer.mid,
                message=payload.message,
            )
        )
        print(
            "Received group message "
            f"from mid={peer.mid.hex()} public_key={sender_public_key.hex()}: {payload.message}"
        )

    @lazy_wrapper(NonceToSignPayload)
    def on_nonce_to_sign(self, peer: Peer, payload: NonceToSignPayload) -> None:
        sender_public_key = peer.public_key.key_to_bin()
        if self.member_public_keys and sender_public_key not in self.member_public_keys:
            print(f"Ignored nonce-to-sign from non-member peer: {sender_public_key.hex()}")
            return

        message = NonceToSign(
            sender_public_key=sender_public_key,
            sender_mid=peer.mid,
            group_id=payload.group_id,
            round_number=payload.round_number,
            nonce=payload.nonce,
            deadline=payload.deadline,
        )
        if self._nonce_to_sign and not self._nonce_to_sign.done():
            self._nonce_to_sign.set_result(message)
        else:
            self._pending_nonces_to_sign.append(message)

    @lazy_wrapper(SignatureSharePayload)
    def on_signature_share(self, peer: Peer, payload: SignatureSharePayload) -> None:
        sender_public_key = peer.public_key.key_to_bin()
        if self.member_public_keys and sender_public_key not in self.member_public_keys:
            print(f"Ignored signature share from non-member peer: {sender_public_key.hex()}")
            return

        share = SignatureShare(
            sender_public_key=sender_public_key,
            sender_mid=peer.mid,
            group_id=payload.group_id,
            round_number=payload.round_number,
            nonce=payload.nonce,
            signature=payload.signature,
        )
        if self._signature_share_queue is not None:
            self._signature_share_queue.put_nowait(share)
        else:
            self._pending_signature_shares.append(share)
