from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from ipv8.messaging.interfaces.udp.endpoint import UDPv4Address
from ipv8.peer import Peer
from ipv8_service import IPv8

from lab_group_client.community import ChallengeResponse, LabGroupSigningCommunity, RoundResult, SignatureShare
from lab_group_client.config import LabClientConfig, ipv8_configuration
from lab_group_client.register_group import describe_peer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Runner for Lab 2 challenge/signature rounds.")
    parser.add_argument(
        "--config",
        default="config/lab_client.example.json",
        help="Path to the lab client JSON config.",
    )
    parser.add_argument(
        "--round",
        type=int,
        default=1,
        choices=(1, 2, 3),
        help="Round number to start from. The runner continues through round 3.",
    )
    return parser.parse_args()


def member_number_for_public_key(config: LabClientConfig, public_key: bytes) -> int:
    try:
        return config.member_public_keys.index(public_key) + 1
    except ValueError as exc:
        raise ValueError(
            "local private key does not match any configured member_public_keys entry; "
            f"local public key is {public_key.hex()}"
        ) from exc


def submitter_public_key(config: LabClientConfig, round_number: int) -> bytes:
    # Submitter order is inferred directly from registration order.
    return config.member_public_keys[round_number - 1]


def ready_message(config: LabClientConfig, start_round: int) -> str:
    return f"run-rounds-ready:{config.group_id}:{start_round}"


def timeout_before_deadline(deadline: float, fallback: float) -> float:
    # Once the server provides a deadline, no wait should exceed the remaining wall-clock budget.
    remaining = deadline - time.time()
    if remaining <= 0:
        raise TimeoutError("server challenge deadline has already passed")
    return min(fallback, remaining)


def bounded_timeout(total_deadline: float, fallback: float) -> float:
    remaining = total_deadline - time.time()
    if remaining <= 0:
        raise TimeoutError("timed out waiting for expected server round")
    return min(fallback, remaining)


def validate_signature_share(
    config: LabClientConfig,
    share: SignatureShare,
    round_number: int,
    nonce: bytes,
    expected_signers: set[bytes],
) -> bool:
    # Keep validation close to collection so bad/late/wrong-round shares do not poison the bundle.
    if share.sender_public_key not in expected_signers:
        print(f"Ignored signature share from unexpected signer: {share.sender_public_key.hex()}")
        return False
    if share.group_id != config.group_id:
        print(f"Ignored signature share for unexpected group_id: {share.group_id}")
        return False
    if share.round_number != round_number:
        print(f"Ignored signature share for round {share.round_number}; expected {round_number}")
        return False
    if share.nonce != nonce:
        print(f"Ignored signature share with mismatched nonce from {share.sender_public_key.hex()}")
        return False
    return True


async def collect_signature_shares(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
    round_number: int,
    nonce: bytes,
    deadline: float,
    expected_signers: set[bytes],
    member_peers: dict[bytes, Peer],
) -> dict[bytes, bytes]:
    # Submitter waits until both teammates have returned valid signatures for this exact nonce.
    signatures: dict[bytes, bytes] = {}
    while expected_signers - signatures.keys():
        timeout = timeout_before_deadline(deadline, config.signature_share_timeout)
        try:
            share = await community.wait_for_signature_share(timeout=timeout)
        except TimeoutError:
            missing_signers = expected_signers - signatures.keys()
            print(
                "Timed out waiting for signature share; resending nonce to "
                f"{len(missing_signers)} missing teammate(s)."
            )
            for signer_key in missing_signers:
                peer = member_peers[signer_key]
                community.send_nonce_to_sign(
                    peer,
                    group_id=config.group_id,
                    round_number=round_number,
                    nonce=nonce,
                    deadline=deadline,
                )
                print(
                    f"Re-sent nonce to member{member_number_for_public_key(config, signer_key)} at {peer.address}"
                )
            resend_sleep = timeout_before_deadline(deadline, config.nonce_resend_interval)
            await asyncio.sleep(resend_sleep)
            continue
        if not validate_signature_share(config, share, round_number, nonce, expected_signers):
            continue
        signatures[share.sender_public_key] = share.signature
        print(f"Collected signature from member{member_number_for_public_key(config, share.sender_public_key)}")
    return signatures


async def request_expected_challenge(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
    server_peer: Peer,
    member_peers: dict[bytes, Peer],
    expected_round: int,
    known_server_deadline: float | None,
) -> ChallengeResponse:
    # The next submitter may ask slightly before the previous bundle is recorded.
    # In that case the server can return the previous active round; keep polling until it advances.
    # While polling, keep servicing teammate nonce messages instead of blocking solely on server responses.
    total_deadline = known_server_deadline if known_server_deadline is not None else time.time() + config.challenge_timeout
    while True:
        timeout = bounded_timeout(total_deadline, config.challenge_timeout)
        challenge_task = asyncio.create_task(
            community.request_challenge(
                server_peer=server_peer,
                group_id=config.group_id,
                timeout=timeout,
            )
        )
        nonce_task = asyncio.create_task(
            community.wait_for_nonce_to_sign(timeout=timeout)
        )
        done, _ = await asyncio.wait(
            {challenge_task, nonce_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        if challenge_task in done:
            if nonce_task in done:
                try:
                    nonce_message = nonce_task.result()
                except TimeoutError:
                    pass
                else:
                    await sign_and_return_nonce_message(
                        community=community,
                        config=config,
                        member_peers=member_peers,
                        nonce_message=nonce_message,
                        expected_round=None,
                    )
            else:
                nonce_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await nonce_task
            outcome = challenge_task.result()
        else:
            challenge_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await challenge_task
            try:
                nonce_message = nonce_task.result()
            except TimeoutError:
                continue
            await sign_and_return_nonce_message(
                community=community,
                config=config,
                member_peers=member_peers,
                nonce_message=nonce_message,
                expected_round=None,
            )
            continue

        if isinstance(outcome, ChallengeResponse):
            print(f"Received challenge response for round {outcome.round_number}")
            if outcome.round_number == expected_round:
                return outcome
            if outcome.round_number < expected_round:
                print(
                    f"Server is still on round {outcome.round_number}; "
                    f"polling for round {expected_round}..."
                )
                await asyncio.sleep(config.next_challenge_retry_delay)
                continue
            raise RuntimeError(f"server returned future round {outcome.round_number}; expected {expected_round}")

        if isinstance(outcome, RoundResult):
            print(f"Server returned round result while polling: {outcome.message}")
            if not outcome.success and (
                "group not found" in outcome.message
                or "requester is not a member" in outcome.message
                or "already completed" in outcome.message
            ):
                raise RuntimeError(outcome.message)
            await asyncio.sleep(config.next_challenge_retry_delay)
            continue

        raise RuntimeError(f"unexpected challenge outcome: {outcome!r}")


async def sign_and_return_nonce_message(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
    member_peers: dict[bytes, Peer],
    nonce_message,
    expected_round: int | None,
) -> float:
    # Validate sender identity from authenticated IPv8 metadata, not from an untrusted payload field.
    payload_round = nonce_message.round_number
    expected_submitter = submitter_public_key(config, payload_round)
    submitter_peer = member_peers.get(expected_submitter)
    if submitter_peer is None:
        raise ValueError(
            f"discovered topology does not contain submitter peer for member{payload_round}; "
            "restart run-lab-rounds while all members are online"
        )
    if expected_round is not None and payload_round != expected_round:
        raise ValueError(f"nonce-to-sign is for round {payload_round}, expected {expected_round}")
    if nonce_message.sender_public_key != expected_submitter:
        raise ValueError(
            "nonce-to-sign came from the wrong submitter: "
            f"{nonce_message.sender_public_key.hex()}"
        )
    if nonce_message.group_id != config.group_id:
        raise ValueError(f"nonce-to-sign has unexpected group_id: {nonce_message.group_id}")

    signature = community.sign_nonce(nonce_message.nonce)
    community.send_signature_share(
        submitter_peer,
        group_id=config.group_id,
        round_number=payload_round,
        nonce=nonce_message.nonce,
        signature=signature,
    )
    print(f"Sent signature share to member{payload_round}: {signature.hex()}")
    return nonce_message.deadline


async def run_as_signer(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
    member_peers: dict[bytes, Peer],
    round_number: int,
    known_server_deadline: float | None = None,
) -> float:
    print(f"Waiting for nonce from member{round_number}...")
    while True:
        if known_server_deadline is not None:
            timeout = timeout_before_deadline(known_server_deadline, config.nonce_to_sign_timeout)
        else:
            timeout = config.nonce_to_sign_timeout
        try:
            nonce_message = await community.wait_for_nonce_to_sign(timeout=timeout)
        except TimeoutError:
            print(f"Timed out waiting for nonce from member{round_number}; still waiting...")
            continue
        # Sign every valid nonce request we receive. This keeps resends and overlapping round traffic moving.
        deadline = await sign_and_return_nonce_message(
            community=community,
            config=config,
            member_peers=member_peers,
            nonce_message=nonce_message,
            expected_round=None,
        )
        if nonce_message.round_number == round_number:
            return deadline
        print(
            f"Handled nonce for round {nonce_message.round_number} while waiting for round {round_number}; "
            "continuing to wait."
        )


async def run_as_submitter(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
    server_peer: Peer,
    member_peers: dict[bytes, Peer],
    round_number: int,
    known_server_deadline: float | None,
) -> float:
    local_public_key = community.my_peer.public_key.key_to_bin()
    expected_teammate_keys = {key for key in config.member_public_keys if key != local_public_key}
    missing_peers = expected_teammate_keys - member_peers.keys()
    if missing_peers:
        missing = ", ".join(key.hex() for key in missing_peers)
        raise ValueError(f"discovered topology is missing teammate peer(s): {missing}")

    outcome = await request_expected_challenge(
        community=community,
        config=config,
        server_peer=server_peer,
        member_peers=member_peers,
        expected_round=round_number,
        known_server_deadline=known_server_deadline,
    )

    print("Using challenge response:")
    print(f"round_number={outcome.round_number}")
    print(f"deadline={outcome.deadline}")
    print(f"nonce={outcome.nonce.hex()}")

    own_signature = community.sign_nonce(outcome.nonce)
    print(f"own_signature={own_signature.hex()}")
    community.prepare_signature_share_queue()
    try:
        # Fan out the server nonce to the two non-submitters.
        for teammate_key in expected_teammate_keys:
            peer = member_peers[teammate_key]
            community.send_nonce_to_sign(
                peer,
                group_id=config.group_id,
                round_number=outcome.round_number,
                nonce=outcome.nonce,
                deadline=outcome.deadline,
            )
            print(f"Sent nonce to member{member_number_for_public_key(config, teammate_key)} at {peer.address}")

        # Wait for the two teammate signatures over the same raw nonce.
        collected_signatures = await collect_signature_shares(
            community=community,
            config=config,
            round_number=outcome.round_number,
            nonce=outcome.nonce,
            deadline=outcome.deadline,
            expected_signers=expected_teammate_keys,
            member_peers=member_peers,
        )
    finally:
        community.clear_signature_share_queue()

    signatures_by_key = {
        local_public_key: own_signature,
        **collected_signatures,
    }
    # The server requires sig1/sig2/sig3 to match the original registration order.
    signatures = tuple(signatures_by_key[key] for key in config.member_public_keys)

    result = await community.submit_signature_bundle(
        server_peer=server_peer,
        group_id=config.group_id,
        round_number=outcome.round_number,
        signatures=signatures,
        timeout=timeout_before_deadline(outcome.deadline, config.bundle_result_timeout),
    )
    print("Received round result:")
    print(f"success={result.success}")
    print(f"round_number={result.round_number}")
    print(f"rounds_completed={result.rounds_completed}")
    print(f"message={result.message}")
    if not result.success:
        raise RuntimeError(result.message)
    return outcome.deadline


async def wait_for_ready_topology(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
) -> tuple[Peer, dict[bytes, Peer]]:
    local_public_key = community.my_peer.public_key.key_to_bin()
    if local_public_key not in config.member_public_keys:
        raise ValueError(
            "local private key does not match any configured member_public_keys entry; "
            f"local public key is {local_public_key.hex()}"
        )

    print(f"Using identity file: {config.private_key_file}")
    print(f"Joined community: {config.community_id.hex()}")
    print(f"Expecting server public key: {config.server_public_key.hex()}")
    print("Discovering server and group members...")

    deadline = asyncio.get_running_loop().time() + config.discovery_timeout
    seen_peer_keys: set[bytes] = set()
    server_peer: Peer | None = None
    member_peers: dict[bytes, Peer] = {}

    while True:
        server_peer = community.find_server_peer(config.server_public_key) or server_peer
        member_peers = community.find_member_peers(config.member_public_keys)

        for peer in community.get_discovered_peers():
            public_key = peer.public_key.key_to_bin()
            if public_key in seen_peer_keys:
                continue
            seen_peer_keys.add(public_key)

            if public_key == config.server_public_key:
                print(f"Matched server: {describe_peer(peer)}")
            elif public_key in config.member_public_keys:
                print(f"Matched {f"member{config.member_public_keys.index(public_key) + 1}"}: {describe_peer(peer)}")
            else:
                print(f"Discovered non-group peer: {describe_peer(peer)}")

        # Walk directly to every peer we've already found. This keeps NAT holes open and
        # makes us visible to peers who learned our address from the bootstrap but couldn't
        # reach us yet because no outgoing packet from us had opened a mapping their way.
        if server_peer is not None:
            community.walk_to(server_peer.address)
        for peer in member_peers.values():
            community.walk_to(peer.address)

        # Send hello messages to confirm bidirectional connectivity with member peers.
        for peer in member_peers.values():
            community.send_group_message(peer, "hello")

        if server_peer is not None and len(member_peers) >= 2:
            return server_peer, member_peers

        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(
                "timed out preparing session; "
                f"server_found={server_peer is not None}, member_peers_found={len(member_peers)}/2"
            )

        print(
            "Still preparing: "
            f"server_found={server_peer is not None}, member_peers_found={len(member_peers)}/2"
        )
        await asyncio.sleep(config.discovery_poll_interval)


async def wait_for_all_members_ready(
    community: LabGroupSigningCommunity,
    config: LabClientConfig,
    member_peers: dict[bytes, Peer],
    local_public_key: bytes,
    local_member_number: int,
    start_round: int,
) -> None:
    expected_teammate_keys = {key for key in config.member_public_keys if key != local_public_key}
    missing_peers = expected_teammate_keys - member_peers.keys()
    if missing_peers:
        missing = ", ".join(key.hex() for key in missing_peers)
        raise ValueError(f"discovered topology is missing teammate peer(s): {missing}")

    message = ready_message(config, start_round)
    deadline = asyncio.get_running_loop().time() + config.discovery_timeout
    announced_count = 0
    all_ready_count = 0
    stabilization_rounds = 3  # Extra rounds after all ready to ensure bidirectional discovery

    print("Waiting until every member has finished discovery before requesting any challenge...")
    while True:
        ready_teammates = {
            group_message.sender_public_key
            for group_message in community.received_group_messages
            if group_message.message == message and group_message.sender_public_key in expected_teammate_keys
        }
        if ready_teammates == expected_teammate_keys:
            all_ready_count += 1
            if all_ready_count >= stabilization_rounds:
                print("All members are ready and connections stabilized; starting challenge rounds.")
                return
        else:
            all_ready_count = 0

        if asyncio.get_running_loop().time() >= deadline:
            missing_ready = expected_teammate_keys - ready_teammates
            missing = ", ".join(
                f"member{member_number_for_public_key(config, key)}" for key in missing_ready
            )
            raise TimeoutError(f"timed out waiting for ready signal from: {missing}")

        announced_count += 1
        for teammate_key in expected_teammate_keys:
            peer = member_peers[teammate_key]
            community.send_group_message(peer, message)
            print(
                f"Announced member{local_member_number} ready to "
                f"member{member_number_for_public_key(config, teammate_key)} at {peer.address} "
                f"(attempt {announced_count})"
            )

        print(
            f"Ready barrier: received {len(ready_teammates)}/{len(expected_teammate_keys)} "
            "teammate ready signal(s)." + (
                f" (stabilizing connection: {all_ready_count}/{stabilization_rounds})"
                if ready_teammates == expected_teammate_keys else ""
            )
        )
        await asyncio.sleep(config.discovery_poll_interval)


async def run_rounds(config: LabClientConfig, start_round: int) -> int:
    if not config.group_id or config.group_id.startswith("replace-with"):
        raise ValueError("config.group_id must be set to the group_id returned by registration")

    ipv8 = IPv8(
        ipv8_configuration(config),
        extra_communities={"LabGroupSigningCommunity": LabGroupSigningCommunity},
    )
    await ipv8.start()
    try:
        community = ipv8.get_overlay(LabGroupSigningCommunity)
        if community is None or not isinstance(community, LabGroupSigningCommunity):
            raise RuntimeError("failed to load LabGroupSigningCommunity overlay")

        local_public_key = community.my_peer.public_key.key_to_bin()
        local_member_number = member_number_for_public_key(config, local_public_key)
        print(f"Local member number from registration order: {local_member_number}")

        server_peer, member_peers = await wait_for_ready_topology(community, config)

        # Send hello messages to confirm bidirectional connectivity with discovered peers.
        for peer in member_peers.values():
            community.send_group_message(peer, "hello")

        print("Discovery complete.")
        await wait_for_all_members_ready(
            community=community,
            config=config,
            member_peers=member_peers,
            local_public_key=local_public_key,
            local_member_number=local_member_number,
            start_round=start_round,
        )

        known_server_deadline: float | None = None
        for round_number in range(start_round, 4):
            expected_submitter = submitter_public_key(config, round_number)
            print(f"Expected submitter for round {round_number}: member{round_number}")

            if local_public_key == expected_submitter:
                known_server_deadline = await run_as_submitter(
                    community=community,
                    config=config,
                    server_peer=server_peer,
                    member_peers=member_peers,
                    round_number=round_number,
                    known_server_deadline=known_server_deadline,
                )
            else:
                known_server_deadline = await run_as_signer(
                    community=community,
                    config=config,
                    member_peers=member_peers,
                    round_number=round_number,
                    known_server_deadline=known_server_deadline,
                )
        return 0
    finally:
        await ipv8.stop()


def main() -> int:
    args = parse_args()
    try:
        config = LabClientConfig.from_file(args.config)
        return asyncio.run(run_rounds(config, args.round))
    except Exception as exc:
        print(f"round runner failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
