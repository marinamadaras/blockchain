from __future__ import annotations

import argparse
import asyncio
import sys

from ipv8.peer import Peer
from ipv8_service import IPv8

from lab_group_client.community import LabGroupSigningCommunity
from lab_group_client.config import LabClientConfig, ipv8_configuration


def describe_peer(peer: Peer) -> str:
    return (
        f"address={peer.address} "
        f"mid={peer.mid.hex()} "
        f"public_key={peer.public_key.key_to_bin().hex()}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover configured group members in the Lab 2 IPv8 community.")
    parser.add_argument(
        "--config",
        default="config/lab_client.example.json",
        help="Path to the lab client JSON config.",
    )
    parser.add_argument(
        "--send",
        default=None,
        help="Optional group-internal message to send to each discovered teammate.",
    )
    parser.add_argument(
        "--wait-after-send",
        type=float,
        default=2.0,
        help="How long to keep listening after sending a group message.",
    )
    return parser.parse_args()


def member_label(config: LabClientConfig, public_key: bytes) -> str:
    try:
        return f"member{config.member_public_keys.index(public_key) + 1}"
    except ValueError:
        return "unknown-member"


async def discover_members(config: LabClientConfig, message: str | None, wait_after_send: float) -> int:
    ipv8 = IPv8(
        ipv8_configuration(config),
        extra_communities={"LabGroupSigningCommunity": LabGroupSigningCommunity},
    )
    await ipv8.start()
    try:
        community = ipv8.get_overlay(LabGroupSigningCommunity)
        if community is None or not isinstance(community, LabGroupSigningCommunity):
            raise RuntimeError("failed to load LabGroupSigningCommunity overlay")

        print(f"Using identity file: {config.private_key_file}")
        print(f"Joined community: {config.community_id.hex()}")
        print("Discovering configured group members...")

        local_public_key = community.my_peer.public_key.key_to_bin()
        if local_public_key not in config.member_public_keys:
            raise ValueError(
                "local private key does not match any configured member_public_keys entry; "
                f"local public key is {local_public_key.hex()}"
            )

        expected_peer_count = 2
        deadline = asyncio.get_running_loop().time() + config.discovery_timeout
        seen_member_keys: set[bytes] = set()
        seen_other_keys: set[bytes] = set()

        while True:
            member_peers = community.find_member_peers(config.member_public_keys)
            for public_key, peer in member_peers.items():
                if public_key not in seen_member_keys:
                    seen_member_keys.add(public_key)
                    print(f"Matched {member_label(config, public_key)}: {describe_peer(peer)}")

            # Walk directly to every peer we've found. This keeps NAT holes open and
            # ensures teammates can see us by forcing bidirectional contact.
            for peer in member_peers.values():
                community.walk_to(peer.address)
                community.send_group_message(peer, "hello")

            if len(member_peers) >= expected_peer_count:
                print("All expected peers discovered. Stabilizing connections...")
                stabilize_until = asyncio.get_running_loop().time() + 15
                while asyncio.get_running_loop().time() < stabilize_until:
                    for peer in member_peers.values():
                        community.walk_to(peer.address)
                    await asyncio.sleep(1)
                break

            for peer in community.get_discovered_peers():
                public_key = peer.public_key.key_to_bin()
                if public_key not in member_peers and public_key not in seen_other_keys:
                    seen_other_keys.add(public_key)
                    print(f"Discovered non-group peer: {describe_peer(peer)}")

            if asyncio.get_running_loop().time() >= deadline:
                expected = ", ".join(key.hex() for key in config.member_public_keys)
                raise TimeoutError(
                    "timed out waiting for group members; discovered "
                    f"{len(member_peers)} configured member peer(s). Expected keys: {expected}"
                )

            print(
                f"Matched {len(member_peers)}/{expected_peer_count} expected configured member peer(s); "
                "still discovering..."
            )
            await asyncio.sleep(config.discovery_poll_interval)

        print(f"Matched {len(member_peers)}/{expected_peer_count} expected configured member peer(s).")

        if message is not None:
            for public_key, peer in member_peers.items():
                print(f"Sending group message to {member_label(config, public_key)} at {peer.address}")
                community.send_group_message(peer, message)
            await asyncio.sleep(wait_after_send)

        return 0
    finally:
        await ipv8.stop()


def main() -> int:
    args = parse_args()
    try:
        config = LabClientConfig.from_file(args.config)
        return asyncio.run(discover_members(config, args.send, args.wait_after_send))
    except Exception as exc:
        print(f"member discovery failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
