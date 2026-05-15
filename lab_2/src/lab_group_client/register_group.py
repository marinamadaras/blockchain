from __future__ import annotations

import argparse
import asyncio
import sys

from ipv8_service import IPv8

from lab_group_client.community import LabGroupSigningCommunity
from lab_group_client.config import LabClientConfig, ipv8_configuration


def describe_peer(peer) -> str:
    return (
        f"address={peer.address} "
        f"mid={peer.mid.hex()} "
        f"public_key={peer.public_key.key_to_bin().hex()}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Register a 3-member lab group with the IPv8 challenge server.")
    parser.add_argument(
        "--config",
        default="config/lab_client.example.json",
        help="Path to the lab client JSON config.",
    )
    return parser.parse_args()


async def discover_server(community: LabGroupSigningCommunity, config: LabClientConfig):
    print(f"Using identity file: {config.private_key_file}")
    print(f"Joined community: {config.community_id.hex()}")
    print(f"Expecting server public key: {config.server_public_key.hex()}")
    print("Starting peer discovery...")

    deadline = asyncio.get_running_loop().time() + config.discovery_timeout
    seen_peers: set[str] = set()

    while True:
        server_peer = community.find_server_peer(config.server_public_key)
        if server_peer is not None:
            print("Matched server peer by public key.")
            print(f"Server address: {server_peer.address}")
            print(f"Server MID: {server_peer.mid.hex()}")
            return server_peer

        peers = community.get_discovered_peers()
        for peer in peers:
            peer_key_hex = peer.public_key.key_to_bin().hex()
            if peer_key_hex not in seen_peers:
                seen_peers.add(peer_key_hex)
                print(f"Discovered non-server peer: {describe_peer(peer)}")

        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(
                "timed out waiting for the lab server peer; peer discovery may still be working, "
                "but the configured server public key was not found"
            )

        if not peers:
            print("No peers discovered yet.")
        else:
            print(f"Discovered {len(peers)} peer(s); server not matched yet.")

        await asyncio.sleep(config.discovery_poll_interval)


async def register(config: LabClientConfig) -> int:
    # Start an IPv8 node that joins the lab community and discovers peers through random walk.
    ipv8 = IPv8(
        ipv8_configuration(config),
        extra_communities={"LabGroupSigningCommunity": LabGroupSigningCommunity},
    )
    await ipv8.start()
    try:
        community = ipv8.get_overlay(LabGroupSigningCommunity)
        if community is None or not isinstance(community, LabGroupSigningCommunity):
            raise RuntimeError("failed to load LabGroupSigningCommunity overlay")

        server_peer = await discover_server(community, config)

        # This sends message_id=1 and waits for message_id=2 from the configured server key.
        result = await community.register_group(
            server_peer=server_peer,
            member_public_keys=config.member_public_keys,
            timeout=config.registration_timeout,
        )
        # Keep output easy to parse from scripts or a terminal.
        print(f"success={result.success}")
        print(f"group_id={result.group_id}")
        print(f"message={result.message}")
        return 0 if result.success else 1
    finally:
        await ipv8.stop()


def main() -> int:
    args = parse_args()
    try:
        # All lab-specific parameters live in JSON so different members can reuse the same code.
        config = LabClientConfig.from_file(args.config)
        return asyncio.run(register(config))
    except Exception as exc:
        print(f"registration failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
