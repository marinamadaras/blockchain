import asyncio
import hashlib
import struct
import time

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8
from config import *

class SubmissionMessage(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]

class ServerResponse(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

class Lab1Community(Community):
    community_id = bytes.fromhex(community_id_course)

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        self.add_message_handler(ServerResponse, self.on_response)
        self.server_key = bytes.fromhex(sever_public_key)
        self.submitted = False
        self.done = asyncio.Event()

    def find_server(self):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == self.server_key:
                return peer
        return None

    def try_submit(self, nonce: int):
        if self.submitted:
            return
        server = self.find_server()
        if server is None:
            return
        self.ez_send(server, SubmissionMessage(email, github_url, nonce))
        self.submitted = True
        print("submission sent")

    @lazy_wrapper(ServerResponse)
    def on_response(self, peer: Peer, payload: ServerResponse):
        status = "accepted" if payload.success else "rejected"
        print(f"!!!! server: {status}: {payload.message}")
        self.done.set()


def mine():
    prefix = email.encode() + b"\n" + github_url.encode() + b"\n"
    start_time = time.time()
    nonce = 0

    print("mining :) ...")
    while True:
        nonce_bytes = struct.pack(">q", nonce)
        digest = hashlib.sha256(prefix + nonce_bytes).digest()

        # check if we have 28 leading zero bits
        if digest[:3] == b"\x00\x00\x00" and digest[3] < 0x10:
            now = time.time()
            print(f"\n[*] found nonce={nonce} in {now - start_time:.1f}s")
            return nonce

        if nonce % 1000000 == 0:
            print(f"{nonce // 1000000}M nonces tried...")
        nonce += 1


def create_ipv8(community: type):
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("marina", "curve25519", sk_file)
    builder.add_overlay(
        "Lab1Community", "marina",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 10.0})],
        default_bootstrap_defs, {}, [],
    )
    return IPv8(builder.finalize(), extra_communities={"Lab1Community": community})

async def main():
    nonce = mine()

    ipv8 = create_ipv8(Lab1Community)
    await ipv8.start()

    community = ipv8.get_overlay(Lab1Community)
    for _ in range(60):
        community.try_submit(nonce)
        if community.done.is_set():
            break
        await asyncio.sleep(2)
    else:
        print("timed out, server not found :(")

    await ipv8.stop()

if __name__ == "__main__":
    asyncio.run(main())