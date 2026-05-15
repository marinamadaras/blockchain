# blockchain-engineering-project
For the TUDelft course CS4160

## Requirements

- Python 3.10+
- py-ipv8 library: https://github.com/Tribler/py-ipv8
- py-ipv8 documentation: https://py-ipv8.readthedocs.io/

## Setup

Install the project and Python dependency with:

```bash
python3 -m pip install -e .
```

## Group Registration

Copy `config/lab_client.example.json` to a local config file and fill in:

- `private_key_file` for the member that sends the registration
- `member_public_keys` in the canonical order for later signature bundles

The client discovers the server through IPv8 peer discovery by matching `server_public_key`, so no fixed server host or
port is needed in the config.

### Key Management

Each group member only needs their own private key. Do not share private keys between members.

For registration, the config needs:

- your own private key file in `private_key_file`
- all three group members' public keys in `member_public_keys`

The order of `member_public_keys` is important. It becomes the canonical signature order for later bundle submissions.
All group members should use the same order in their configs.

The server still requires the sender to be one of the listed public keys. That means the private key in
`private_key_file` should match one of the three public keys in `member_public_keys`.

Private keys should be placed under `keys/`. That directory is ignored by Git.

Print the public key hex for an existing member key with:

```bash
lab-key keys/member1_private.pem
```

Put the printed public key into `member_public_keys`.

### Running Registration

Create or update your local config:

```bash
cp config/lab_client.example.json config/lab_client.local.json
```

Fill in:

- `private_key_file`, for example `../keys/member1_private.pem`
- the three `member_public_keys`
- optionally `listen_port` if another local IPv8 client is already using the default port

Run registration with:

```bash
register-lab-group --config config/lab_client.local.json
```

The command will:

- start an IPv8 node
- join the lab group-signing community
- discover peers through IPv8 random walk and bootstrappers
- find the lab server by matching `server_public_key`
- send the group registration payload with the three public keys
- print the server response: `success`, `group_id`, and `message`

## Group Member Discovery

Your teammates appear as peers in the same Lab 2 IPv8 community. The client can discover all peers in the community and
filter the known group members by the public keys in `member_public_keys`.

Run teammate discovery with:

```bash
discover-lab-members --config config/lab_client.local.json
```

Your local private key must match one of the three configured public keys. If it does not, discovery fails immediately.
Otherwise, the command expects to find the other two members.

You can also send a signed group-internal test message to discovered members:

```bash
discover-lab-members --config config/lab_client.local.json --send "hello from member1"
```

Group-internal messages are sent inside the same Lab 2 community with IPv8 authenticated messaging. The receiver checks
the sender from the packet signature, ignores messages from public keys outside `member_public_keys`, and prints the
sender MID and public key for accepted messages.

## Session Preparation

Before timed challenge rounds, prepare the network topology without requesting any server challenge:

```bash
prepare-lab-session --config config/lab_client.local.json
```

This trigger:

- starts IPv8 and joins the Lab 2 community
- verifies your local private key matches one of `member_public_keys`
- discovers the lab server by `server_public_key`
- discovers the other two group members by `member_public_keys`
- writes the discovered server/member addresses to `session_cache_file`

This command does not send a challenge request, so it does not start the 10-second round budget.

## Round Runner

After registration and session preparation, start the round runner with:

```bash
run-lab-rounds --config config/lab_client.local.json --round 1
```

The runner starts at the selected round and continues through round 3:

- infers your member number from `member_public_keys`
- infers the submitter for the round from registration order
- if you are the submitter, sends `ChallengeRequestPayload` (`message_id=3`) to the server
- accepts either `ChallengeResponsePayload` (`message_id=4`) or early `RoundResultPayload` (`message_id=6`)
- if you are the submitter, signs the raw 32-byte nonce, sends it to teammates, collects signature shares, and submits
  `SignatureBundlePayload` (`message_id=5`) to the server
- if a teammate signature share does not arrive before the configured timeout, the submitter re-sends
  `NonceToSignPayload` only to the still-missing teammate(s)
- if you are not the submitter, waits for `NonceToSignPayload`, signs the raw nonce, and returns `SignatureSharePayload`
  to the submitter
- after sending a signature, if this peer is the next round's submitter, it immediately polls the server until the
  challenge response reports that next round
- while that next submitter is polling the server, it still handles incoming `NonceToSignPayload` messages and returns
  signature shares instead of blocking solely on server responses
- peers that are not next-round submitters stay alive and wait for the next submitter's nonce

The config must include `group_id`, which is returned by successful registration.

### Multi-Round Workflow

The submitter for each round is derived from registration order:

- round 1 submitter: `member_public_keys[0]`
- round 2 submitter: `member_public_keys[1]`
- round 3 submitter: `member_public_keys[2]`

All three members run the same command. The local private key decides which branch each process follows.

For each round:

1. The designated submitter asks the server for the current challenge.
2. The server returns the nonce, round number, and shared deadline.
3. The submitter signs the raw nonce locally and sends `NonceToSignPayload` to the other two members.
4. Each signer signs the same raw nonce and sends `SignatureSharePayload` back.
5. The submitter gathers all three signatures, restores registration order, and submits `SignatureBundlePayload`.
6. The server returns `RoundResultPayload`.

The handoff to the next round is intentionally eager:

- after a signer returns its signature, it advances toward the next loop iteration
- if that signer is the next round's submitter, it polls the server until the returned `round_number` advances
- while polling the server, it still services incoming `NonceToSignPayload` work instead of blocking solely on the
  server response
- if a submitter times out waiting for one or more teammate signatures, it re-sends the nonce only to the missing peers
- ordinary signers tolerate nonce requests from any valid round, sign them, and continue waiting for the round they
  currently need

## Code Layout

- `src/lab_group_client/config.py`
  Loads the JSON config, validates the three public keys, requires the private key file to exist, stores timing values
  for challenge polling and nonce resends, and builds the IPv8 config with random-walk server discovery.

- `src/lab_group_client/community.py`
  Defines the IPv8 protocol messages and community logic. `RegisterPayload` is `message_id=1`.
  `RegisterResponsePayload` is `message_id=2`. Challenge/server messages are `message_id=3` through `6`.
  Group-internal nonce/signature messages are `NonceToSignPayload` (`message_id=101`) and
  `SignatureSharePayload` (`message_id=102`). This file sends authenticated IPv8 messages, validates server responses
  against the configured server public key, signs raw nonces, and buffers inbound nonce/signature work so fast messages
  are not lost between awaits.

- `src/lab_group_client/register_group.py`
  CLI workflow for registration. It starts IPv8, waits until the server is discovered by public key, calls the community
  registration method, and prints the result.

- `src/lab_group_client/discover_members.py`
  Separate CLI workflow for teammate discovery. It starts IPv8, filters discovered peers by `member_public_keys`, and
  can optionally send a group-internal test message to each matched teammate.

- `src/lab_group_client/prepare_session.py`
  Combined setup trigger for later timed rounds. It discovers the server and teammates, validates the local key belongs
  to the group, and writes a session cache.

- `src/lab_group_client/run_rounds.py`
  Challenge runner from the selected start round through round 3. It requests challenges for the round submitter, sends
  nonces to teammates, collects signature shares in registration order, re-sends missing nonce requests, submits
  bundles, lets the next submitter poll the server until the next round is active, and keeps servicing nonce-sign work
  while that polling is in progress.

- `src/lab_group_client/keys.py`
  Small helper CLI for printing the public key hex from an existing private key file.

- `config/lab_client.example.json`
  Template config. Copy this to a local config and fill in real key values.

- `requirements.txt` and `pyproject.toml`
  Python dependency and install metadata. The installable package is `pyipv8`, while the upstream repository is
  `Tribler/py-ipv8`.

## Signature Order

- marina
- ada
- galya
