# Peer-to-peer handshake

This is a Rust p2p handshake implementation for [CometBFT](https://github.com/cometbft/cometbft) (previously Tendermint Core).

# Running it

## TL;DR

Run these in 2 separate terminals, side by side:
```sh
make run-target
make run-handshake
```

## A more detailed version

### Pre-requisites

The following versions were used during development:
- go 1.21.5 (darwin/arm64)
- cargo/rustc 1.74.1 (a28077b28 2023-12-04)

### Start target p2p node

This project contains a vendered [CometBFT](https://github.com/cometbft/cometbft) under the [`target-node`](./target-node) directory (I used a shallow git subtree, but still the docs directory is around 50Mb, hence the larger size). I intentionally pulled the latest (unstable) code from `main` because I was curious if the handshake worked with the latest development version (it also works with the latest stable release [`v0.38.2`](https://github.com/cometbft/cometbft/tree/v0.38.2)).

This vendored version contains some minor modifications - namely `Printf`'s for info about node startup and successful handshakes.

To run the node:
```sh
make run-target
```

When you first run that, it's going to create the `~/.cometbft/{config,data}`. You might want to delete that afterwards.

### Connect from Rust

Run the Rust part of the handshake in another terminal:
```sh
make run-handshake
```

### Verifying it worked

When the handshake is successful both nodes print info (identical formatting):
```
Peer handshake authorized
    this node = 2c9594256d694681e50f7406b3a094ffefb88bef
  remote node = dd742ac67c5c0a92b40f810bfcb60355db0613a9
```

`this node` ID should match `remote node` ID in the other terminal, and vice versa.

# Implementation

For the handshake entrypoint, please see `src/handshake/mod.rs#do_handshake()`. This function encompasses the handshake interaction. If there are no `Err`'s then the happy path means the connection is authorized by the end of the function, i.e. a successful handshake.

[tendermint-rs](https://github.com/informalsystems/tendermint-rs.git) was an already existing implementation in Rust, and so I used it to bootstrap. Many of the dependencies are re-used as well as [tendermint-proto](https://crates.io/crates/tendermint-proto), the proto struct definitions used by the protocol. Even though this implementation is a complete overhaul, some reused code remains. Were this to become an open source project, this would need to be attributed (as well as a licence included).

## Algorithm

### Authenticated Encryption Handshake

[[source](https://github.com/naartjie/cometbft-handshake/blob/d28ec6840c02e69b86fe400220265bc6934a8a65/target-node/spec/p2p/legacy-docs/peer.md#authenticated-encryption-handshake)]


> CometBFT implements the Station-to-Station protocol
> using X25519 keys for Diffie-Helman key-exchange and chacha20poly1305 for encryption.
>
> Previous versions of this protocol (0.32 and below) suffered from malleability attacks whereas an active man
> in the middle attacker could compromise confidentiality as described in [Prime, Order Please!
> Revisiting Small Subgroup and Invalid Curve Attacks on
> Protocols using Diffie-Hellman](https://eprint.iacr.org/2019/526.pdf).
>
> We have added dependency on the Merlin a keccak based transcript hashing protocol to ensure non-malleability.
>
> It goes as follows:
>
> - generate an ephemeral X25519 keypair
> - send the ephemeral public key to the peer
> - wait to receive the peer's ephemeral public key
> - create a new Merlin Transcript with the string "TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH"
> - Sort the ephemeral keys and add the high labeled "EPHEMERAL_UPPER_PUBLIC_KEY" and the low keys labeled "EPHEMERAL_LOWER_PUBLIC_KEY" to the Merlin transcript.
> - compute the Diffie-Hellman shared secret using the peers ephemeral public key and our ephemeral private key
> - add the DH secret to the transcript labeled DH_SECRET.
> - generate two keys to use for encryption (sending and receiving) and a challenge for authentication as follows:
    > - create a hkdf-sha256 instance with the key being the diffie hellman shared secret, and info parameter as
>     `TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN`
>     - get 64 bytes of output from hkdf-sha256
    > - if we had the smaller ephemeral pubkey, use the first 32 bytes for the key for receiving, the second 32 bytes for sending; else the opposite.
> - use a separate nonce for receiving and sending. Both nonces start at 0, and should support the full 96 bit nonce range
> - all communications from now on are encrypted in 1400 byte frames (plus encoding overhead),
>   using the respective secret and nonce. Each nonce is incremented by one after each use.
> - we now have an encrypted channel, but still need to authenticate
> - extract a 32 bytes challenge from merlin transcript with the label "SECRET_CONNECTION_MAC"
> - sign the common challenge obtained from the hkdf with our persistent private key
> - send the amino encoded persistent pubkey and signature to the peer
> - wait to receive the persistent public key and signature from the peer
> - verify the signature on the challenge using the peer's persistent public key
>
> If this is an outgoing connection (we dialed the peer) and we used a peer ID,
> then finally verify that the peer's persistent public key corresponds to the peer ID we dialed,
> ie. `peer.PubKey.Address() == <ID>`.
>
> The connection has now been authenticated. All traffic is encrypted.
>
> Note: only the dialer can authenticate the identity of the peer,
> but this is what we care about since when we join the network we wish to
> ensure we have reached the intended peer (and are not being MITMd).
