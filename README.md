# Peer-to-peer handshake

This is a Rust p2p handshake implementation for [CometBFT](https://github.com/cometbft/cometbft) (previously Tendermint Core). Prior art exists at [tendermint-rs](https://github.com/informalsystems/tendermint-rs.git), it was used to get this project started and so many of the dependencies are re-used as well as [tendermint-proto](https://crates.io/crates/tendermint-proto), the proto struct definitions used by the protocol.

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

This project contains a vendered [CometBFT](https://github.com/cometbft/cometbft) under the [`target-node`](./target-node) directory (via git subtree). I intentionally pulled the latest (unstable) code from `main` because I was curious if the handshake worked with the latest development version (it also works with the latest stable release [`v0.38.2`](https://github.com/cometbft/cometbft/tree/v0.38.2)).

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