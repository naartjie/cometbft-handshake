# Peer-to-peer handshake

This is a Rust p2p handshake implementation for [CometBFT](https://github.com/cometbft/cometbft). Prior art exists at [tendermint-rs](https://github.com/informalsystems/tendermint-rs.git), it was used to bootstrap this project and uses the same dependencies, it also reuses the tendermint-proto, the proto struct definitions used by the protocol.

## Pre-requisites

The following versions were used:
- go 1.21.5 (darwin/arm64)
- cargo/rustc 1.74.1 (a28077b28 2023-12-04)

### Start target p2p node

This project contains a vendered [CometBFT](https://github.com/cometbft/cometbft) under the [./target-node] directory (via git subtree). It has some tweaks in order to print meaningful info when a new p2p handshake is authorized.

To run the node:
```
make run-target
```

### Connect from rust

```
make run-handshake
```

### Verifying it worked

In the first terminal verify there is a message printed:

`We've authorized peer id <...>`

In the second terminal you should see:

```
connecting to 127.0.0.1:26656, my peer id is VerificationKey("...")
handshake was successful
```


## TODO

- takes too long to start target node
- Nonce shouldn't be a counter
- Box<dyn Error>: narrow it down?
- both sides should clearly print:
  - local public peer id
  - remote public peer id