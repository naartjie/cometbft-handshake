# Peer-to-peer handshake

This is a Rust p2p handshake protocol implementation  for [CometBFT](https://github.com/cometbft/cometbft). Prior art exists at [tendermint-rs](https://github.com/informalsystems/tendermint-rs.git), it was used to bootstrap this project and uses the same dependencies, it also reuses the tendermint-proto, the proto struct definitions used by the protocol.

## Pre-requisites

The following versions were used:
- go 1.21.5
- cargo/rust 1.74.1

### Start target p2p node
You can run a vanilla CometBFT target node
```
# run this once off, to initialize config files
go run github.com/cometbft/cometbft/cmd/cometbft@v0.38.2 init

# to start the node
go run github.com/cometbft/cometbft/cmd/cometbft@v0.38.2 node --proxy_app=kvstore
```

If you'd like to add a printline to the terminal, run the following:

TODO: add Printf patch

This will print a message that the handshake was successful as well as the peer id.

```
git clone git@github.com:cometbft/cometbft.git
cd cometbft

# run this once off, to initialize config files
go run cmd/cometbft/main.go init

# to start the node
go run cmd/cometbft/main.go node --proxy_app=kvstore --log_level=error
```

### Connect from rust

```
cargo run --bin handshake
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