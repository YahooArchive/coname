# End-to-End keyserver protocol

The protocol consists of exchanging `protobuf3` messages over `grpc`. The
message descriptors are split into three files:

- `client.proto` -- all messages that are required for operation of a
  lightweight (stateful or stateless) client. Keyserver entries and server
  signature structures.
- `verifier.proto` -- everything that a verifier needs to use but a client does
  not. Pushing signatures, downloading update logs, etc.
- `replication.proto` -- service-provider internal protocol, included here as a
  part of the reference implementation. Handles high-availability replication
  and synchronization of updates to the keyserver state.
