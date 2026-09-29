# Testing

## What automated tests cover

Run with `./gradlew test`. They run on the JVM, need no emulator and no
device, and they are the only tests that gate CI.

Currently covered:

- log redaction: named secrets, long hex and base64 runs, PEM blocks, setup
  codes, and the cases that must *not* be redacted
- log routing, level filtering and cause-chain formatting

Everything else in the test plan below is not written yet, because the code it
would test is not written yet. See [STATUS.md](STATUS.md).

## The test plan

Unit tests, per layer:

- byte readers and writers, endianness, truncation
- TLV8 and OPACK, round-trip and malformed input
- property lists, binary and XML
- HKDF, HMAC, SHA-512 against published vectors
- X25519 and Ed25519 against RFC 7748 and RFC 8032 vectors
- ChaCha20-Poly1305 against RFC 8439 vectors
- SRP-6a against a known exchange
- RPPairing message encode/decode and the state machine, including every
  rejection path
- mDNS record encode/decode, name compression, TXT handling
- HTTP/2 framing, RemoteXPC request/response correlation
- GDB packet framing, checksums, escaping, no-ack mode

Integration tests, on a build machine:

- mDNS advertisement and discovery between two sockets on the loopback
- TCP accept, reconnect, address change
- pairing against a test client that replays a recorded exchange
- pairing persistence across process restart
- the HTTP API end to end

## Physical validation

Nothing above proves the protocol is right. That requires:

- an iPhone or iPad on iOS/iPadOS 27+ with Developer Mode enabled
- an Android phone on the same Wi-Fi
- an Android TV box, ideally one with a broken display, since that is the case
  the headless design exists for

Until that has happened, the correct claim is "implemented, unverified", and
that is what STATUS.md says.
