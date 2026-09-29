# Architecture

## Why it is split up like this

The stack between "an Android device on Wi-Fi" and "JIT granted on an iPhone"
is seven protocols deep. When it fails, the only useful question is *which
layer*, and the only way to answer that cheaply is to keep the layers apart and
test them separately.

So the protocol work lives in plain Kotlin/JVM modules with no Android
dependency at all. Those modules are unit-testable on a build machine in
seconds, without an emulator. Anything that genuinely needs Android — the
Keystore, network callbacks, the multicast lock, the foreground service —
lives in one module that the rest does not depend on.

```
:app          Android application. Compose status screen, foreground service,
              boot receiver. Contains no protocol logic.

:platform     The only module that touches Android APIs beyond the basics:
              connectivity callbacks, multicast lock, Keystore-backed storage,
              runtime lifecycle.

:server       Local HTTP API and the service advertisement that SideStore and
              LiveContainer look for.

:jit          Orchestration: the sequence that takes a bundle identifier and
              either grants JIT or explains why it could not.

:developer    DVT, ProcessControl, debugproxy, GDB remote protocol.

:coredevice   The tunnel, RSD, RemoteXPC and the HTTP/2 framing underneath it.

:pairing      RPPairing: framing, the state machine, pair setup and verify.

:core:mdns    Multicast DNS: record codec, responder, querier.
:core:net     Socket and address abstractions, free of Android.
:core:crypto  X25519, Ed25519, ChaCha20-Poly1305, HKDF, HMAC, SHA-512, SRP-6a.
:core:serialization  OPACK, TLV8, property lists, byte readers and writers.
:core:logging Structured, per-layer, redacted logging.
```

Dependencies point downwards only. `:core:crypto` knows nothing about
pairing; `:pairing` knows nothing about tunnels; `:app` knows nothing about
any protocol.

## The rule about the screen

`:app` may read state and may start things. Nothing below `:app` may require
`:app` to exist. The target hardware includes a television with a broken
display, so the server is owned by a foreground service and driven by the
application object at launch. The Compose screen is a window onto state, never
a step in a sequence.

## Status reporting

Every stage reports itself as one of: not implemented, idle, running, ready,
failed. A stage with no code behind it reports "not implemented" rather than
staying blank, so the difference between "not built yet" and "built and
broken" is visible from across a room.
