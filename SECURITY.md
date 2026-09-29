# Security

## What this is for

It gives a debugger's privileges, on the user's own iPhone, to the user's own
applications, from the user's own Android device, on the user's own network.
That is the whole scope.

## What it does not do

- never asks for an Apple ID, password or two-factor code
- never contacts a server that is not on the local network
- never sends a pairing record, key or setup code anywhere
- never listens on an address reachable from the internet
- has no remote access path, no telemetry and no update channel

## What is stored

A pairing record: this host's long-term Ed25519 identity, the device's public
identity, and the identifiers needed to be recognised again. It is kept in
app-private storage, encrypted with a key held in the Android Keystore, so it
is not readable by other applications and does not leave the device.

There is no export and no import. A pairing file from a computer is not
accepted, and this one cannot be handed to anything else. That is the point:
the pairing belongs to this Android device and that iPhone.

## What is never logged

Every log line passes through a redactor before it is stored or shown.
Anything that looks like a private key, a shared secret, an SRP value, a
session key, an identity resolving key or a setup code is replaced. The tests
for that are part of the gating test suite, because a log the user is
encouraged to share when reporting a problem is exactly the wrong place for a
key that can impersonate their host.

## Setup codes

The code is generated per pairing attempt, shown only while pairing is in
progress, and discarded afterwards. It is never persisted.

## Reporting a problem

Open an issue. Do not include a log without reading it first, even though it
has been redacted.
