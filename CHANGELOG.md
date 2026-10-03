# Changelog

Builds are cut by CI from `main` and published as `build-<number>`. Entries below record
what changed and, where it matters, what a real iPhone proved or disproved.

## Unreleased

- Advertise the pointer and text records with a two minute lifetime instead of 75 minutes. A
  reinstall gives the server a new identity, and an uninstalled app cannot send a goodbye, so
  dead "pair with this host" entries used to sit in the iPhone's list for over an hour.

## build-80

- Record every packet that crosses the tunnel, with addresses, ports and flags, including the
  ones the TCP code ignores. Served as plain text at `GET /diag`.
- Retransmit the TCP SYN once a second instead of giving up after one attempt, and use short
  socket reads so a single lost packet is not fatal.
- Report a reply whose ports match but whose addresses do not, rather than dropping it silently.

On hardware the TLS-PSK and CDTunnel handshakes both succeeded for the first time. Userspace
TCP then failed: the SYN to the RSD port went unanswered. That is what `/diag` exists to
explain.

## build-79

- Connect the tunnel data plane the instant `createListener` returns a port, and hold it open.
  iOS closes a listener that nothing connects to, so a port requested in advance was already
  dead by the time anyone asked for JIT, which showed up as `ECONNREFUSED`.
- Run launches over the live tunnel instead of dialling a stale port.
- Throw the tunnel away after a failed launch so the next attempt gets a fresh one.

## build-78

- Serve the routes SideStore and LiveContainer actually use: `/<udid>/<bundle id>/`,
  `/<bundle id>/`, `/ver/` and `/re/`. Previously only `/launch?bundleId=` existed, so a client
  would have received a 404 even with a working tunnel.
- Percent decode bundle identifiers, refuse a udid no paired device has instead of launching
  anyway, and answer 501 for listing installed apps, which is not written.

## build-77

- Dial the paired device instead of waiting to be dialled. Pairing leaves the server as the
  accessory, and iOS will not create a tunnel listener on a connection it opened, so pairing
  could complete while JIT stayed unavailable.
- Added the pieces that made that possible: a one shot mDNS browser that keeps the IPv6 scope
  AAAA records drop, `authTag` resolution of an advertisement to a stored pairing record, the
  initiator side of pair verify, and a reconnect loop that holds the control connection open.
- Removed `DvtClient`, which guessed a PID by scanning a reply for any plausible integer, and a
  dead ChaCha20-Poly1305 nonce helper that used the wrong byte offset.

On hardware this was the first build where the browse, host initiated pair verify and
`createListener` all succeeded.

## Earlier builds

Development of the protocol stack, from pair setup through to the developer services:

- SRP-6a pair setup as the accessory, pair verify, and session key derivation
- RPPairing framing and the encrypted control channel
- TLS-PSK client on Bouncy Castle, because Android's JSSE will not offer pure PSK suites
- CDTunnel framing and handshake
- A userspace TCP client over raw IPv6 tunnel packets, needed because an unrooted Android
  device cannot create a TUN interface
- RSD over RemoteXPC, carried by a minimal HTTP/2 implementation
- A real NSKeyedArchiver encoder and binary plist decoder, replacing string scraping
- DTX framing, channel requests and ProcessControl
- The debugproxy and GDB remote attach sequence
- mDNS responder, pairable host advertisement, local HTTP API, and the Android service,
  foreground notification and Compose UI
