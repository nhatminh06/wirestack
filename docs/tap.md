# TAP integration

## Why TAP, not TUN

TUN devices carry raw IP packets (Layer 3). TAP devices carry raw Ethernet
frames (Layer 2). Wirestack implements Ethernet itself, so it needs the
kernel to hand it full frames, headers included. `TapDevice::open` requests
`IFF_TAP`.

## `IFF_NO_PI`

Without `IFF_NO_PI`, the kernel prepends a 4-byte tun/tap packet-information
header (flags + protocol) to every frame read from the device, and expects
the same header on writes. Wirestack has no use for that metadata — the
Ethernet header already carries EtherType — so `IFF_NO_PI` is set and every
`read()` returns exactly one Ethernet frame with no extra header.

## Opening the device

`wirestack::TapDevice::open(name)`:

1. opens `/dev/net/tun`
2. builds an `ifreq` with `ifr_flags = IFF_TAP | IFF_NO_PI` and the requested
   interface name
3. issues `TUNSETIFF`
4. reads back the interface name the kernel actually assigned (it need not
   match the request, e.g. when the request is empty)

Wirestack only opens and configures the tun/tap character device itself. It
does **not** assign an IP address or bring the interface up — that is host
network configuration, done separately with `ip`.

## Required permissions

`TUNSETIFF` requires `CAP_NET_ADMIN`. In practice this means running as root
or with the binary granted `cap_net_admin` via `setcap`.

## Setup

```bash
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02
```

In another terminal, configure the host side of the interface Wirestack just
created:

```bash
sudo ip addr add 10.0.0.1/24 dev wire0
sudo ip link set wire0 up
```

## Observing frames

```bash
sudo tcpdump -eni wire0
```

`-e` prints link-layer (Ethernet) headers, which is what should be compared
against Wirestack's own `ethernet src=... dst=... type=...` output line for
line.

## Limitations

- No Ethernet FCS: TAP devices do not deliver or expect a frame check
  sequence, so none is validated or generated.
- No 802.1Q VLAN tag handling: the parser reads a fixed 14-byte header; a
  tagged frame's EtherType field will read as `0x8100` and be treated as an
  unknown EtherType rather than unwrapped.
- No IPv4 packet handling yet — see [docs/arp.md](arp.md) for what ARP
  support currently exists.
