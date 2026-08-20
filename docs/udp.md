# UDP

## Supported form

IPv4 UDP only: unicast, addressed exactly to Wirestack's configured local
IP (destination filtering happens in the IPv4 layer, see
[docs/ipv4.md](ipv4.md) — UDP does not duplicate it). No broadcast, no
multicast.

`UdpDatagram` holds only `source_port`, `destination_port`, and `payload`
— the wire `length` and `checksum` fields are validated during parsing but
not stored, same as `Ipv4Packet` dropping its flags/fragment-offset word.

## Checksum

UDP over IPv4 checksums the IPv4 pseudo-header (source IPv4, destination
IPv4, a zero byte, protocol 17, UDP length) followed by the UDP header and
payload, using the same `wirestack::internetChecksum` as IPv4/ICMP. The
pseudo-header is never transmitted.

Two special rules specific to UDP:

- **Zero means "not provided"**: a received UDP checksum field of `0x0000`
  is valid IPv4 UDP and is accepted without checksum validation. Any other
  value is validated normally.
- **Computed-zero encoding**: when Wirestack generates a checksum and the
  raw computed value happens to be `0x0000`, the transmitted field is set
  to `0xffff` instead — a wire value of `0x0000` would be misread as "no
  checksum". Wirestack always generates a real checksum; it never emits
  the omitted-checksum encoding itself.

## Echo endpoint

Fixed at port 9000 — not a CLI argument, since a single built-in
development endpoint doesn't need a configuration surface. Any datagram
delivered to port 9000 is echoed back byte-for-byte, with source/destination
ports and IPs reversed. A datagram to any other port is valid UDP with no
bound endpoint and is silently dropped (no ICMP Port Unreachable). A
request with source port 0 is parsed and delivered normally, but no reply
is sent, since port 0 has no valid meaning as a reply destination.

## Testing

Manual, since opening a TAP device requires `CAP_NET_ADMIN`:

```bash
# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02

# terminal 2
sudo ip addr add 10.0.0.1/24 dev wire0
sudo ip link set wire0 up
sudo ip neigh del 10.0.0.2 dev wire0 2>/dev/null || true
ping -c1 10.0.0.2   # confirm ARP + ICMP still work first

# terminal 3
sudo tcpdump -eni wire0 'arp or icmp or udp'

# terminal 4
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"hello", ("10.0.0.2", 9000))
data, addr = s.recvfrom(65535)
print(data, addr)
PY
```

Expected: `b'hello' ('10.0.0.2', 9000)`. Sending to port 9001 instead should
time out with no reply observed in tcpdump.

## Limitations

- Single built-in echo endpoint; no general application registration API.
- No ICMP Port Unreachable for datagrams to an unbound port.
- No broadcast or multicast UDP.
- No ephemeral port allocation (Wirestack never originates UDP traffic).
