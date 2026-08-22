# HTTP

Minimal HTTP/1.0 GET handling, layered strictly above TCP. `tcp.hpp`/
`tcp.cpp` and `tcp_connection.hpp`/`tcp_connection.cpp` contain no HTTP
knowledge; the HTTP layer (`http.hpp`/`http.cpp`) receives only the
ordinary binary bytes TCP already accepted, and never touches sequence
numbers, ACKs, or connection state directly.

## Supported request syntax

```text
METHOD SP REQUEST-TARGET SP HTTP-VERSION CRLF
[header-line CRLF]*
CRLF
```

Exactly one ASCII space between the three request-line fields is
required; a double space, a tab, a missing target/version, or an extra
token is malformed. Only `GET` is implemented; only `HTTP/1.0` is
supported. The target must begin with `/`, be non-empty, and contain no
space or control byte -- it is never URL-decoded, normalized, or resolved
against a filesystem.

Headers are optional. Each present header requires a non-empty
token-charset field name, an immediate colon, optional horizontal
whitespace, and a value of visible ASCII or horizontal tab only. Header
names are compared case-insensitively. Obsolete line-folded continuations
are rejected. Unknown headers are accepted and ignored.

`Transfer-Encoding` is rejected outright (any value). `Content-Length` is
valid only when absent or exactly the literal value `0`; any other value
-- nonzero, non-numeric, overflowing, or a duplicate header -- is
malformed. Request bodies are never read or waited for.

Bytes after the terminating blank line (pipelining, or a second request)
make the whole request malformed -- this milestone supports exactly one
request per connection.

## Incremental buffering

HTTP request bytes may arrive across several in-order TCP segments. Each
TCP four-tuple gets a bounded `HttpConnectionState` (an accumulated byte
buffer plus a `responded` flag) owned by `main.cpp`, separate from
`TcpConnectionTable`. The parser itself is stateless: it re-scans the
whole buffer-so-far on every call rather than resuming partial parse
state, which is simple and cheap given the buffer is capped well under
the size where re-scanning would matter.

## Limits

```text
maximum request-line length: 2048 bytes (including its own CRLF)
maximum header block:        8192 bytes (request line + headers + all CRLFs + final CRLF)
```

Appending is capped at the header-block limit -- bytes beyond it are
silently dropped, never buffered, so a connection's HTTP state can never
grow unbounded. Exceeding either limit before a complete request is found
produces `400 Bad Request` and stops accumulation; it does not continue
waiting for more bytes.

## Responses

| Condition | Status |
|---|---|
| `GET /` | 200 |
| `GET` any other valid target | 404 |
| valid syntax, method other than `GET` | 405 (with `Allow: GET`) |
| valid syntax, version other than `HTTP/1.0` | 505 |
| malformed request, oversized request, or peer EOF before completion | 400 |

Every response carries `Content-Type: text/plain; charset=utf-8`, an
exact `Content-Length`, and `Connection: close`. No `Date` header --
deterministic tests must not depend on wall-clock time.

Exact 200 response (CRLF shown explicitly):

```text
HTTP/1.0 200 OK\r\n
Content-Type: text/plain; charset=utf-8\r\n
Content-Length: 21\r\n
Connection: close\r\n
\r\n
Hello from Wirestack\n
```

400/404/405/505 use the same shape with fixed bodies `Bad Request\n` (12),
`Not Found\n` (10), `Method Not Allowed\n` (19, plus `Allow: GET\r\n`), and
`HTTP Version Not Supported\n` (27).

## One request per connection

After Wirestack responds once for a connection (`HttpConnectionState::
responded == true`), no further payload for that connection is
reprocessed -- TCP's own duplicate-suppression already prevents a
retransmitted client segment from being delivered as new payload a second
time, and the `responded` flag guards against any other later delivery.

## Connection lifecycle

```text
TCP payload accepted / peer FIN accepted
  -> appended to the HTTP buffer (if any payload)
  -> parseHttpRequest(buffer)

Incomplete, no peer FIN yet:  wait for more TCP payload, no response
Incomplete, peer FIN:         400 (peer closed before completing the request)
Complete:                     200 or 404, selected by target
Malformed / TooLarge:         400
UnsupportedMethod:             405
UnsupportedVersion:            505

response selected
  -> serializeHttpResponse
  -> TcpConnectionTable::makeOutgoingData (queued, retransmitted like any TCP data)
  -> only on success: TcpConnectionTable::beginClose (queued FIN)
```

The response and the FIN are ordinary queued TCP segments -- they are
retransmitted, cumulatively/partially ACK-retired, and time out exactly
like any other TCP data through the existing Milestone 7/8 machinery.
`beginClose` is never called before the response segment was
successfully constructed. If a peer's FIN arrives together with a
complete request in the same segment, the request is still processed
normally and exactly one response is sent.

HTTP session state is erased whenever the underlying TCP connection
disappears: an accepted RST, retransmission-budget exhaustion, TIME_WAIT
expiration, or the passive-close path's silent final-ACK removal (the
last of these required one small additive signal on `TcpReceiveResult`,
`connection_closed`, since Milestone 8 had no existing way to report it).

## Outbound HTTP/1.0 client

A minimal client (`http_client.hpp`/`http_client.cpp`) drives one
outbound GET over a TCP connection opened with active open (see
"TCP active open" in `docs/tcp.md`). Same layering discipline as the
server: `HttpClientSession` is owned entirely by `main.cpp`, keyed by
the exact `TcpConnectionKey`, and stored in a map separate from the
server's `http_sessions` -- a connection is never present in both.
`handleTcp`/`handleIpv4` route a connection to at most one of the
server request parser or the client response parser, by explicit map
membership; a connection present in neither map (e.g. a plain
`--active-open` connection with no HTTP role) gets no automatic HTTP
behavior at all regardless of what its `accepted_payload`/`peer_closed`
looks like. This is the same discipline that fixed the cross-layer
defect described in `docs/tcp.md`'s "TCP active open" section, applied
now that active connections can legitimately carry an HTTP role.

### Runtime configuration

```bash
./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02 \
  --http-get 10.0.0.1:9090 --source-port 49200 --target /
```

`--http-get`, `--source-port`, and `--target` must all be given
together; `--http-get`/`--active-open` are mutually exclusive (both
configure the same one-shot active-open slot). `--http-get` takes a
literal IPv4 address and port -- no hostnames, no DNS. `--target` must
begin with `/` and contain no space, CR, LF, or other control byte;
validated before any TCP connection is created. As with
`--active-open`, the peer's MAC must already be in the ARP cache
(Wirestack sends no ARP requests of its own) and the request fires
exactly once, as soon as the handshake completes.

### Request

Sent once `beginConnect`'s handshake reaches `Established`
(`TcpReceiveResult::connection_established`), through the same
`TcpConnectionTable::makeOutgoingData` bounded send buffer as any other
application data -- ordinary MSS segmentation, window/congestion
gating, and retransmission apply unchanged, and the HTTP layer never
regenerates the request itself on a delayed ACK. Exact bytes:

```text
GET <target> HTTP/1.0\r\n
Host: <remote-ip>:<remote-port>\r\n
Connection: close\r\n
\r\n
```

No `User-Agent`, `Accept-Encoding`, request body, `Content-Length`, or
`Transfer-Encoding`. `request_enqueued` guards against enqueuing a
second time on a duplicate establishment signal.

### Response parsing

`parseHttpResponse` is a bounded incremental parser mirroring
`parseHttpRequest`'s stateless re-scan-the-whole-buffer approach.
Limits: `kMaxHttpResponseStatusLineLength` (2048 bytes incl. CRLF),
`kMaxHttpResponseHeaderBlockLength` (8192 bytes incl. the final blank
line), `kMaxHttpResponseBodyLength` (262144 bytes).

Status line: exactly `HTTP/1.0 <3-digit-status> <reason>\r\n`; any
other version (including `HTTP/1.1`) is `UnsupportedVersion`; status
must be 200-599 (1xx is rejected, not merely unsupported-as-informational).
Headers: same token/OWS/case-insensitive rules as the request parser;
folded continuations and NUL are rejected. `Content-Length` must be a
single valid unsigned decimal value (no sign, comma, hex, leading
overflow, or duplicate header even with matching values) not exceeding
the body cap. `Transfer-Encoding` (any value, alone or alongside
`Content-Length`) is `UnsupportedTransferEncoding` -- chunked decoding
is not implemented.

Completion:
- `Content-Length` present: complete once exactly that many body bytes
  have arrived; fewer bytes followed by peer FIN is `Truncated`; more
  than declared is `Malformed`. Does not require FIN.
- `Content-Length` absent: close-delimited -- body is whatever arrived
  before the peer's FIN, complete only once that FIN is accepted
  (`TcpReceiveResult::peer_closed`), and an empty close-delimited body
  is valid.

Only `TcpReceiveResult::accepted_payload` (already-reassembled,
in-order, duplicate-free bytes) is ever appended to a client session's
buffer -- out-of-order and unreleased bytes stay inside TCP reassembly,
never reach the parser. The response body is arbitrary bytes: no
C-string or UTF-8 assumption, an embedded `0x00` does not truncate it.

On `Malformed`/`TooLarge`/`UnsupportedVersion`/
`UnsupportedTransferEncoding`/`Truncated`, the session is marked
`failed` -- no successful response is exposed, no bytes reach the
server's request parser, and no `HTTP/1.0 400 Bad Request` (or any
other reply) is sent to the peer; Wirestack simply initiates its own
close through the existing TCP machinery, same as on a successful
completion.

### Close and cleanup

Once a response completes (or the session fails), Wirestack initiates
its own close via `TcpConnectionTable::beginClose` -- it does not wait
for a `Connection: close` FIN it already asked for. `HttpClientSession`
is erased whenever its connection disappears: normal close completion,
RST/refusal, SYN or data retransmission exhaustion, or TIME_WAIT
expiry, mirroring exactly how `http_sessions` (the server's state) is
already erased on those same events.

## Manual verification procedure

For a reproducible, automated version of this check with packet-capture
evidence, see [docs/interoperability.md](interoperability.md).

Opening a TAP device requires `CAP_NET_ADMIN`:

```bash
# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02

# terminal 2
sudo ip addr add 10.0.0.1/24 dev wire0
sudo ip link set wire0 up

curl --http1.0 -v http://10.0.0.2:8080/
curl --http1.0 -v http://10.0.0.2:8080/missing
curl --http1.1 -v http://10.0.0.2:8080/   # expect 505

# terminal 3
sudo tcpdump -eni wire0 'tcp port 8080'
```

Expected: the `/` request returns `HTTP/1.0 200 OK` with body `Hello from
Wirestack`; `/missing` returns `404 Not Found`; an HTTP/1.1 request
returns `505 HTTP Version Not Supported`. tcpdump should show the
handshake, the GET request bytes, the response bytes, and the FIN
exchange, in that order.

To exercise the outbound client against a plain listener instead:

```bash
# terminal 2, in place of curl above
python3 -m http.server -b 10.0.0.1 9090

# terminal 1
sudo ./build/wirestack wire0 10.0.0.2 02:00:00:00:00:02 \
  --http-get 10.0.0.1:9090 --source-port 49200 --target /
```

Expected: tcpdump shows Wirestack's SYN, the peer's SYN-ACK, Wirestack's
ACK, then Wirestack's GET, the peer's response, its FIN, and Wirestack's
own close; Wirestack's stdout prints the response status and body
length once (`http-client: response complete status=... body_len=...`).
For a reproducible version with packet-capture evidence, see
`tools/integration/http_get.sh` and
[docs/interoperability.md](interoperability.md).

## Limitations

- No HTTP/1.1, no keep-alive, no pipelining, no redirects.
- No request bodies, no chunked transfer encoding, no compression.
- No TLS, no DNS/hostnames -- the outbound client's destination must be
  a literal IPv4 address.
- No filesystem-backed serving -- exactly one route (`/`) is recognized.
- The outbound client sends exactly one GET request per connection and
  does not implement any other method, a general HTTP client library,
  or a POSIX socket API.
- No query-string, header-map, or cookie handling beyond what's needed to
  reject `Transfer-Encoding` and validate `Content-Length`.
- No URL decoding or path normalization.
