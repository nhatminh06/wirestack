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

## Manual verification procedure

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

## Limitations

- No HTTP/1.1, no keep-alive, no pipelining.
- No request bodies, no chunked transfer encoding.
- No TLS.
- No filesystem-backed serving -- exactly one route (`/`) is recognized.
- No query-string, header-map, or cookie handling beyond what's needed to
  reject `Transfer-Encoding` and validate `Content-Length`.
- No URL decoding or path normalization.
