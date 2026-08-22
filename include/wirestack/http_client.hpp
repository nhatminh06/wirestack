#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "wirestack/ipv4_address.hpp"

namespace wirestack {

// Maximum status-line length, including its own trailing CRLF.
inline constexpr std::size_t kMaxHttpResponseStatusLineLength = 2048;

// Maximum header block: status line + header lines + all CRLFs + the
// final blank-line CRLF.
inline constexpr std::size_t kMaxHttpResponseHeaderBlockLength = 8192;

// Maximum response body Wirestack will buffer.
inline constexpr std::size_t kMaxHttpResponseBodyLength = 262144;

enum class HttpResponseParseStatus {
    Incomplete,
    Complete,
    Malformed,
    TooLarge,
    UnsupportedVersion,
    UnsupportedTransferEncoding,
    Truncated,
};

struct HttpResponseParseResult {
    HttpResponseParseStatus status;
    // Set only when status == Complete.
    std::optional<int> status_code;
    std::vector<std::byte> body; // meaningful only when status == Complete
    bool content_length_present = false;
};

// Parses `buffer` -- every response byte accumulated so far for one TCP
// connection -- as a bounded HTTP/1.0 response (status line, headers,
// body). Stateless: re-scans the whole buffer-so-far on every call, the
// same approach as parseHttpRequest in http.hpp, cheap given the bound.
// `peer_closed` reports whether the peer's FIN has already been accepted
// by TCP; it is what makes a close-delimited (no Content-Length) body
// completable, and what turns a not-yet-complete response into Truncated
// rather than leaving it Incomplete forever.
HttpResponseParseResult parseHttpResponse(std::span<const std::byte> buffer, bool peer_closed);

// Per-connection outbound HTTP/1.0 client state, owned by main.cpp
// (mirrors HttpConnectionState's split from TcpConnectionTable: TCP
// knows nothing about HTTP either direction). `remote_ip`/`remote_port`
// are the literal destination this session's exact request was built
// for -- used only for the Host header and for logging, never as TCP
// sequence state.
struct HttpClientSession {
    Ipv4Address remote_ip;
    std::uint16_t remote_port = 0;
    std::string target;

    bool request_enqueued = false;
    std::vector<std::byte> response_buffer;
    bool peer_fin_seen = false;

    bool response_complete = false;
    bool failed = false;
    bool close_initiated = false;

    // Valid once response_complete is true.
    int status_code = 0;
    std::vector<std::byte> body;
};

enum class HttpClientTargetError {
    Empty,
    MissingLeadingSlash,
    InvalidByte, // space, CR, LF, or another control byte
};

// Validates a request target in isolation, before any TCP connection is
// created (see docs/http.md). Does not validate the destination address
// or ports -- that's ordinary IPv4/port parsing at the CLI layer.
std::optional<HttpClientTargetError> validateHttpClientTarget(std::string_view target);

// Builds the exact bounded GET request:
//   GET <target> HTTP/1.0\r\n
//   Host: <remote_ip>:<remote_port>\r\n
//   Connection: close\r\n
//   \r\n
// Returns nullopt if `target` fails validateHttpClientTarget -- the
// serializer never emits CRLF-injected or otherwise malformed bytes.
std::optional<std::vector<std::byte>> buildHttpGetRequest(Ipv4Address remote_ip,
                                                            std::uint16_t remote_port,
                                                            std::string_view target);

} // namespace wirestack
