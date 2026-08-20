#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace wirestack {

struct HttpRequest {
    std::string method;
    std::string target;
    std::string version;
};

enum class HttpParseStatus {
    Incomplete,
    Complete,
    Malformed,
    TooLarge,
    UnsupportedMethod,
    UnsupportedVersion,
};

struct HttpParseResult {
    HttpParseStatus status;
    // Set only when status == Complete.
    std::optional<HttpRequest> request;
};

// Includes the request-line's own trailing CRLF.
inline constexpr std::size_t kMaxHttpRequestLineLength = 2048;

// Request line + header lines + all CRLF separators + the final CRLF.
inline constexpr std::size_t kMaxHttpHeaderBlockLength = 8192;

// Parses `buffer` as a bounded HTTP/1.0 request head (request-line,
// headers, terminating blank line). Stateless: re-scans the whole
// buffer-so-far on every call -- cheap given the 8192-byte bound, and
// avoids a resumable incremental parser. `buffer` is exactly what has
// been accumulated for one TCP connection so far.
HttpParseResult parseHttpRequest(std::span<const std::byte> buffer);

// Per-TCP-four-tuple HTTP application state: the accumulated request
// buffer and whether a response has already been generated (this
// milestone allows exactly one request per connection).
struct HttpConnectionState {
    std::vector<std::byte> buffer;
    bool responded = false;
};

// Appends `bytes` to `state.buffer`, silently capping at
// kMaxHttpHeaderBlockLength -- bytes beyond the cap are dropped, never
// buffered, so a connection can never grow its HTTP buffer unbounded.
void appendHttpBytes(HttpConnectionState& state, std::span<const std::byte> bytes);

enum class HttpStatus {
    Ok200,
    BadRequest400,
    NotFound404,
    MethodNotAllowed405,
    VersionNotSupported505,
};

struct HttpResponse {
    HttpStatus status;
    std::string content_type;
    std::vector<std::byte> body;
    bool include_allow_get = false;
};

HttpResponse makeOkResponse();
HttpResponse makeBadRequestResponse();
HttpResponse makeNotFoundResponse();
HttpResponse makeMethodNotAllowedResponse();
HttpResponse makeVersionNotSupportedResponse();

// target == "/" -> 200, anything else -> 404. Only meaningful when the
// request parsed as HttpParseStatus::Complete.
HttpResponse selectResponse(const HttpRequest& request);

std::vector<std::byte> serializeHttpResponse(const HttpResponse& response);

} // namespace wirestack
