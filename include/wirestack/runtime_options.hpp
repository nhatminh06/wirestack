#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "wirestack/ipv4_address.hpp"

namespace wirestack {

// wirestack's three mutually exclusive runtime modes, selected entirely by
// command-line options (positional tap/local-ip/local-mac are always
// required and are not part of this parser -- see main.cpp).
enum class RuntimeMode {
    Passive,
    ActiveOpen,
    HttpGet,
};

struct RuntimeOptions {
    RuntimeMode mode = RuntimeMode::Passive;
    // Meaningful only when mode != Passive.
    // True only for mode == HttpGet with a hostname destination (see
    // docs/dns.md) -- --active-open never accepts a hostname. When true,
    // `remote_ip` is unset and the real destination is resolved at
    // runtime via DNS before TCP active open begins; `hostname` carries
    // the normalized (lowercased) name, used verbatim in the HTTP Host
    // header regardless of what address it resolves to.
    bool destination_is_hostname = false;
    Ipv4Address remote_ip;
    std::string hostname;
    std::uint16_t remote_port = 0;
    std::uint16_t source_port = 0;
    // Meaningful only when destination_is_hostname.
    Ipv4Address dns_server_ip;
    std::uint16_t dns_server_port = 0;
    // Meaningful only when mode == HttpGet.
    std::string target;
};

struct RuntimeOptionsError {
    std::string message;
};

// Exactly one of `options`/`error` is set. An absent `error` with `options`
// set to RuntimeMode::Passive means no runtime-mode options were given at
// all; it is never produced for input that failed validation -- invalid
// input always sets `error` and leaves `options` unset, so it can never be
// mistaken for passive mode.
struct RuntimeOptionsParseResult {
    std::optional<RuntimeOptions> options;
    std::optional<RuntimeOptionsError> error;
};

// Parses argv[4..argc) -- everything after the tap/local-ip/local-mac
// positionals. Valid forms:
//   (nothing)                                                  -> Passive
//   --active-open <ip>:<port> --source-port <port>              -> ActiveOpen
//   --http-get <ip>:<port> --source-port <port> --target </path> -> HttpGet
//   --http-get <hostname>:<port> --dns-server <ip>:<port>
//       --source-port <port> --target </path>                   -> HttpGet (DNS)
// Ports are parsed with strict complete-string decimal conversion (no
// leading/trailing junk, no sign, no leading/trailing whitespace, 1-65535).
// A --http-get destination is tried as a literal IPv4 address first; only
// if that fails is it validated as a hostname (see wirestack/dns.hpp).
// --dns-server is required exactly when the --http-get destination is a
// hostname, and rejected in every other case (literal destination,
// --active-open, or passive mode) -- see docs/dns.md.
RuntimeOptionsParseResult parseRuntimeOptions(int argc, char** argv);

} // namespace wirestack
