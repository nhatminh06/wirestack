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
    Ipv4Address remote_ip;
    std::uint16_t remote_port = 0;
    std::uint16_t source_port = 0;
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
// Ports are parsed with strict complete-string decimal conversion (no
// leading/trailing junk, no sign, no leading/trailing whitespace, 1-65535).
RuntimeOptionsParseResult parseRuntimeOptions(int argc, char** argv);

} // namespace wirestack
