#include "wirestack/runtime_options.hpp"

#include <charconv>

#include "wirestack/dns.hpp"
#include "wirestack/http_client.hpp"

namespace wirestack {

namespace {

RuntimeOptionsParseResult makeError(std::string message) {
    return RuntimeOptionsParseResult{std::nullopt, RuntimeOptionsError{std::move(message)}};
}

RuntimeOptionsParseResult makeOptions(RuntimeOptions options) {
    return RuntimeOptionsParseResult{std::move(options), std::nullopt};
}

// Strict decimal parse: the entire string must be digits (no sign, no
// leading/trailing whitespace, no hex, no trailing junk), and the value
// must fall in the valid port range 1-65535. Rejecting non-digit first
// characters up front means a leading '-' or '+' never reaches
// std::from_chars, sidestepping any ambiguity in how it treats a sign
// against an unsigned output type.
std::optional<std::uint16_t> parseStrictPort(std::string_view text) {
    if (text.empty() || text.front() < '0' || text.front() > '9') {
        return std::nullopt;
    }
    unsigned long value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    if (value == 0 || value > 0xffff) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

const char* describeTargetError(HttpClientTargetError error) {
    switch (error) {
        case HttpClientTargetError::Empty:
            return "empty";
        case HttpClientTargetError::MissingLeadingSlash:
            return "must begin with '/'";
        case HttpClientTargetError::InvalidByte:
            return "contains a space, CR, LF, or other control byte";
    }
    return "invalid";
}

} // namespace

RuntimeOptionsParseResult parseRuntimeOptions(int argc, char** argv) {
    std::optional<std::string> active_open_arg;
    std::optional<std::string> http_get_arg;
    std::optional<std::string> source_port_arg;
    std::optional<std::string> target_arg;
    std::optional<std::string> dns_server_arg;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--active-open") {
            if (active_open_arg) return makeError("--active-open given more than once");
            if (i + 1 >= argc) return makeError("--active-open requires a value");
            active_open_arg = argv[++i];
        } else if (arg == "--http-get") {
            if (http_get_arg) return makeError("--http-get given more than once");
            if (i + 1 >= argc) return makeError("--http-get requires a value");
            http_get_arg = argv[++i];
        } else if (arg == "--source-port") {
            if (source_port_arg) return makeError("--source-port given more than once");
            if (i + 1 >= argc) return makeError("--source-port requires a value");
            source_port_arg = argv[++i];
        } else if (arg == "--target") {
            if (target_arg) return makeError("--target given more than once");
            if (i + 1 >= argc) return makeError("--target requires a value");
            target_arg = argv[++i];
        } else if (arg == "--dns-server") {
            if (dns_server_arg) return makeError("--dns-server given more than once");
            if (i + 1 >= argc) return makeError("--dns-server requires a value");
            dns_server_arg = argv[++i];
        } else {
            return makeError("unknown option: " + arg);
        }
    }

    if (active_open_arg && http_get_arg) {
        return makeError("--active-open and --http-get are mutually exclusive");
    }
    if (target_arg && !http_get_arg) {
        return makeError("--target requires --http-get");
    }
    if (dns_server_arg && active_open_arg) {
        return makeError("--dns-server is not supported with --active-open");
    }

    if (!active_open_arg && !http_get_arg) {
        if (source_port_arg) {
            return makeError("--source-port requires --active-open or --http-get");
        }
        if (dns_server_arg) {
            return makeError("--dns-server requires --http-get with a hostname destination");
        }
        return makeOptions(RuntimeOptions{});
    }

    if (!source_port_arg) {
        return makeError(active_open_arg ? "--active-open requires --source-port"
                                          : "--http-get requires --source-port");
    }
    if (http_get_arg && !target_arg) {
        return makeError("--http-get requires --target");
    }

    const std::string& destination = active_open_arg ? *active_open_arg : *http_get_arg;
    auto colon = destination.rfind(':');
    if (colon == std::string::npos) {
        return makeError("destination must be <ip-or-hostname>:<port>");
    }
    std::string host_part = destination.substr(0, colon);
    auto remote_port = parseStrictPort(destination.substr(colon + 1));
    if (!remote_port) {
        return makeError("invalid destination port");
    }

    auto source_port = parseStrictPort(*source_port_arg);
    if (!source_port) {
        return makeError("invalid --source-port");
    }

    if (active_open_arg) {
        auto remote_ip = Ipv4Address::parse(host_part);
        if (!remote_ip) {
            return makeError("invalid destination IPv4 address");
        }
        RuntimeOptions options;
        options.remote_ip = *remote_ip;
        options.remote_port = *remote_port;
        options.source_port = *source_port;
        options.mode = RuntimeMode::ActiveOpen;
        return makeOptions(std::move(options));
    }

    if (auto target_error = validateHttpClientTarget(*target_arg)) {
        return makeError(std::string("invalid --target: ") + describeTargetError(*target_error));
    }

    RuntimeOptions options;
    options.remote_port = *remote_port;
    options.source_port = *source_port;
    options.mode = RuntimeMode::HttpGet;
    options.target = *target_arg;

    auto remote_ip = Ipv4Address::parse(host_part);
    if (remote_ip) {
        if (dns_server_arg) {
            return makeError("--dns-server requires a hostname destination, not a literal IPv4 address");
        }
        options.destination_is_hostname = false;
        options.remote_ip = *remote_ip;
        return makeOptions(std::move(options));
    }

    auto normalized_hostname = normalizeHostname(host_part);
    if (!normalized_hostname.normalized) {
        return makeError("invalid destination: not a valid IPv4 address or hostname");
    }
    if (!dns_server_arg) {
        return makeError("hostname destination requires --dns-server");
    }

    auto dns_colon = dns_server_arg->rfind(':');
    if (dns_colon == std::string::npos) {
        return makeError("--dns-server must be <ip>:<port>");
    }
    auto dns_server_ip = Ipv4Address::parse(dns_server_arg->substr(0, dns_colon));
    if (!dns_server_ip) {
        return makeError("invalid --dns-server IPv4 address");
    }
    auto dns_server_port = parseStrictPort(dns_server_arg->substr(dns_colon + 1));
    if (!dns_server_port) {
        return makeError("invalid --dns-server port");
    }

    options.destination_is_hostname = true;
    options.hostname = *normalized_hostname.normalized;
    options.dns_server_ip = *dns_server_ip;
    options.dns_server_port = *dns_server_port;
    return makeOptions(std::move(options));
}

} // namespace wirestack
