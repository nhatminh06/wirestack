#include "wirestack/arp.hpp"

#include "test_util.hpp"

using wirestack::ArpOperation;
using wirestack::ArpPacket;
using wirestack::ArpParseError;
using wirestack::Ipv4Address;
using wirestack::MacAddress;
using wirestack::makeArpReply;
using wirestack::maybeReply;
using wirestack::parseArpPacket;
using wirestack::serializeArpPacket;

namespace {

std::vector<std::byte> toBytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

// Hand-built ARP request: sender 02:00:00:00:00:01/10.0.0.1, target
// 00:00:00:00:00:00/10.0.0.2, operation=request. Independent of the
// serializer.
std::vector<std::byte> knownRequestBytes() {
    return toBytes({
        0x00, 0x01,                          // hardware type: Ethernet
        0x08, 0x00,                          // protocol type: IPv4
        0x06,                                // hardware size
        0x04,                                // protocol size
        0x00, 0x01,                          // operation: request
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,  // sender MAC
        0x0a, 0x00, 0x00, 0x01,              // sender IP: 10.0.0.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // target MAC: unknown
        0x0a, 0x00, 0x00, 0x02,              // target IP: 10.0.0.2
    });
}

// Hand-built ARP reply: sender 02:00:00:00:00:02/10.0.0.2, target
// aa:bb:cc:dd:ee:ff/10.0.0.1, operation=reply.
std::vector<std::byte> knownReplyBytes() {
    return toBytes({
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x02,                          // operation: reply
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,  // sender MAC
        0x0a, 0x00, 0x00, 0x02,              // sender IP: 10.0.0.2
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // target MAC
        0x0a, 0x00, 0x00, 0x01,              // target IP: 10.0.0.1
    });
}

} // namespace

int main() {
    // known-vector request decode
    {
        auto result = parseArpPacket(knownRequestBytes());
        CHECK(std::holds_alternative<ArpPacket>(result));
        if (auto* packet = std::get_if<ArpPacket>(&result)) {
            CHECK(packet->operation == ArpOperation::Request);
            CHECK(packet->sender_mac == *MacAddress::parse("02:00:00:00:00:01"));
            CHECK(packet->sender_ip == *Ipv4Address::parse("10.0.0.1"));
            CHECK(packet->target_mac == *MacAddress::parse("00:00:00:00:00:00"));
            CHECK(packet->target_ip == *Ipv4Address::parse("10.0.0.2"));
        }
    }

    // known-vector reply serialize, compared against hand-written bytes
    {
        ArpPacket reply;
        reply.operation = ArpOperation::Reply;
        reply.sender_mac = *MacAddress::parse("02:00:00:00:00:02");
        reply.sender_ip = *Ipv4Address::parse("10.0.0.2");
        reply.target_mac = *MacAddress::parse("aa:bb:cc:dd:ee:ff");
        reply.target_ip = *Ipv4Address::parse("10.0.0.1");

        CHECK(serializeArpPacket(reply) == knownReplyBytes());
    }

    // round trip
    {
        ArpPacket original;
        original.operation = ArpOperation::Request;
        original.sender_mac = *MacAddress::parse("11:22:33:44:55:66");
        original.sender_ip = *Ipv4Address::parse("192.168.1.1");
        original.target_mac = *MacAddress::parse("00:00:00:00:00:00");
        original.target_ip = *Ipv4Address::parse("192.168.1.2");

        auto serialized = serializeArpPacket(original);
        auto result = parseArpPacket(serialized);
        CHECK(std::holds_alternative<ArpPacket>(result));
        if (auto* packet = std::get_if<ArpPacket>(&result)) {
            CHECK(packet->operation == original.operation);
            CHECK(packet->sender_mac == original.sender_mac);
            CHECK(packet->sender_ip == original.sender_ip);
            CHECK(packet->target_mac == original.target_mac);
            CHECK(packet->target_ip == original.target_ip);
        }
    }

    // malformed: too short
    {
        CHECK(std::holds_alternative<ArpParseError>(parseArpPacket({})));

        auto too_short = knownRequestBytes();
        too_short.pop_back();
        CHECK(too_short.size() == 27);
        auto result = parseArpPacket(too_short);
        CHECK(std::holds_alternative<ArpParseError>(result));
        if (auto* err = std::get_if<ArpParseError>(&result)) {
            CHECK(*err == ArpParseError::TooShort);
        }
    }

    // malformed: wrong hardware type
    {
        auto bytes = knownRequestBytes();
        bytes[1] = std::byte{0x06}; // hardware type = 6, not 1
        auto result = parseArpPacket(bytes);
        CHECK(std::holds_alternative<ArpParseError>(result));
        if (auto* err = std::get_if<ArpParseError>(&result)) {
            CHECK(*err == ArpParseError::UnsupportedHardwareType);
        }
    }

    // malformed: wrong protocol type
    {
        auto bytes = knownRequestBytes();
        bytes[2] = std::byte{0x86};
        bytes[3] = std::byte{0xdd}; // protocol type = 0x86dd (IPv6), not 0x0800
        auto result = parseArpPacket(bytes);
        CHECK(std::holds_alternative<ArpParseError>(result));
        if (auto* err = std::get_if<ArpParseError>(&result)) {
            CHECK(*err == ArpParseError::UnsupportedProtocolType);
        }
    }

    // malformed: wrong hardware size
    {
        auto bytes = knownRequestBytes();
        bytes[4] = std::byte{0x04};
        auto result = parseArpPacket(bytes);
        CHECK(std::holds_alternative<ArpParseError>(result));
        if (auto* err = std::get_if<ArpParseError>(&result)) {
            CHECK(*err == ArpParseError::InvalidHardwareSize);
        }
    }

    // malformed: wrong protocol size
    {
        auto bytes = knownRequestBytes();
        bytes[5] = std::byte{0x06};
        auto result = parseArpPacket(bytes);
        CHECK(std::holds_alternative<ArpParseError>(result));
        if (auto* err = std::get_if<ArpParseError>(&result)) {
            CHECK(*err == ArpParseError::InvalidProtocolSize);
        }
    }

    // malformed: unsupported opcode
    {
        auto bytes = knownRequestBytes();
        bytes[7] = std::byte{0x03}; // operation = 3
        auto result = parseArpPacket(bytes);
        CHECK(std::holds_alternative<ArpParseError>(result));
        if (auto* err = std::get_if<ArpParseError>(&result)) {
            CHECK(*err == ArpParseError::UnsupportedOperation);
        }
    }

    // valid request with Ethernet padding beyond the 28-byte logical packet
    {
        auto bytes = knownRequestBytes();
        bytes.insert(bytes.end(), 10, std::byte{0x00}); // padding
        auto result = parseArpPacket(bytes);
        CHECK(std::holds_alternative<ArpPacket>(result));
        if (auto* packet = std::get_if<ArpPacket>(&result)) {
            CHECK(packet->sender_ip == *Ipv4Address::parse("10.0.0.1"));
            CHECK(packet->target_ip == *Ipv4Address::parse("10.0.0.2"));
        }
    }

    // reply construction: local IP 10.0.0.2, local MAC 02:00:00:00:00:02
    {
        auto local_ip = *Ipv4Address::parse("10.0.0.2");
        auto local_mac = *MacAddress::parse("02:00:00:00:00:02");

        auto request_result = parseArpPacket(knownRequestBytes());
        auto* request = std::get_if<ArpPacket>(&request_result);
        CHECK(request != nullptr);
        if (request != nullptr) {
            auto reply = makeArpReply(*request, local_ip, local_mac);
            CHECK(reply.operation == ArpOperation::Reply);
            CHECK(reply.sender_ip == local_ip);
            CHECK(reply.sender_mac == local_mac);
            CHECK(reply.target_ip == request->sender_ip);
            CHECK(reply.target_mac == request->sender_mac);

            // maybeReply: request targets local IP -> reply produced
            auto maybe = maybeReply(*request, local_ip, local_mac);
            CHECK(maybe.has_value());
            if (maybe) {
                CHECK(maybe->sender_ip == local_ip);
                CHECK(maybe->target_mac == request->sender_mac);
            }

            // maybeReply: request targets a different IP -> no reply
            auto other_ip = *Ipv4Address::parse("10.0.0.99");
            CHECK(!maybeReply(*request, other_ip, local_mac).has_value());
        }
    }

    return wirestack::test::failureCount() == 0 ? 0 : 1;
}
