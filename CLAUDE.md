# CLAUDE.md

This file defines the working rules for this repository.

Read it before making changes.

## Project

This repository implements a userspace TCP/IP network stack in C++20.

The eventual target is:

```bash
curl http://10.0.0.2:8080
```

with the connection handled by protocol implementations in this repository rather than the Linux kernel TCP/IP stack.

Expected protocol progression:

```text
TAP
 ↓
Ethernet
 ├── ARP
 └── IPv4
      ├── ICMP
      ├── UDP
      └── TCP
           ↓
          HTTP
```

This is a systems-learning project. Correctness and understanding matter more than feature count.

---

## Core principles

Optimize for:

1. correctness
2. clear protocol behavior
3. safe packet parsing
4. small understandable components
5. deterministic tests
6. debuggability
7. measurable behavior

Do not optimize for:

* number of files
* number of abstractions
* feature count
* architectural sophistication
* impressive-sounding documentation

Prefer boring, correct systems code.

---

## No AI attribution

Never add AI attribution anywhere in this repository.

Do not add references to:

* Claude
* Anthropic
* ChatGPT
* OpenAI
* Copilot
* AI-generated code
* generated-by
* assisted-by

Do not add AI systems as:

* authors
* contributors
* co-authors
* commit trailers
* documentation credits

Never produce a commit containing:

```text
Co-Authored-By: Claude
```

or equivalent AI attribution.

---

## Git policy

Do not commit unless explicitly instructed.

Do not push unless explicitly instructed.

Do not create branches unless explicitly instructed.

Do not modify Git history.

Do not run destructive Git commands without explicit approval.

Avoid:

```bash
git reset --hard
git clean -fd
git push --force
git rebase
```

unless specifically requested.

Before a requested commit, provide:

* changed files
* concise diff summary
* proposed commit message

Commit messages should describe the engineering change directly.

Good:

```text
implement Ethernet II frame parsing
```

```text
add ARP request and reply handling
```

```text
handle TCP passive open handshake
```

Bad:

```text
enhance networking architecture
```

```text
implement robust comprehensive packet processing solution
```

Do not mention AI in commit messages.

---

## Avoid AI slop

Do not generate unnecessary:

* comments
* documentation
* helper functions
* wrapper classes
* configuration files
* interfaces
* factories
* managers
* abstractions
* TODOs
* logging
* badges
* diagrams
* examples

Every addition should solve a current concrete problem.

Do not write comments such as:

```cpp
// Increment the counter
counter++;
```

Good comments explain things that are not obvious from the code:

```cpp
// IPv4 checksum treats the checksum field itself as zero during calculation.
```

Avoid marketing language.

Do not describe code as:

* robust
* comprehensive
* enterprise-grade
* production-ready
* scalable
* cutting-edge
* seamless

unless there is specific evidence and the wording is genuinely necessary.

Documentation should state what exists and what does not exist.

---

## Language and build

Primary language:

```text
C++20
```

Build system:

```text
CMake
```

Target platform:

```text
Linux
```

Keep external dependencies minimal.

Do not introduce a large dependency without a concrete reason.

---

## C++ style

Prefer:

* RAII
* value types
* explicit ownership
* `std::span`
* `std::array`
* `std::vector`
* `std::optional` where semantically appropriate
* strong small domain types where they improve correctness

Avoid:

* raw owning pointers
* unnecessary inheritance
* singleton state
* global mutable state
* unsafe casts
* type punning packet buffers
* packed protocol structs mapped directly over untrusted bytes

Do not build class hierarchies merely to mirror OSI layers.

---

## Packet parsing

All network input is untrusted.

Before reading a field:

* verify enough bytes exist

Before trusting a length:

* validate it against the actual packet buffer

Never assume:

* alignment
* minimum packet size beyond what has been checked
* well-formed headers
* correct checksums
* valid protocol values

Handle network byte order explicitly.

Avoid:

```cpp
auto* header =
    reinterpret_cast<const Ipv4Header*>(buffer.data());
```

for parsing untrusted packets.

Prefer deliberate reads from a byte view.

Parsing errors should be explicit.

Malformed packets should not:

* crash
* invoke undefined behavior
* read out of bounds
* produce partially trusted protocol objects

---

## Checksums

Checksum implementations must have known test vectors.

Protocols eventually requiring checksum support include:

* IPv4
* ICMP
* UDP
* TCP

Do not assume checksum correctness because packets appear to work.

Test it independently.

---

## Error handling

Expected malformed network input is not an exceptional program failure.

Prefer explicit parser errors/results.

Reserve exceptions for actual exceptional application conditions where they make sense.

Do not silently ignore parser invariants.

---

## Protocol layering

Keep protocol responsibilities separate.

Conceptually:

```text
Ethernet
    ↓
ARP / IPv4
         ↓
ICMP / UDP / TCP
```

A lower layer should not contain application-specific logic.

A packet parser should not decide routing/application policy unless that belongs to the protocol abstraction itself.

Do not create a generic packet-processing framework unless the existing code clearly demands one.

---

## Scope

Current development should follow this order:

### 0. Foundation

* CMake
* tests
* sanitizers
* project layout

### 1. Ethernet + TAP

* TAP read/write
* MAC addresses
* Ethernet II parser
* Ethernet II serializer

### 2. ARP

* request
* reply
* cache
* local-IP response

### 3. IPv4

* parsing
* serialization
* checksum
* protocol dispatch

### 4. ICMP

* Echo Request
* Echo Reply
* working `ping`

### 5. UDP

* basic endpoint abstraction
* bind
* send
* receive
* echo server

### 6. TCP

Develop incrementally:

* segment parsing
* checksum
* connection tuple
* state machine
* passive open
* handshake
* data transfer
* close
* retransmission
* receive window
* basic duplicate/out-of-order handling

### 7. HTTP

Minimal HTTP server over our own TCP implementation.

Do not work significantly ahead of the current milestone unless explicitly requested.

---

## Initial non-goals

Do not implement these early:

* IPv6
* NAT
* DHCP
* DNS
* IP fragmentation/reassembly
* IPv4 options
* raw socket compatibility APIs
* full POSIX socket semantics
* TCP SACK
* TCP timestamps
* TCP Fast Open
* sophisticated congestion control
* multiple NIC routing
* firewalling
* TLS
* HTTP/2
* HTTP/3

Non-goal does not mean never. It means do not add complexity before the core stack works.

---

## TCP rule

TCP is the most complex part of this project.

Never implement multiple major TCP mechanisms simultaneously when a smaller testable step is possible.

For TCP bugs:

1. capture traffic
2. inspect sequence/ack numbers and flags
3. identify violated state/invariant
4. add regression test
5. fix the smallest responsible component

Do not guess.

Do not "fix" packet behavior by inserting arbitrary delays.

---

## Testing

New protocol behavior requires tests.

Prefer deterministic tests using explicit byte sequences.

Important test categories:

* valid decode
* valid encode
* encode/decode round trip
* minimum-size packet
* truncated packet
* invalid header length
* invalid declared payload length
* checksum failure
* unknown/unsupported protocol values
* edge values

Integration behavior should eventually be tested using Linux networking tools.

Examples:

```bash
ip
ping
arping
nc
socat
curl
tcpdump
```

Do not fake integration results.

---

## Sanitizers

Code handling packet buffers should be regularly tested with:

* AddressSanitizer
* UndefinedBehaviorSanitizer

If sanitizer findings occur, fix them before adding more functionality unless there is a documented reason not to.

---

## Debugging

Use evidence.

For packet bugs, inspect:

```bash
tcpdump
```

or Wireshark captures.

For process bugs, use appropriate tools such as:

```bash
gdb
strace
```

When diagnosing a failure, avoid modifying unrelated layers.

---

## Formatting and lint

Keep formatting consistent.

Do not perform repository-wide cosmetic reformatting while working on an unrelated feature.

Do not rewrite working files merely to match personal stylistic preference.

A change should have a narrow diff.

---

## README

Keep README focused on users of the repository.

Eventually it should answer:

* what is this?
* what works?
* how is it structured?
* how do I build it?
* how do I run it?
* how can I reproduce the demo?
* what does not work yet?

Do not turn README into a development diary.

Do not claim unsupported protocol compliance.

---

## Documentation

Protocol notes belong under `docs/` when they provide genuine value.

Examples:

```text
docs/tap.md
docs/ethernet.md
docs/arp.md
docs/ipv4.md
docs/tcp.md
docs/testing.md
```

Do not create these in advance as empty shells.

Documentation must match implementation.

---

## Benchmarks

Never invent numbers.

Every benchmark result must include enough information to reproduce it, including relevant:

* hardware
* build configuration
* packet size/workload
* test duration
* measurement method

Avoid performance claims until measurements exist.

---

## Refactoring

Before a significant refactor:

1. inspect current architecture
2. identify the concrete problem
3. keep existing tests passing
4. make the smallest design change that fixes the issue

Do not replace working code merely because another structure looks cleaner.

---

## Changes outside task scope

Do not modify unrelated files.

If you discover an unrelated problem:

* mention it
* leave it alone unless it blocks the current task

Keep diffs reviewable.

---

## Before implementing

For non-trivial work, first inspect:

* relevant source
* relevant headers
* existing tests
* build configuration

Then state briefly:

1. what exists
2. what needs to change
3. important design decision, if any

Do not produce a long planning essay.

---

## After implementing

Always report:

### Changed

List meaningful files/components changed.

### Design

Mention only decisions worth reviewing.

### Verification

Report the exact commands actually run and whether they passed.

Example:

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

If sanitizers were run, say so.

### Remaining

State concrete remaining work.

Do not say a milestone is complete when tests or integration behavior have not actually been verified.

---

## Definition of done

A feature is not done merely because code exists.

It should normally satisfy:

* compiles
* tests pass
* malformed input is handled
* behavior is verified
* no unnecessary code was added
* documentation is accurate
* diff is narrow
* no unrelated regressions are known

For integration milestones, verify using real packets.

---

## Current project mindset

The purpose of this repository is to understand networking by building it.

When choosing between:

```text
more abstraction
```

and

```text
clearer visibility into what the protocol is actually doing
```

prefer visibility.

When choosing between:

```text
more features
```

and

```text
stronger correctness tests for existing behavior
```

prefer correctness.

When choosing between:

```text
clever code
```

and

```text
obvious code
```

prefer obvious code.
