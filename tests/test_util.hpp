#pragma once

#include <cstdlib>
#include <iostream>

namespace wirestack::test {

inline int& failureCount() {
    static int count = 0;
    return count;
}

} // namespace wirestack::test

#define CHECK(cond)                                                                              \
    do {                                                                                          \
        if (!(cond)) {                                                                            \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond << '\n';         \
            ++::wirestack::test::failureCount();                                                  \
        }                                                                                          \
    } while (0)

