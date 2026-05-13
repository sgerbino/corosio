//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

// Test that header file is self-contained.
#include <boost/corosio/host_name.hpp>

#include <string>

#include "test_suite.hpp"

namespace boost::corosio {

struct host_name_test
{
    // Calling host_name() returns a non-empty string. Every machine
    // has a hostname.
    void testReturnsNonEmpty()
    {
        std::string h = host_name();
        BOOST_TEST(!h.empty());
    }

    // Two successive calls return the same value. Catches buffer
    // and lifetime bugs.
    void testStable()
    {
        std::string a = host_name();
        std::string b = host_name();
        BOOST_TEST_EQ(a, b);
    }

    // DNS label max is 63 octets, full hostname max is 255. Anything
    // outside that range is almost certainly garbage from a
    // miscounted buffer.
    void testReasonableLength()
    {
        std::string h = host_name();
        BOOST_TEST(h.size() > 0);
        BOOST_TEST(h.size() <= 255);
    }

    // Load-bearing for the Windows design choice: host_name() must
    // work without an io_context. A regression to winsock
    // gethostname() would fail this on Windows because corosio's
    // WSAStartup is lazy (inside io_context).
    void testNoIoContextNeeded()
    {
        std::string h = host_name();
        BOOST_TEST(!h.empty());
    }

    // Catches encoding regressions, especially in the Windows
    // UTF-16 -> UTF-8 conversion. We cannot assert ASCII-only:
    // hostnames may legitimately contain non-ASCII characters.
    // Allow printable ASCII (0x20-0x7E) and any high-bit byte
    // (UTF-8 continuation or leading byte).
    void testCharsetSanity()
    {
        std::string h = host_name();
        for (unsigned char c : h)
        {
            bool printable_ascii = (c >= 0x20 && c <= 0x7E);
            bool high_bit = (c >= 0x80);
            BOOST_TEST(printable_ascii || high_bit);
        }
    }

    void run()
    {
        testReturnsNonEmpty();
        testStable();
        testReasonableLength();
        testNoIoContextNeeded();
        testCharsetSanity();
    }
};

TEST_SUITE(host_name_test, "boost.corosio.host_name");

} // namespace boost::corosio
