//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "test_suite.hpp"

#include <boost/corosio/native/native_io_context.hpp>

#if BOOST_COROSIO_HAS_IO_URING

namespace boost::corosio {

struct native_io_uring_test
{
    void testConstruct()
    {
        native_io_context<io_uring> ctx;
        BOOST_TEST_PASS();
    }

    void testStopRestart()
    {
        native_io_context<io_uring> ctx;
        BOOST_TEST(!ctx.stopped());
        ctx.stop();
        BOOST_TEST(ctx.stopped());
        ctx.restart();
        BOOST_TEST(!ctx.stopped());
    }

    void run()
    {
        testConstruct();
        testStopRestart();
    }
};

TEST_SUITE(
    native_io_uring_test,
    "boost.corosio.native.io_context.io_uring");

} // namespace boost::corosio

#endif // BOOST_COROSIO_HAS_IO_URING
