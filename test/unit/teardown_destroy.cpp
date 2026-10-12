//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/test/socket_pair.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>

#include <tuple>
#include <utility>

#include "context.hpp"
#include "test_suite.hpp"

namespace boost::corosio {

// Tearing down a context destroys every frame suspended in one of its
// operations, and with it the chain awaiting that frame, exactly once.
template<auto Backend>
struct teardown_destroy_test
{
    struct destroy_count_t
    {
        int* n;
        explicit destroy_count_t(int& c) : n(&c) {}
        destroy_count_t(destroy_count_t&& o) noexcept
            : n(std::exchange(o.n, nullptr)) {}
        ~destroy_count_t()
        {
            if (n)
                ++*n;
        }
    };

    void testParkedReadDestroysChain()
    {
        int child_down = 0, parent_down = 0;
        {
            io_context ioc(Backend);
            auto [a, b] = test::make_socket_pair(ioc);
            auto child = [](tcp_socket& s, destroy_count_t) -> capy::task<> {
                char c;
                std::ignore = co_await s.read_some(capy::mutable_buffer(&c, 1));
            };
            auto parent = [&](tcp_socket& s, destroy_count_t) -> capy::task<> {
                co_await child(s, destroy_count_t(child_down));
            };
            capy::run_async(ioc.get_executor())(
                parent(a, destroy_count_t(parent_down)));
            std::ignore = ioc.poll();
            BOOST_TEST_EQ(child_down, 0);
            BOOST_TEST_EQ(parent_down, 0);
        }
        BOOST_TEST_EQ(child_down, 1);
        BOOST_TEST_EQ(parent_down, 1);
    }

    // The frame owns the socket whose impl stores the parked op, so
    // destroying the frame releases that impl while the op is still
    // inside its own teardown.
    void testParkedReadOwningSocketDestroysChain()
    {
        int down = 0;
        {
            io_context ioc(Backend);
            auto [a, b] = test::make_socket_pair(ioc);
            auto owner = [](tcp_socket s, destroy_count_t) -> capy::task<> {
                char c;
                std::ignore = co_await s.read_some(capy::mutable_buffer(&c, 1));
            };
            capy::run_async(ioc.get_executor())(
                owner(std::move(a), destroy_count_t(down)));
            std::ignore = ioc.poll();
            BOOST_TEST_EQ(down, 0);
        }
        BOOST_TEST_EQ(down, 1);
    }

    void testParkedAcceptDestroysChain()
    {
        int parent_down = 0;
        {
            io_context ioc(Backend);
            tcp_acceptor acc(ioc);
            BOOST_TEST(!acc.open());
            acc.set_option(socket_option::reuse_address(true));
            BOOST_TEST(!acc.bind(endpoint(ipv4_address::loopback(), 0)));
            BOOST_TEST(!acc.listen());
            auto parent = [](tcp_acceptor& a, destroy_count_t) -> capy::task<> {
                std::ignore = co_await a.accept();
            };
            capy::run_async(ioc.get_executor())(
                parent(acc, destroy_count_t(parent_down)));
            std::ignore = ioc.poll();
            BOOST_TEST_EQ(parent_down, 0);
        }
        BOOST_TEST_EQ(parent_down, 1);
    }

    void run()
    {
        testParkedReadDestroysChain();
        testParkedReadOwningSocketDestroysChain();
        testParkedAcceptDestroysChain();
    }
};

COROSIO_BACKEND_TESTS(teardown_destroy_test, "boost.corosio.teardown_destroy")

} // namespace boost::corosio
