//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "context.hpp"
#include "test_suite.hpp"

#if BOOST_COROSIO_HAS_IO_URING

#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timer.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <vector>

namespace boost::corosio {

struct native_io_uring_specific_test
{
    /** Issue more concurrent connect/accept pairs than the default SQ ring
        depth (256). Verifies that the SQ backpressure path in
        `io_uring_submit_op` (flush-and-retry / synchronous EAGAIN) does
        not lose completions. */
    void testSqBackpressure()
    {
        io_context ioc(io_uring);

        tcp_acceptor acc(ioc);
        acc.open();
        acc.set_option(socket_option::reuse_address(true));
        BOOST_TEST(!acc.bind(endpoint(ipv4_address::loopback(), 0)));
        BOOST_TEST(!acc.listen());
        auto port = acc.local_endpoint().port();

        // 300 pairs drives the SQ ring beyond its default depth of 256,
        // exercising the flush-and-retry path in io_uring_submit_op.
        constexpr int N = 300;

        std::vector<std::shared_ptr<tcp_socket>> clients;
        std::vector<std::shared_ptr<tcp_socket>> servers;
        clients.reserve(N);
        servers.reserve(N);

        std::atomic<int> completed{0};

        for (int i = 0; i < N; ++i)
        {
            clients.emplace_back(std::make_shared<tcp_socket>(ioc));
            servers.emplace_back(std::make_shared<tcp_socket>(ioc));
            clients.back()->open();
        }

        for (int i = 0; i < N; ++i)
        {
            auto cl = clients[i];
            auto sv = servers[i];

            auto connect_coro = [cl, port]() -> capy::task<> {
                auto [ec] =
                    co_await cl->connect(endpoint(ipv4_address::loopback(), port));
                BOOST_TEST(!ec);
            };

            auto accept_coro = [&acc, sv, &completed]() -> capy::task<> {
                auto [ec] = co_await acc.accept(*sv);
                BOOST_TEST(!ec);
                if (!ec)
                    ++completed;
            };

            capy::run_async(ioc.get_executor())(connect_coro());
            capy::run_async(ioc.get_executor())(accept_coro());
        }

        ioc.run();
        BOOST_TEST(completed == N);
    }

    /** Connect N clients without any async_accept outstanding, then drain
        with N sequential async_accept calls. Exercises the multishot
        acceptor's `ready_fds_` parking path: the kernel delivers all CQEs
        before any waiter is present, so they must all be parked and then
        popped in order. */
    void testMultishotAcceptQueue()
    {
        io_context ioc(io_uring);

        tcp_acceptor acc(ioc);
        acc.open();
        acc.set_option(socket_option::reuse_address(true));
        BOOST_TEST(!acc.bind(endpoint(ipv4_address::loopback(), 0)));
        BOOST_TEST(!acc.listen());
        auto port = acc.local_endpoint().port();

        constexpr int N = 10;

        // Allocate up front so addresses are stable across the loop.
        std::vector<tcp_socket> clients;
        clients.reserve(N);

        // Fire N connects; no async_accept is outstanding. The multishot op
        // will deliver CQEs and park accepted fds in ready_fds_.
        for (int i = 0; i < N; ++i)
        {
            clients.emplace_back(ioc);
            clients.back().open();

            auto& cl = clients.back();
            capy::run_async(ioc.get_executor())(
                [&cl, port]() -> capy::task<> {
                    co_await cl.connect(endpoint(ipv4_address::loopback(), port));
                }());
        }

        // Brief pause to let multishot CQEs arrive before we start accepting.
        timer delay(ioc);
        delay.expires_after(std::chrono::milliseconds(50));

        int accepted = 0;
        capy::run_async(ioc.get_executor())(
            [&]() -> capy::task<> {
                (void)co_await delay.wait();

                for (int i = 0; i < N; ++i)
                {
                    tcp_socket peer(ioc);
                    auto [ec] = co_await acc.accept(peer);
                    BOOST_TEST(!ec);
                    if (!ec)
                        ++accepted;
                }
            }());

        ioc.run();
        BOOST_TEST(accepted == N);
    }

    /** Issue both a read and a write on the same socket, then call cancel().
        Both ops must complete with `operation_aborted`. This verifies that
        `IORING_OP_ASYNC_CANCEL` (cancel-by-fd) drains all in-flight ops
        for the socket, not just the first one found. */
    void testCancelByFd()
    {
        io_context ioc(io_uring);

        tcp_acceptor acc(ioc);
        acc.open();
        acc.set_option(socket_option::reuse_address(true));
        BOOST_TEST(!acc.bind(endpoint(ipv4_address::loopback(), 0)));
        BOOST_TEST(!acc.listen());
        auto port = acc.local_endpoint().port();

        tcp_socket client(ioc);
        tcp_socket server(ioc);
        client.open();

        bool both_done = false;
        std::error_code read_ec;
        std::error_code write_ec;

        capy::run_async(ioc.get_executor())(
            [&]() -> capy::task<> {
                auto [cn_ec] = co_await client.connect(
                    endpoint(ipv4_address::loopback(), port));
                BOOST_TEST(!cn_ec);
                auto [ac_ec] = co_await acc.accept(server);
                BOOST_TEST(!ac_ec);

                char read_buf[64];

                // Large write buffer to saturate the kernel socket send buffer
                // so write_some blocks rather than completing immediately.
                std::vector<char> big_buf(16 * 1024 * 1024, 'x');

                auto reader_coro = [&]() -> capy::task<> {
                    auto [ec, n] = co_await client.read_some(
                        capy::mutable_buffer(read_buf, sizeof(read_buf)));
                    read_ec = ec;
                };

                auto writer_coro = [&]() -> capy::task<> {
                    while (true)
                    {
                        auto [ec, n] = co_await client.write_some(
                            capy::const_buffer(big_buf.data(), big_buf.size()));
                        if (ec)
                        {
                            write_ec = ec;
                            break;
                        }
                    }
                };

                capy::run_async(ioc.get_executor())(reader_coro());
                capy::run_async(ioc.get_executor())(writer_coro());

                // Let the ops land in the ring before cancelling.
                timer t(ioc);
                t.expires_after(std::chrono::milliseconds(20));
                (void)co_await t.wait();

                client.cancel();

                // Give cancellation CQEs time to arrive.
                timer t2(ioc);
                t2.expires_after(std::chrono::milliseconds(50));
                (void)co_await t2.wait();

                both_done = true;
            }());

        ioc.run();
        BOOST_TEST(both_done);
        BOOST_TEST(read_ec == capy::cond::canceled);
        BOOST_TEST(write_ec == capy::cond::canceled);
    }

    /** Placeholder for the probe-and-fallback path.

        Forcing the io_uring probe to fail at runtime requires a seccomp
        filter that blocks io_uring_setup, which the test framework does
        not currently support. To exercise the fallback manually, run on a
        Docker default-seccomp container or a host with
        kernel.io_uring_disabled=2. */
    void testProbeFallback()
    {
        BOOST_TEST_PASS();
    }

    void run()
    {
        testSqBackpressure();
        testMultishotAcceptQueue();
        testCancelByFd();
        testProbeFallback();
    }
};

TEST_SUITE(
    native_io_uring_specific_test,
    "boost.corosio.native.io_uring_specific");

} // namespace boost::corosio

#endif // BOOST_COROSIO_HAS_IO_URING
