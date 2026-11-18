//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/native/native_tcp_socket.hpp>
#include <boost/corosio/native/native_tcp_acceptor.hpp>
#include <boost/corosio/native/native_io_context.hpp>
#include <boost/corosio/native/native_socket_option.hpp>
#include <boost/corosio/test/socket_pair.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>

#include <array>
#include <cstddef>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "context.hpp"
#include "must.hpp"
#include "test_suite.hpp"

namespace boost::corosio {

template<auto Backend>
struct native_tcp_socket_test
{
    // Shadow-engagement checks: the native overload must return a
    // distinct awaitable type from the base. If a shadow is broken
    // (e.g. signature drift, missing override), these fail at compile
    // time. The check is unevaluated; no runtime cost.
    static_assert(
        !std::is_same_v<
            decltype(std::declval<native_tcp_socket<Backend>&>().read_some(
                std::declval<capy::mutable_buffer>())),
            decltype(std::declval<io_stream&>().read_some(
                std::declval<capy::mutable_buffer>()))>,
        "native_tcp_socket::read_some must shadow io_stream::read_some");
    static_assert(
        !std::is_same_v<
            decltype(std::declval<native_tcp_socket<Backend>&>().write_some(
                std::declval<capy::const_buffer>())),
            decltype(std::declval<io_stream&>().write_some(
                std::declval<capy::const_buffer>()))>,
        "native_tcp_socket::write_some must shadow io_stream::write_some");
    static_assert(
        !std::is_same_v<
            decltype(std::declval<native_tcp_socket<Backend>&>().connect(
                std::declval<endpoint>())),
            decltype(std::declval<tcp_socket&>().connect(
                std::declval<endpoint>()))>,
        "native_tcp_socket::connect must shadow tcp_socket::connect");
    static_assert(
        !std::is_same_v<
            decltype(std::declval<native_tcp_socket<Backend>&>().wait(
                wait_type::read)),
            decltype(std::declval<tcp_socket&>().wait(wait_type::read))>,
        "native_tcp_socket::wait must shadow tcp_socket::wait");

    void testSocketConstruct()
    {
        native_io_context<Backend> ctx;
        native_tcp_socket<Backend> s(ctx);
        BOOST_TEST_PASS();
    }

    void testSocketMoveConstruct()
    {
        native_io_context<Backend> ctx;
        native_tcp_socket<Backend> s1(ctx);
        BOOST_TEST(!s1.open());
        BOOST_TEST(s1.is_open());

        native_tcp_socket<Backend> s2(std::move(s1));
        BOOST_TEST(s2.is_open());
    }

    void testSocketPolymorphicSlice()
    {
        native_io_context<Backend> ctx;
        native_tcp_socket<Backend> ns(ctx);
        BOOST_TEST(!ns.open());

        tcp_socket& base = ns;
        BOOST_TEST(base.is_open());

        [[maybe_unused]] io_stream& stream_base = ns;

        [[maybe_unused]] io_read_stream& read_base = ns;

        [[maybe_unused]] io_write_stream& write_base = ns;

        BOOST_TEST_PASS();
    }

    // Exercise the shadowed wait() awaitable. A connected socket with
    // an empty send buffer probes writable, so wait_type::write
    // resolves without parking on every backend.
    void testWait()
    {
        native_io_context<Backend> ioc;
        auto [s1, s2] = test::must(
            test::make_socket_pair<
                native_tcp_socket<Backend>, native_tcp_acceptor<Backend>>(ioc));

        std::error_code wait_ec;
        bool wait_done = false;

        auto waiter = [&]() -> capy::task<> {
            auto [ec] = co_await s1.wait(wait_type::write);
            wait_ec   = ec;
            wait_done = true;
        };
        capy::run_async(ioc.get_executor())(waiter());
        ioc.run();

        BOOST_TEST(wait_done);
        BOOST_TEST(!wait_ec);
    }

    // Exercise inline native_socket_option types on a TCP socket so the
    // boolean<IPPROTO_TCP, TCP_NODELAY> instantiation is fully hit.
    void testNativeNoDelay()
    {
        native_io_context<Backend> ctx;
        native_tcp_socket<Backend> s(ctx);
        BOOST_TEST(!s.open());

        test::must_ok(s.set_option(native_socket_option::no_delay(true)));
        auto nd =
            test::must(s.template get_option<native_socket_option::no_delay>());
        BOOST_TEST(nd.value());

        test::must_ok(s.set_option(native_socket_option::no_delay(false)));
        nd =
            test::must(s.template get_option<native_socket_option::no_delay>());
        BOOST_TEST(!nd.value());

        // Cover member accessors on the inline boolean<>.
        native_socket_option::no_delay direct(true);
        BOOST_TEST(direct.value());
        BOOST_TEST_EQ(direct.size(family::v4), sizeof(int));
        BOOST_TEST(direct.data(family::v4) != nullptr);
        BOOST_TEST_EQ(direct.level(family::v4), IPPROTO_TCP);
        BOOST_TEST_EQ(direct.name(family::v4), TCP_NODELAY);

        native_socket_option::no_delay const& cd = direct;
        BOOST_TEST(cd.data(family::v4) != nullptr);

        s.close();
    }

    void testConnectAutoOpens()
    {
        // connect() auto-opens like the base class: the failure (no
        // listener on the target port) comes from the connect attempt,
        // not from a closed descriptor, and the socket ends up open.
        native_io_context<Backend> ioc;
        native_tcp_socket<Backend> s(ioc);
        BOOST_TEST_EQ(s.is_open(), false);

        bool done = false;
        auto task = [&]() -> capy::task<> {
            auto [ec] =
                co_await s.connect(endpoint(ipv4_address::loopback(), 1));
            BOOST_TEST(ec != std::errc::bad_file_descriptor);
            done = true;
        };
        capy::run_async(ioc.get_executor())(task());
        ioc.run();
        BOOST_TEST(done);
        BOOST_TEST(s.is_open());
    }

    // Stream operations on a closed socket complete with
    // bad_file_descriptor instead of dispatching.
    void testClosedOpsComplete()
    {
        native_io_context<Backend> ioc;
        native_tcp_socket<Backend> s(ioc);

        bool done = false;
        auto task = [&]() -> capy::task<> {
            char buf[8] = {};

            auto [rec, rn] =
                co_await s.read_some(capy::mutable_buffer(buf, sizeof(buf)));
            BOOST_TEST(rec == std::errc::bad_file_descriptor);
            BOOST_TEST_EQ(rn, 0u);

            auto [wec, wn] =
                co_await s.write_some(capy::const_buffer(buf, sizeof(buf)));
            BOOST_TEST(wec == std::errc::bad_file_descriptor);
            BOOST_TEST_EQ(wn, 0u);

            auto [tec] = co_await s.wait(wait_type::read);
            BOOST_TEST(tec == std::errc::bad_file_descriptor);

            auto [raec, ran] =
                co_await s.read(capy::mutable_buffer(buf, sizeof(buf)));
            BOOST_TEST(raec == std::errc::bad_file_descriptor);
            BOOST_TEST_EQ(ran, 0u);

            auto [waec, wan] =
                co_await s.write(capy::const_buffer(buf, sizeof(buf)));
            BOOST_TEST(waec == std::errc::bad_file_descriptor);
            BOOST_TEST_EQ(wan, 0u);
            done = true;
        };
        capy::run_async(ioc.get_executor())(task());
        ioc.run();
        BOOST_TEST(done);
    }

    using socket_pair_t =
        std::tuple<native_tcp_socket<Backend>, native_tcp_socket<Backend>>;

    static socket_pair_t make_pair(native_io_context<Backend>& ioc)
    {
        return test::must(
            test::make_socket_pair<
                native_tcp_socket<Backend>, native_tcp_acceptor<Backend>>(ioc));
    }

    static std::vector<char> pattern(std::size_t n, int seed)
    {
        std::vector<char> v(n);
        for (std::size_t i = 0; i < n; ++i)
            v[i] = static_cast<char>(i * 31 + static_cast<std::size_t>(seed));
        return v;
    }

    static std::vector<char>
    slice(std::vector<char> const& v, std::size_t pos, std::size_t n)
    {
        return {v.begin() + pos, v.begin() + pos + n};
    }

    // More than the socket buffers hold, so both sides park partway
    // and resume with their progress.
    void testTransferAllLarge()
    {
        native_io_context<Backend> ioc;
        auto [a, b] = make_pair(ioc);

        std::size_t const part = std::size_t(4) << 20;
        auto const x           = pattern(part, 1);
        auto const y           = pattern(part, 2);
        auto const z           = pattern(part, 3);
        std::vector<char> in(3 * part);

        std::error_code wec, rec;
        std::size_t wn = 0, rn = 0;
        auto writer = [&]() -> capy::task<> {
            std::array<capy::const_buffer, 3> bufs{
                capy::const_buffer(x.data(), part),
                capy::const_buffer(y.data(), part),
                capy::const_buffer(z.data(), part)};
            auto [ec, n] = co_await a.write(bufs);
            wec          = ec;
            wn           = n;
        };
        auto reader = [&]() -> capy::task<> {
            auto [ec, n] =
                co_await b.read(capy::mutable_buffer(in.data(), in.size()));
            rec = ec;
            rn  = n;
        };
        capy::run_async(ioc.get_executor())(writer());
        capy::run_async(ioc.get_executor())(reader());
        ioc.run();

        BOOST_TEST(!wec);
        BOOST_TEST_EQ(wn, 3 * part);
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(rn, 3 * part);
        BOOST_TEST(slice(in, 0, part) == x);
        BOOST_TEST(slice(in, part, part) == y);
        BOOST_TEST(slice(in, 2 * part, part) == z);
    }

    // More buffers than one OS buffer array holds, in both directions.
    void testTransferAllManyBuffers()
    {
        native_io_context<Backend> ioc;
        auto [a, b] = make_pair(ioc);

        constexpr int count   = 40;
        std::size_t const len = 1000;
        std::vector<std::vector<char>> out, in;
        std::vector<capy::const_buffer> ob;
        std::vector<capy::mutable_buffer> ib;
        for (int k = 0; k < count; ++k)
        {
            // Empty buffers in the middle must be skipped, not end it.
            std::size_t const n = (k % 7 == 3) ? 0 : len;
            out.push_back(pattern(n, k));
            in.emplace_back(n);
        }
        for (int k = 0; k < count; ++k)
        {
            ob.emplace_back(out[k].data(), out[k].size());
            ib.emplace_back(in[k].data(), in[k].size());
        }
        std::size_t total = 0;
        for (auto const& v : out)
            total += v.size();

        std::error_code wec, rec;
        std::size_t wn = 0, rn = 0;
        auto writer = [&]() -> capy::task<> {
            auto [ec, n] = co_await a.write(ob);
            wec          = ec;
            wn           = n;
        };
        auto reader = [&]() -> capy::task<> {
            auto [ec, n] = co_await b.read(ib);
            rec          = ec;
            rn           = n;
        };
        capy::run_async(ioc.get_executor())(reader());
        capy::run_async(ioc.get_executor())(writer());
        ioc.run();

        BOOST_TEST(!wec);
        BOOST_TEST_EQ(wn, total);
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(rn, total);
        BOOST_TEST(out == in);
    }

    // A read that starts parked collects every piece the peer sends.
    void testReadAllPieces()
    {
        native_io_context<Backend> ioc;
        auto [a, b] = make_pair(ioc);

        auto const out = pattern(100, 7);
        std::vector<char> in(100);
        std::error_code rec;
        std::size_t rn = 0;
        auto reader    = [&]() -> capy::task<> {
            auto [ec, n] =
                co_await b.read(capy::mutable_buffer(in.data(), in.size()));
            rec = ec;
            rn  = n;
        };
        auto writer = [&]() -> capy::task<> {
            std::size_t const cuts[] = {0, 10, 50, 100};
            for (std::size_t i = 0; i + 1 < std::size(cuts); ++i)
            {
                auto [ec, n] = co_await a.write(
                    capy::const_buffer(
                        out.data() + cuts[i], cuts[i + 1] - cuts[i]));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, cuts[i + 1] - cuts[i]);
            }
        };
        capy::run_async(ioc.get_executor())(reader());
        capy::run_async(ioc.get_executor())(writer());
        ioc.run();

        BOOST_TEST(!rec);
        BOOST_TEST_EQ(rn, 100u);
        BOOST_TEST(out == in);
    }

    // End of stream partway reports eof with the bytes read before
    // it, whether the read starts before or after the data arrives.
    void testReadAllEof()
    {
        for (bool reader_first : {true, false})
        {
            native_io_context<Backend> ioc;
            auto [a, b] = make_pair(ioc);

            auto const out = pattern(100, 9);
            std::vector<char> in(1000);
            std::error_code rec;
            std::size_t rn = 0;
            auto reader    = [&]() -> capy::task<> {
                auto [ec, n] =
                    co_await b.read(capy::mutable_buffer(in.data(), in.size()));
                rec = ec;
                rn  = n;
            };
            auto writer = [&]() -> capy::task<> {
                auto [ec, n] = co_await a.write(
                    capy::const_buffer(out.data(), out.size()));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, out.size());
                test::must_ok(a.shutdown(shutdown_type::shutdown_send));
            };
            if (reader_first)
                capy::run_async(ioc.get_executor())(reader());
            capy::run_async(ioc.get_executor())(writer());
            if (!reader_first)
                capy::run_async(ioc.get_executor())(reader());
            ioc.run();

            BOOST_TEST(rec == capy::cond::eof);
            BOOST_TEST_EQ(rn, out.size());
            BOOST_TEST(slice(in, 0, out.size()) == out);
        }
    }

    // Cancelling a write the peer never drains reports canceled,
    // even when some bytes were taken.
    void testWriteAllCancel()
    {
        native_io_context<Backend> ioc;
        auto [a, b] = make_pair(ioc);

        std::vector<char> big(std::size_t(32) << 20);
        std::error_code wec;
        std::size_t wn = big.size();
        bool done      = false;
        auto writer    = [&]() -> capy::task<> {
            auto [ec, n] =
                co_await a.write(capy::const_buffer(big.data(), big.size()));
            wec  = ec;
            wn   = n;
            done = true;
        };
        // Runs once the writer has parked on a full send buffer.
        auto canceller = [&]() -> capy::task<> {
            a.cancel();
            co_return;
        };
        capy::run_async(ioc.get_executor())(writer());
        capy::run_async(ioc.get_executor())(canceller());
        ioc.run();

        BOOST_TEST(done);
        BOOST_TEST(wec == capy::cond::canceled);
        BOOST_TEST(wn < big.size());
    }

    // Cancelling a parked read keeps the bytes it already filled.
    void testReadAllCancel()
    {
        native_io_context<Backend> ioc;
        auto [a, b] = make_pair(ioc);

        auto const out = pattern(10, 11);
        std::vector<char> in(100);
        std::error_code rec;
        std::size_t rn = in.size();
        auto reader    = [&]() -> capy::task<> {
            auto [ec, n] =
                co_await b.read(capy::mutable_buffer(in.data(), in.size()));
            rec = ec;
            rn  = n;
        };
        auto writer = [&]() -> capy::task<> {
            auto [ec, n] =
                co_await a.write(capy::const_buffer(out.data(), out.size()));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, out.size());
            b.cancel();
        };
        capy::run_async(ioc.get_executor())(reader());
        capy::run_async(ioc.get_executor())(writer());
        ioc.run();

        BOOST_TEST(rec == capy::cond::canceled);
        BOOST_TEST(rn <= out.size());
        BOOST_TEST(slice(in, 0, rn) == slice(out, 0, rn));
    }

    void testTransferAllEmpty()
    {
        native_io_context<Backend> ioc;
        auto [a, b] = make_pair(ioc);

        bool done = false;
        auto task = [&]() -> capy::task<> {
            auto [wec, wn] = co_await a.write(capy::const_buffer());
            BOOST_TEST(!wec);
            BOOST_TEST_EQ(wn, 0u);
            auto [rec, rn] = co_await b.read(capy::mutable_buffer());
            BOOST_TEST(!rec);
            BOOST_TEST_EQ(rn, 0u);
            done = true;
        };
        capy::run_async(ioc.get_executor())(task());
        ioc.run();
        BOOST_TEST(done);
    }

    void run()
    {
        testConnectAutoOpens();
        testClosedOpsComplete();
        testSocketConstruct();
        testSocketMoveConstruct();
        testSocketPolymorphicSlice();
        testWait();
        testNativeNoDelay();
        testTransferAllLarge();
        testTransferAllManyBuffers();
        testReadAllPieces();
        testReadAllEof();
        testWriteAllCancel();
        testReadAllCancel();
        testTransferAllEmpty();
    }
};

COROSIO_BACKEND_TESTS(native_tcp_socket_test, "boost.corosio.native.tcp_socket")

} // namespace boost::corosio
