//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/test/socket_pair.hpp>
#include <boost/corosio/acceptor.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/url/ipv4_address.hpp>

#include <cstdint>
#include <stdexcept>

namespace boost {
namespace corosio {
namespace test {

namespace {

constexpr std::uint16_t test_port_base = 49300;
constexpr std::uint16_t test_port_range = 100;
std::uint16_t next_test_port = 0;

std::uint16_t
get_test_port() noexcept
{
    auto port = test_port_base + (next_test_port % test_port_range);
    ++next_test_port;
    return static_cast<std::uint16_t>(port);
}

} // namespace

std::pair<socket, socket>
make_socket_pair(io_context& ioc)
{
    auto ex = ioc.get_executor();
    std::uint16_t port = get_test_port();

    system::error_code accept_ec;
    system::error_code connect_ec;
    bool accept_done = false;
    bool connect_done = false;

    acceptor acc(ioc);
    acc.listen(endpoint(urls::ipv4_address::loopback(), port));

    socket s1(ioc);
    socket s2(ioc);
    s2.open();

    capy::run_async(ex)(
        [](acceptor& a, socket& s,
           system::error_code& ec_out, bool& done_out) -> capy::task<>
        {
            auto [ec] = co_await a.accept(s);
            ec_out = ec;
            done_out = true;
        }(acc, s1, accept_ec, accept_done));

    capy::run_async(ex)(
        [](socket& s, endpoint ep,
           system::error_code& ec_out, bool& done_out) -> capy::task<>
        {
            auto [ec] = co_await s.connect(ep);
            ec_out = ec;
            done_out = true;
        }(s2, endpoint(urls::ipv4_address::loopback(), port),
          connect_ec, connect_done));

    ioc.run();
    ioc.restart();

    if (!accept_done || accept_ec)
    {
        acc.close();
        throw std::runtime_error("socket_pair accept failed");
    }

    if (!connect_done || connect_ec)
    {
        acc.close();
        s1.close();
        throw std::runtime_error("socket_pair connect failed");
    }

    acc.close();

    return {std::move(s1), std::move(s2)};
}

} // namespace test
} // namespace corosio
} // namespace boost
