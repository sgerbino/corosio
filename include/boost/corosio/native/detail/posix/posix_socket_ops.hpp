//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_POSIX_POSIX_SOCKET_OPS_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_POSIX_POSIX_SOCKET_OPS_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/native/detail/make_err.hpp>

#include <sys/socket.h>

#include <cstddef>
#include <system_error>

namespace boost::corosio::detail::posix {

/// Perform socket shutdown.
inline std::error_code
do_shutdown(int fd, tcp_socket::shutdown_type what) noexcept
{
    int how;
    switch (what)
    {
    case tcp_socket::shutdown_receive:
        how = SHUT_RD;
        break;
    case tcp_socket::shutdown_send:
        how = SHUT_WR;
        break;
    case tcp_socket::shutdown_both:
        how = SHUT_RDWR;
        break;
    default:
        return make_err(EINVAL);
    }
    if (::shutdown(fd, how) != 0)
        return make_err(errno);
    return {};
}

/// Set a socket option.
inline std::error_code
do_set_option(
    int fd, int level, int optname, void const* data, std::size_t size) noexcept
{
    if (::setsockopt(fd, level, optname, data, static_cast<socklen_t>(size)) !=
        0)
        return make_err(errno);
    return {};
}

/// Get a socket option.
inline std::error_code
do_get_option(
    int fd, int level, int optname, void* data, std::size_t* size) noexcept
{
    socklen_t len = static_cast<socklen_t>(*size);
    if (::getsockopt(fd, level, optname, data, &len) != 0)
        return make_err(errno);
    *size = static_cast<std::size_t>(len);
    return {};
}

} // namespace boost::corosio::detail::posix

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_POSIX_POSIX_SOCKET_OPS_HPP
