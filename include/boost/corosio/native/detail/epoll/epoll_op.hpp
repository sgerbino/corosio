//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_OP_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_OP_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/native/detail/reactor_op.hpp>
#include <boost/corosio/native/detail/reactor_descriptor_state.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/endpoint_convert.hpp>

#include <boost/capy/error.hpp>

#include <cstdint>

/*
    epoll Operation State
    =====================

    Each async I/O operation has a corresponding epoll_op-derived struct that
    holds the operation's state while it's in flight. The socket impl owns
    fixed slots for each operation type (conn_, rd_, wr_), so only one
    operation of each type can be pending per socket at a time.

    Persistent Registration
    -----------------------
    File descriptors are registered with epoll once (via descriptor_state) and
    stay registered until closed. The descriptor_state tracks which operations
    are pending (read_op, write_op, connect_op). When an event arrives, the
    reactor dispatches to the appropriate pending operation.

    Impl Lifetime Management
    ------------------------
    When cancel() posts an op to the scheduler's ready queue, the socket impl
    might be destroyed before the scheduler processes the op. The `impl_ptr`
    member holds a shared_ptr to the impl, keeping it alive until the op
    completes. This is set by cancel() and cleared in operator() after the
    coroutine is resumed.

    EOF Detection
    -------------
    For reads, 0 bytes with no error means EOF. But an empty user buffer also
    returns 0 bytes. The `empty_buffer_read` flag distinguishes these cases.

    SIGPIPE Prevention
    ------------------
    Writes use sendmsg() with MSG_NOSIGNAL instead of writev() to prevent
    SIGPIPE when the peer has closed.
*/

namespace boost::corosio::detail {

// Forward declarations
class epoll_socket;
class epoll_acceptor;
class epoll_scheduler;

/// Backend traits for epoll.
struct epoll_backend
{
    using socket_type   = epoll_socket;
    using acceptor_type = epoll_acceptor;
};

/// Base operation type for epoll backend.
using epoll_op = reactor_op<epoll_backend>;

/** Per-descriptor state for persistent epoll registration.

    Fd is registered once with epoll and stays registered until closed.
    Deferred I/O: reactor sets ready_events and queues this struct,
    scheduler pops it and calls operator()() to perform I/O under mutex.
*/
struct descriptor_state final
    : reactor_descriptor_state<epoll_op, epoll_scheduler>
{
    /// Perform deferred I/O and queue completions.
    void operator()() override;
};

/** Connect operation for epoll backend.

    Inherits shared perform_io() (SO_ERROR check) from reactor_connect_op.
*/
struct epoll_connect_op final : reactor_connect_op<epoll_backend>
{
    void operator()() override;
};

/** Read operation for epoll backend. */
struct epoll_read_op final : reactor_read_op<epoll_backend>
{
    void operator()() override;
};

/** Write operation for epoll backend. */
struct epoll_write_op final : reactor_write_op<epoll_backend>
{
    void operator()() override;
};

/** Accept operation for epoll backend.

    Overrides perform_io() with accept4(SOCK_NONBLOCK|SOCK_CLOEXEC).
*/
struct epoll_accept_op final : reactor_accept_op<epoll_backend>
{
    void perform_io() noexcept override
    {
        socklen_t addrlen = sizeof(peer_storage);
        int new_fd;
        do
        {
            new_fd = ::accept4(
                fd, reinterpret_cast<sockaddr*>(&peer_storage), &addrlen,
                SOCK_NONBLOCK | SOCK_CLOEXEC);
        }
        while (new_fd < 0 && errno == EINTR);

        if (new_fd >= 0)
        {
            accepted_fd = new_fd;
            complete(0, 0);
        }
        else
        {
            complete(errno, 0);
        }
    }

    void operator()() override;
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL

#endif // BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_OP_HPP
