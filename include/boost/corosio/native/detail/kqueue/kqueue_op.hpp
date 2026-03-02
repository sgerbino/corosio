//
// Copyright (c) 2026 Michael Vandeberg
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_OP_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_OP_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_KQUEUE

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/native/detail/reactor_op.hpp>
#include <boost/corosio/native/detail/reactor_descriptor_state.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/endpoint_convert.hpp>

#include <boost/capy/error.hpp>

#include <cstdint>
#include <fcntl.h>

/*
    kqueue Operation State
    ======================

    Each async I/O operation has a corresponding kqueue_op-derived struct that
    holds the operation's state while it's in flight. The socket impl owns
    fixed slots for each operation type (conn_, rd_, wr_), so only one
    operation of each type can be pending per socket at a time.

    Persistent Registration
    -----------------------
    File descriptors are registered with kqueue once (via descriptor_state) and
    stay registered until closed. Uses EV_CLEAR for edge-triggered semantics
    (equivalent to epoll's EPOLLET). The descriptor_state tracks which operations
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
    SO_NOSIGPIPE is set on each socket at creation time (see sockets.cpp).
    Writes use writev() which is safe because the socket-level option suppresses
    SIGPIPE delivery.
*/

namespace boost::corosio::detail {

// Ready-event flag constants for descriptor_state::ready_events_.
// These match the epoll numeric values (EPOLLIN=0x1, EPOLLOUT=0x4,
// EPOLLERR=0x8) so that descriptor_state::operator()() uses the same
// flag-checking logic as the epoll backend.
static constexpr std::uint32_t kqueue_event_read  = 0x001;
static constexpr std::uint32_t kqueue_event_write = 0x004;
static constexpr std::uint32_t kqueue_event_error = 0x008;

// Forward declarations
class kqueue_socket;
class kqueue_acceptor;
class kqueue_scheduler;

/// Backend traits for kqueue.
struct kqueue_backend
{
    using socket_type   = kqueue_socket;
    using acceptor_type = kqueue_acceptor;
};

/// Base operation type for kqueue backend.
using kqueue_op = reactor_op<kqueue_backend>;

/** Per-descriptor state for persistent kqueue registration.

    Fd is registered once with kqueue (EVFILT_READ + EVFILT_WRITE, both
    EV_CLEAR) and stays registered until closed. Deferred I/O: reactor
    sets ready_events and queues this struct, scheduler pops it and calls
    operator()() to perform I/O under mutex.
*/
struct descriptor_state final
    : reactor_descriptor_state<kqueue_op, kqueue_scheduler>
{
    /// Perform deferred I/O and queue completions.
    void operator()() override;
};

/** Connect operation for kqueue backend.

    Inherits shared perform_io() (SO_ERROR check) from reactor_connect_op.
*/
struct kqueue_connect_op final : reactor_connect_op<kqueue_backend>
{
    void operator()() override;
};

/** Read operation for kqueue backend. */
struct kqueue_read_op final : reactor_read_op<kqueue_backend>
{
    void operator()() override;
};

/** Write operation for kqueue backend.

    Overrides perform_io() with writev() (SO_NOSIGPIPE set at socket
    creation time prevents SIGPIPE).
*/
struct kqueue_write_op final : reactor_write_op<kqueue_backend>
{
    void perform_io() noexcept override
    {
        ssize_t n;
        do
        {
            n = ::writev(fd, iovecs, iovec_count);
        }
        while (n < 0 && errno == EINTR);

        if (n >= 0)
            complete(0, static_cast<std::size_t>(n));
        else
            complete(errno, 0);
    }

    void operator()() override;
};

/** Accept operation for kqueue backend.

    Overrides perform_io() with accept()+fcntl()+SO_NOSIGPIPE.
*/
struct kqueue_accept_op final : reactor_accept_op<kqueue_backend>
{
    void perform_io() noexcept override
    {
        sockaddr_storage addr_storage{};
        socklen_t addrlen = sizeof(addr_storage);

        int new_fd;
        do
        {
            new_fd = ::accept(
                fd, reinterpret_cast<sockaddr*>(&addr_storage), &addrlen);
        }
        while (new_fd < 0 && errno == EINTR);

        if (new_fd >= 0)
        {
            // Set non-blocking
            int flags = ::fcntl(new_fd, F_GETFL, 0);
            if (flags == -1 ||
                ::fcntl(new_fd, F_SETFL, flags | O_NONBLOCK) == -1)
            {
                int err = errno;
                ::close(new_fd);
                complete(err, 0);
                return;
            }

            // Set close-on-exec
            if (::fcntl(new_fd, F_SETFD, FD_CLOEXEC) == -1)
            {
                int err = errno;
                ::close(new_fd);
                complete(err, 0);
                return;
            }

            // Suppress SIGPIPE on accepted sockets; macOS lacks MSG_NOSIGNAL
            int one = 1;
            if (::setsockopt(
                    new_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) == -1)
            {
                int err = errno;
                ::close(new_fd);
                complete(err, 0);
                return;
            }

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

#endif // BOOST_COROSIO_HAS_KQUEUE

#endif // BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_OP_HPP
