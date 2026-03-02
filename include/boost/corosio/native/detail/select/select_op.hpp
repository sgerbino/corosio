//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_OP_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_OP_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/native/detail/reactor_op.hpp>
#include <boost/corosio/native/detail/reactor_descriptor_state.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/endpoint_convert.hpp>

#include <boost/capy/error.hpp>

#include <cstdint>
#include <fcntl.h>
#include <sys/select.h>

/*
    select Operation State
    ======================

    Each async I/O operation has a corresponding select_op-derived struct that
    holds the operation's state while it's in flight. The socket impl owns
    fixed slots for each operation type (conn_, rd_, wr_), so only one
    operation of each type can be pending per socket at a time.

    Persistent Descriptor Registration
    -----------------------------------
    File descriptors are tracked by the scheduler via descriptor_state and
    stay tracked until closed. The descriptor_state tracks which operations
    are pending (read_op, write_op, connect_op). When select() reports
    readiness, the reactor dispatches to the appropriate pending operation
    through the deferred I/O model.

    Deferred I/O Model
    ------------------
    The reactor no longer performs I/O directly. Instead:
    1. Reactor sets ready_events and queues descriptor_state
    2. Scheduler pops descriptor_state and calls operator()
    3. operator() performs I/O under mutex and queues completions

    This matches the epoll/kqueue architecture and eliminates
    per-descriptor mutex locking from the reactor hot path.

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
class select_socket;
class select_acceptor;
class select_scheduler;

// Ready-event constants matching epoll/kqueue conventions
static constexpr std::uint32_t select_event_read  = 0x001;
static constexpr std::uint32_t select_event_write = 0x004;
static constexpr std::uint32_t select_event_error = 0x008;

/// Backend traits for select.
struct select_backend
{
    using socket_type   = select_socket;
    using acceptor_type = select_acceptor;
};

/// Base operation type for select backend.
using select_op = reactor_op<select_backend>;

/** Per-descriptor state for persistent select registration.

    Fd is tracked by the scheduler and stays tracked until closed.
    Deferred I/O: reactor sets ready_events and queues this struct,
    scheduler pops it and calls operator()() to perform I/O under mutex.
*/
struct select_descriptor_state final
    : reactor_descriptor_state<select_op, select_scheduler>
{
    /// Perform deferred I/O and queue completions.
    void operator()() override;
};

/** Connect operation for select backend.

    Inherits shared perform_io() (SO_ERROR check) from reactor_connect_op.
*/
struct select_connect_op final : reactor_connect_op<select_backend>
{
    void operator()() override;
};

/** Read operation for select backend. */
struct select_read_op final : reactor_read_op<select_backend>
{
    void operator()() override;
};

/** Write operation for select backend. */
struct select_write_op final : reactor_write_op<select_backend>
{
    void operator()() override;
};

/** Accept operation for select backend.

    Overrides perform_io() with accept()+fcntl() and FD_SETSIZE guard.
*/
struct select_accept_op final : reactor_accept_op<select_backend>
{
    void perform_io() noexcept override
    {
        socklen_t addrlen = sizeof(peer_storage);

        int new_fd;
        do
        {
            new_fd = ::accept(
                fd, reinterpret_cast<sockaddr*>(&peer_storage), &addrlen);
        }
        while (new_fd < 0 && errno == EINTR);

        if (new_fd >= 0)
        {
            // Reject fds that exceed select()'s FD_SETSIZE limit
            if (new_fd >= FD_SETSIZE)
            {
                ::close(new_fd);
                complete(EINVAL, 0);
                return;
            }

            int flags = ::fcntl(new_fd, F_GETFL, 0);
            if (flags == -1)
            {
                int err = errno;
                ::close(new_fd);
                complete(err, 0);
                return;
            }

            if (::fcntl(new_fd, F_SETFL, flags | O_NONBLOCK) == -1)
            {
                int err = errno;
                ::close(new_fd);
                complete(err, 0);
                return;
            }

            if (::fcntl(new_fd, F_SETFD, FD_CLOEXEC) == -1)
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

#endif // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_OP_HPP
