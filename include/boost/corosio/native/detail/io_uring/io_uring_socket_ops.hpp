//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SOCKET_OPS_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SOCKET_OPS_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

#include <liburing.h>

#include <boost/capy/error.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_buffer.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_scheduler.hpp>
#include <boost/corosio/native/detail/make_err.hpp>

#include <system_error>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace boost::corosio::detail {

/// Maximum scatter/gather segments per read/write/dgram op.
///
/// Bounded well below `IOV_MAX` (1024 on Linux) so each op's
/// `iovec[io_uring_max_iov]` lives inside the io_uring_op object on
/// the same allocation as the rest of its state. Plan 4's registered-
/// buffer work will revisit; until then 16 covers typical scatter use
/// cases (fragmented buffers from buffer_sequence) without bloating
/// per-op memory.
inline constexpr std::size_t io_uring_max_iov = 16;

/** Resolve ec_out/bytes_out from a CQE result for a completed I/O op.

    Shared by read, write, and connect handlers. For reads, `res == 0`
    with a non-empty buffer means the peer closed the connection (EOF).

    @param self       The completed op.
    @param is_read    True if this is a receive/read operation.
    @param empty_buf  True if the submitted buffer was zero-length.
*/
inline void
uring_set_result(io_uring_op* self, bool is_read, bool empty_buf) noexcept
{
    if (!self->ec_out)
        return;

    if (self->cancelled.load(std::memory_order_acquire))
        *self->ec_out = capy::error::canceled;
    else if (self->res < 0)
        *self->ec_out = make_err(-self->res);
    else if (is_read && self->res == 0 && !empty_buf)
        *self->ec_out = capy::error::eof;
    else
        *self->ec_out = {};
}

/** Scatter-gather read via `IORING_OP_READV`.

    @par Handler dispatch
    do_cqe captures `res`/`cqe_flags` and queues self into `local`;
    do_handler runs from the scheduler queue and resumes the coroutine.
*/
struct uring_read_op : io_uring_op
{
    iovec iovecs[io_uring_max_iov];
    int   iovec_count = 0;
    int   fd          = -1;

    uring_read_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep)
    {
        is_read = true;
    }

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_read_op*>(base);
        ::io_uring_prep_readv(
            sqe, self->fd, self->iovecs, self->iovec_count, 0);
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags,
        op_queue& local) noexcept
    {
        auto* self      = static_cast<uring_read_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_read_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            auto h = self->h;
            delete self;
            if (h) h.destroy();
            return;
        }

        uring_set_result(self, true, self->empty_buffer);

        if (self->bytes_out)
            *self->bytes_out =
                self->res >= 0 ? static_cast<std::size_t>(self->res) : 0u;

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

/** Scatter-gather write via `IORING_OP_SENDMSG` with `MSG_NOSIGNAL`.

    `MSG_NOSIGNAL` prevents `SIGPIPE` when the peer has closed the
    connection; the error is surfaced as `EPIPE` instead.
*/
struct uring_write_op : io_uring_op
{
    iovec  iovecs[io_uring_max_iov];
    int    iovec_count = 0;
    int    fd          = -1;
    msghdr msg{};

    uring_write_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep)
    {}

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_write_op*>(base);
        ::io_uring_prep_sendmsg(
            sqe, self->fd, &self->msg, MSG_NOSIGNAL);
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags,
        op_queue& local) noexcept
    {
        auto* self      = static_cast<uring_write_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_write_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            auto h = self->h;
            delete self;
            if (h) h.destroy();
            return;
        }

        uring_set_result(self, false, self->empty_buffer);

        if (self->bytes_out)
            *self->bytes_out =
                self->res >= 0 ? static_cast<std::size_t>(self->res) : 0u;

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

/** Non-blocking connect via `IORING_OP_CONNECT`.

    Negative `res` is the connect error; zero means success.
    `remote_endpoint_out` is written only on success so a failed
    connect does not corrupt the socket's cached remote endpoint.
*/
struct uring_connect_op : io_uring_op
{
    sockaddr_storage addr{};
    socklen_t        addrlen            = 0;
    int              fd                 = -1;
    endpoint         target_endpoint{};
    endpoint*        remote_endpoint_out = nullptr;
    endpoint*        local_endpoint_out  = nullptr;

    uring_connect_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep)
    {}

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_connect_op*>(base);
        ::io_uring_prep_connect(
            sqe, self->fd,
            reinterpret_cast<sockaddr const*>(&self->addr),
            self->addrlen);
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags,
        op_queue& local) noexcept
    {
        auto* self      = static_cast<uring_connect_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_connect_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            auto h = self->h;
            delete self;
            if (h) h.destroy();
            return;
        }

        uring_set_result(self, false, false);

        // Write endpoints only on success.
        if (self->res >= 0)
        {
            if (self->remote_endpoint_out)
                *self->remote_endpoint_out = self->target_endpoint;
            if (self->local_endpoint_out && self->fd >= 0)
            {
                sockaddr_storage local{};
                socklen_t len = sizeof(local);
                if (::getsockname(self->fd,
                        reinterpret_cast<sockaddr*>(&local), &len) == 0)
                    *self->local_endpoint_out = sockaddr_to_endpoint(local);
            }
        }

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

/** Submit an `io_uring_op` whose `prep_func` is set.

    Wakes the leader (so it releases `ring_mutex_` if blocked in
    `submit_and_wait_timeout`), then acquires the ring mutex, prepares
    the SQE, and releases. The leader's next kernel wait submits the
    SQE to the kernel. Mirrors Boost.Asio's io_uring submission path.

    On SQ-ring exhaustion, flushes pending submissions and retries
    once. If the SQ stays full, surfaces `EAGAIN` on `*op->ec_out` and
    queues the op as completed so its handler dispatches on the next
    `do_one` cycle.

    @pre `op->prep_func != nullptr`.

    @par Exception Safety
    Nothrow.
*/
inline void
io_uring_submit_op(io_uring_scheduler& sched, io_uring_op* op) noexcept
{
    sched.lazy_init_ring();

    {
        typename io_uring_scheduler::lock_type ring_lock(sched.ring_mutex());

        ::io_uring_sqe* sqe = ::io_uring_get_sqe(sched.ring());
        if (!sqe)
        {
            // SQ ring full — flush to kernel and retry once.
            ::io_uring_submit(sched.ring());
            sqe = ::io_uring_get_sqe(sched.ring());
        }

        if (sqe)
        {
            op->prep_func(op, sqe);
            ::io_uring_sqe_set_data(sqe, op);
            // Release pairs with the acquire in io_uring_op::request_cancel:
            // a stop_token firing after we release the mutex will see
            // sqe_set==true and submit a cancel-by-user_data SQE.
            op->sqe_set.store(true, std::memory_order_release);
        }
        else
        {
            // SQ stayed full after one flush — synchronous failure path.
            // Surface EAGAIN and queue the op as completed so do_one
            // dispatches the handler. The caller's work_started() already
            // counted this op.
            if (op->ec_out)
                *op->ec_out = make_err(EAGAIN);
            typename io_uring_scheduler::lock_type lock(sched.dispatch_mutex());
            sched.push_completed_locked(op);
            return;
        }
    }

    // Wake the leader AFTER releasing ring_mutex_ so the leader's next
    // do_one iteration sees the SQE we just queued in user-space SQ.
    // If we waked before the mutex (or even held the mutex during the
    // wake), there's a race where the leader's Phase 1 io_uring_submit
    // could run BEFORE we prep the SQE — the leader would see an empty
    // SQ and re-enter wait_cqe with no new ops to monitor, leaving the
    // op stranded until the next organic wake.
    sched.interrupt_reactor();
}

/** Non-blocking connect for Unix domain sockets via `IORING_OP_CONNECT`.

    Like `uring_connect_op` but stores `local_endpoint` for the target
    and out-pointers, since `sockaddr_to_local_endpoint` returns
    `local_endpoint`, not `endpoint`.
*/
struct uring_local_connect_op : io_uring_op
{
    sockaddr_storage  addr{};
    socklen_t         addrlen             = 0;
    int               fd                  = -1;
    corosio::local_endpoint    target_endpoint{};
    corosio::local_endpoint*   remote_endpoint_out = nullptr;
    corosio::local_endpoint*   local_endpoint_out  = nullptr;

    uring_local_connect_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep)
    {}

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_local_connect_op*>(base);
        ::io_uring_prep_connect(
            sqe, self->fd,
            reinterpret_cast<sockaddr const*>(&self->addr),
            self->addrlen);
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags,
        op_queue& local) noexcept
    {
        auto* self      = static_cast<uring_local_connect_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_local_connect_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            auto h = self->h;
            delete self;
            if (h) h.destroy();
            return;
        }

        uring_set_result(self, false, false);

        // Write endpoints only on success.
        if (self->res >= 0)
        {
            if (self->remote_endpoint_out)
                *self->remote_endpoint_out = self->target_endpoint;
            if (self->local_endpoint_out && self->fd >= 0)
            {
                sockaddr_storage local{};
                socklen_t len = sizeof(local);
                if (::getsockname(self->fd,
                        reinterpret_cast<sockaddr*>(&local), &len) == 0)
                    *self->local_endpoint_out =
                        sockaddr_to_local_endpoint(local, len);
            }
        }

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SOCKET_OPS_HPP
