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
#include <boost/corosio/native/detail/io_uring/io_uring_buffer.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_scheduler.hpp>
#include <boost/corosio/native/detail/make_err.hpp>

#include <system_error>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace boost::corosio::detail {

/// Maximum scatter/gather segments per read op.
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
        : io_uring_op(&do_handler, &do_cqe)
    {
        is_read = true;
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

/** Write via `IORING_OP_SENDMSG` with `MSG_NOSIGNAL`.

    `MSG_NOSIGNAL` prevents `SIGPIPE` when the peer has closed the
    connection; the error is surfaced as `EPIPE` instead.
*/
struct uring_write_op : io_uring_op
{
    msghdr msg{};
    iovec  iov{};
    int    fd = -1;

    uring_write_op() noexcept
        : io_uring_op(&do_handler, &do_cqe)
    {}

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
*/
struct uring_connect_op : io_uring_op
{
    sockaddr_storage addr{};
    socklen_t        addrlen = 0;
    int              fd      = -1;

    uring_connect_op() noexcept
        : io_uring_op(&do_handler, &do_cqe)
    {}

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

        // Connect has no byte count; res < 0 is the error, 0 is success.
        if (self->ec_out)
        {
            if (self->cancelled.load(std::memory_order_acquire))
                *self->ec_out = capy::error::canceled;
            else if (self->res < 0)
                *self->ec_out = make_err(-self->res);
            else
                *self->ec_out = {};
        }

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

/** Acquire an SQE, fill it via `prep`, and link `op` as user_data.

    Serialises SQE acquisition under `sched.dispatch_mutex()`. On
    transient SQE-ring exhaustion, flushes pending submissions and
    retries once. If no SQE is available after the flush, surfaces
    `std::errc::resource_unavailable_try_again` on `*op->ec_out` and
    posts the op immediately (synchronous failure path — no CQE will
    arrive, but `do_one` still dispatches the handler).

    @par Exception Safety
    Nothrow.

    @param sched The io_uring scheduler owning the ring.
    @param op    The op whose `user_data` will be set in the SQE.
    @param prep  Callable `void(io_uring_sqe*)` that fills the SQE.
                 Called exactly once on success.
*/
template<class PrepFn>
void
io_uring_submit_op(
    io_uring_scheduler& sched, io_uring_op* op, PrepFn prep) noexcept
{
    typename io_uring_scheduler::lock_type lock(sched.dispatch_mutex());

    io_uring_sqe* sqe = ::io_uring_get_sqe(sched.ring());
    if (!sqe)
    {
        // SQ ring full — flush to kernel and retry once.
        ::io_uring_submit(sched.ring());
        sqe = ::io_uring_get_sqe(sched.ring());
    }

    if (!sqe)
    {
        if (op->ec_out)
            *op->ec_out = std::make_error_code(
                std::errc::resource_unavailable_try_again);
        // No CQE will arrive. Push under the lock we already hold without
        // incrementing outstanding_work_ — the caller's work_started()
        // already counted this op, matching the normal CQE dispatch path.
        sched.push_completed_locked(op);
        return;
    }

    prep(sqe);
    ::io_uring_sqe_set_data(sqe, op);
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SOCKET_OPS_HPP
