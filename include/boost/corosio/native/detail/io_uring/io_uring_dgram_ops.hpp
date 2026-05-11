//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_DGRAM_OPS_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_DGRAM_OPS_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

#include <liburing.h>

#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_socket_ops.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/capy/error.hpp>

#include <cstddef>
#include <cstdint>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace boost::corosio::detail {

/** Datagram send op — connected and unconnected.

    Always uses `IORING_OP_SENDMSG`. In connected mode, `dest_len == 0`
    and `msg.msg_name == nullptr`. In unconnected mode, `dest_storage`
    holds the destination and `msg.msg_name` points at it.

    `iovec[io_uring_max_iov]` for scatter/gather: a single datagram
    can be assembled from N user buffers via `msg.msg_iov`.
*/
struct uring_dgram_send_op : io_uring_op
{
    iovec            iovecs[io_uring_max_iov];
    int              iovec_count = 0;
    msghdr           msg{};
    sockaddr_storage dest_storage{};
    socklen_t        dest_len  = 0;
    int              fd        = -1;
    int              msg_flags = 0;

    uring_dgram_send_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep) {}

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_dgram_send_op*>(base);
        ::io_uring_prep_sendmsg(
            sqe, self->fd, &self->msg,
            self->msg_flags | MSG_NOSIGNAL);
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags, op_queue& local) noexcept
    {
        auto* self = static_cast<uring_dgram_send_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_dgram_send_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            delete self;
            return;
        }

        if (self->ec_out)
        {
            if (self->cancelled.load(std::memory_order_acquire))
                *self->ec_out = capy::error::canceled;
            else if (self->res < 0)
                *self->ec_out = make_err(-self->res);
            else
                *self->ec_out = {};
        }
        if (self->bytes_out)
            *self->bytes_out = (self->res >= 0)
                ? static_cast<std::size_t>(self->res) : 0;

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

/** Datagram receive op — connected and unconnected.

    Always uses `IORING_OP_RECVMSG`. In connected mode `msg.msg_name`
    is null. In unconnected mode `msg.msg_name` points at
    `source_storage` and the kernel writes the source address there.

    `res == 0` is success (zero-byte datagrams are valid), NOT EOF.

    The `source_writer` callback lets the concrete socket type
    translate `sockaddr_storage` into `endpoint*` or `local_endpoint*`
    without the op needing to know which family it is.
*/
struct uring_dgram_recv_op : io_uring_op
{
    iovec            iovecs[io_uring_max_iov];
    int              iovec_count = 0;
    msghdr           msg{};
    sockaddr_storage source_storage{};
    socklen_t        source_len = 0;
    int              fd         = -1;
    int              msg_flags  = 0;

    /// Type-erased translator: writes source_storage into the user's
    /// endpoint output via concrete-class-specific conversion.
    void* source_writer_ctx = nullptr;
    void (*source_writer)(
        void*, sockaddr_storage const&, socklen_t) noexcept = nullptr;

    uring_dgram_recv_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep) {}

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_dgram_recv_op*>(base);
        ::io_uring_prep_recvmsg(
            sqe, self->fd, &self->msg, self->msg_flags);
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags, op_queue& local) noexcept
    {
        auto* self = static_cast<uring_dgram_recv_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        // recvmsg writes the actual source addrlen back into msg.msg_namelen.
        self->source_len = self->msg.msg_namelen;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_dgram_recv_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            delete self;
            return;
        }

        if (self->ec_out)
        {
            if (self->cancelled.load(std::memory_order_acquire))
                *self->ec_out = capy::error::canceled;
            else if (self->res < 0)
                *self->ec_out = make_err(-self->res);
            else
                *self->ec_out = {};   // zero-byte datagram is success, not EOF
        }
        if (self->bytes_out)
            *self->bytes_out = (self->res >= 0)
                ? static_cast<std::size_t>(self->res) : 0;

        // Translate source storage into user's endpoint output (only on
        // success and only when the concrete socket type asked for it).
        if (self->source_writer && self->res >= 0)
            self->source_writer(self->source_writer_ctx,
                self->source_storage, self->source_len);

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_DGRAM_OPS_HPP
