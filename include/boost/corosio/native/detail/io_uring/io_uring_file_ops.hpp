//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_FILE_OPS_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_FILE_OPS_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_socket_ops.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>

#include <cstdint>
#include <sys/uio.h>

namespace boost::corosio::detail {

/** Scatter-gather file read via `IORING_OP_READV`.

    Stream files pass `offset == -1` so the kernel uses (and updates)
    the fd's `f_pos`, matching POSIX `read(2)` semantics. Random-
    access files pass an explicit caller-supplied offset.

    @par Handler dispatch
    `do_cqe` captures `res`/`cqe_flags` and queues self into `local`;
    `do_handler` runs from the scheduler queue and resumes the
    coroutine.
*/
struct uring_file_read_op : io_uring_op
{
    iovec        iovecs[io_uring_max_iov];
    int          iovec_count = 0;
    int          fd          = -1;
    std::int64_t offset      = -1;  // -1 means kernel f_pos

    uring_file_read_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep)
    {
        is_read = true;
    }

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_file_read_op*>(base);
        ::io_uring_prep_readv(
            sqe, self->fd, self->iovecs, self->iovec_count,
            static_cast<__u64>(self->offset));
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags,
        op_queue& local) noexcept
    {
        auto* self      = static_cast<uring_file_read_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_file_read_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            auto h = self->h;
            delete self;
            if (h) h.destroy();
            return;
        }

        uring_set_result(self, /*is_read=*/true, self->empty_buffer);

        if (self->bytes_out)
            *self->bytes_out =
                self->res >= 0 ? static_cast<std::size_t>(self->res) : 0u;

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

/** Scatter-gather file write via `IORING_OP_WRITEV`.

    Stream files pass `offset == -1` (kernel f_pos); random-access
    files pass an explicit caller-supplied offset. Unlike socket
    writes, no `MSG_NOSIGNAL` is needed — files don't generate
    SIGPIPE on closed peers.
*/
struct uring_file_write_op : io_uring_op
{
    iovec        iovecs[io_uring_max_iov];
    int          iovec_count = 0;
    int          fd          = -1;
    std::int64_t offset      = -1;

    uring_file_write_op() noexcept
        : io_uring_op(&do_handler, &do_cqe, &do_prep)
    {}

    static void do_prep(io_uring_op* base, ::io_uring_sqe* sqe) noexcept
    {
        auto* self = static_cast<uring_file_write_op*>(base);
        ::io_uring_prep_writev(
            sqe, self->fd, self->iovecs, self->iovec_count,
            static_cast<__u64>(self->offset));
    }

    static void do_cqe(
        io_uring_op* base, int res, unsigned flags,
        op_queue& local) noexcept
    {
        auto* self      = static_cast<uring_file_write_op*>(base);
        self->res       = res;
        self->cqe_flags = flags;
        local.push(self);
    }

    static void do_handler(
        void* owner, scheduler_op* base,
        std::uint32_t /*bytes*/, std::uint32_t /*error*/) noexcept
    {
        auto* self = static_cast<uring_file_write_op*>(base);
        self->stop_cb.reset();

        if (owner == nullptr)
        {
            auto h = self->h;
            delete self;
            if (h) h.destroy();
            return;
        }

        uring_set_result(self, /*is_read=*/false, self->empty_buffer);

        if (self->bytes_out)
            *self->bytes_out =
                self->res >= 0 ? static_cast<std::size_t>(self->res) : 0u;

        self->cont_op.cont.h = self->h;
        auto next = dispatch_coro(self->ex, self->cont_op.cont);
        delete self;
        next.resume();
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_FILE_OPS_HPP
