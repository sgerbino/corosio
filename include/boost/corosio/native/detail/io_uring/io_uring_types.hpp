//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_TYPES_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_TYPES_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

#include <boost/corosio/native/detail/io_uring/io_uring_buffer.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_scheduler.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_socket_ops.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <memory>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace boost::corosio::detail {

class io_uring_tcp_service;  // defined in Task 13

/** TCP socket implementation for io_uring.

    Implements `tcp_socket::implementation` using a proactor model:
    read, write, and connect operations are submitted to the kernel
    via `io_uring_submit_op` and complete through the ring's CQE path.

    The object is always owned by a `shared_ptr` managed by the service.
    In-flight ops hold an additional `shared_ptr` copy (`impl_ptr`) so
    the kernel's user-data pointer remains valid until the CQE arrives.

    @par Thread Safety
    Distinct objects: Safe.
    Shared objects: Unsafe. A socket must not have two operations of
    the same type in flight simultaneously.
*/
class BOOST_COROSIO_DECL io_uring_tcp_socket final
    : public tcp_socket::implementation
    , public std::enable_shared_from_this<io_uring_tcp_socket>
{
    friend io_uring_tcp_service;

    int                   fd_   = -1;
    io_uring_scheduler*   sched_ = nullptr;  // set by service at construction
    io_uring_tcp_service* svc_   = nullptr;

    endpoint local_endpoint_;
    endpoint remote_endpoint_;

public:
    /** Construct with service and scheduler references.

        Both refs must outlive this socket.  `sched_` and `svc_` are
        intentionally separate so service subclasses can pass a
        different scheduler if needed.

        @param svc   The owning service (Task 13).
        @param sched The io_uring scheduler owned by the context.
    */
    explicit io_uring_tcp_socket(
        io_uring_tcp_service& svc,
        io_uring_scheduler&   sched) noexcept
        : sched_(&sched)
        , svc_(&svc)
    {}

    ~io_uring_tcp_socket() override
    {
        if (fd_ >= 0)
            ::close(fd_);
    }

    // ----------------------------------------------------------------
    // io_stream::implementation
    // ----------------------------------------------------------------

    std::coroutine_handle<> read_some(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buffers,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes) override
    {
        auto* op = new uring_read_op();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->impl_ptr  = shared_from_this();

        // Unroll buffer sequence into op's iovec array (is_read already
        // set to true in uring_read_op constructor).
        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));
        op->empty_buffer = (op->iovec_count == 0);

        op->start(token);
        sched_->work_started();

        if (op->empty_buffer)
        {
            // Zero-length read: complete immediately with res=0.
            // push_completed_locked requires the dispatch lock.
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op);
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op, [op](::io_uring_sqe* sqe) {
            ::io_uring_prep_readv(sqe, op->fd, op->iovecs, op->iovec_count, 0);
        });
        return std::noop_coroutine();
    }

    std::coroutine_handle<> write_some(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buffers,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes) override
    {
        auto* op = new uring_write_op();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->impl_ptr  = shared_from_this();

        capy::mutable_buffer buf{};
        std::size_t count = buffers.copy_to(&buf, 1);
        op->empty_buffer  = (count == 0);

        if (!op->empty_buffer)
        {
            op->iov.iov_base = buf.data();
            op->iov.iov_len  = buf.size();
            op->msg.msg_iov  = &op->iov;
            op->msg.msg_iovlen = 1;
        }

        op->start(token);
        sched_->work_started();

        if (op->empty_buffer)
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op);
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op, [op](::io_uring_sqe* sqe) {
            ::io_uring_prep_sendmsg(sqe, op->fd, &op->msg, MSG_NOSIGNAL);
        });
        return std::noop_coroutine();
    }

    // ----------------------------------------------------------------
    // tcp_socket::implementation
    // ----------------------------------------------------------------

    std::coroutine_handle<> connect(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        endpoint                ep,
        std::stop_token         token,
        std::error_code*        ec) override
    {
        auto* op = new uring_connect_op();
        op->h        = h;
        op->ex       = ex;
        op->ec_out   = ec;
        op->fd       = fd_;
        op->impl_ptr = shared_from_this();
        op->addrlen  = endpoint_to_sockaddr(ep, op->addr);

        // Store for endpoint caching on success (do_handler doesn't have
        // access to `ep`, so we rely on post-connect getsockname in the
        // service's open_socket path — endpoint set here for the remote side).
        remote_endpoint_ = ep;

        op->start(token);
        sched_->work_started();

        io_uring_submit_op(*sched_, op, [op](::io_uring_sqe* sqe) {
            ::io_uring_prep_connect(
                sqe, op->fd,
                reinterpret_cast<sockaddr const*>(&op->addr),
                op->addrlen);
        });
        return std::noop_coroutine();
    }

    std::error_code shutdown(tcp_socket::shutdown_type what) noexcept override
    {
        if (::shutdown(fd_, static_cast<int>(what)) != 0)
            return make_err(errno);
        return {};
    }

    native_handle_type native_handle() const noexcept override
    {
        return fd_;
    }

    void cancel() noexcept override
    {
        // TODO(task14): submit cancel-by-fd via io_uring_prep_cancel_fd
    }

    std::error_code set_option(
        int         level,
        int         optname,
        void const* data,
        std::size_t size) noexcept override
    {
        if (::setsockopt(
                fd_, level, optname,
                reinterpret_cast<char const*>(data),
                static_cast<socklen_t>(size)) != 0)
            return make_err(errno);
        return {};
    }

    std::error_code get_option(
        int         level,
        int         optname,
        void*       data,
        std::size_t* size) const noexcept override
    {
        socklen_t len = static_cast<socklen_t>(*size);
        if (::getsockopt(fd_, level, optname,
                reinterpret_cast<char*>(data), &len) != 0)
            return make_err(errno);
        *size = static_cast<std::size_t>(len);
        return {};
    }

    endpoint local_endpoint() const noexcept override
    {
        return local_endpoint_;
    }

    endpoint remote_endpoint() const noexcept override
    {
        return remote_endpoint_;
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_TYPES_HPP
