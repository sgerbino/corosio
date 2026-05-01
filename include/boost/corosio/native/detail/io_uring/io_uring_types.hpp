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
#include <boost/corosio/detail/tcp_service.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace boost::corosio::detail {

class io_uring_tcp_service;

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

    // TODO: populate after async_connect completes (post-Task 14 cancel-aware).
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
        auto op_guard = std::make_unique<uring_read_op>();
        auto* op = op_guard.get();
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

        // start() may throw (stop_callback ctor allocates); unique_ptr
        // cleans up if it does.
        op->start(token);
        sched_->work_started();

        if (op->empty_buffer)
        {
            // Zero-length read: complete immediately with res=0.
            // push_completed_locked requires the dispatch lock.
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release(), [op](::io_uring_sqe* sqe) {
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
        auto op_guard = std::make_unique<uring_write_op>();
        auto* op = op_guard.get();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->impl_ptr  = shared_from_this();

        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));
        op->empty_buffer = (op->iovec_count == 0);

        if (!op->empty_buffer)
        {
            op->msg.msg_iov    = op->iovecs;
            op->msg.msg_iovlen = static_cast<decltype(op->msg.msg_iovlen)>(
                op->iovec_count);
        }

        // start() may throw (stop_callback ctor allocates); unique_ptr
        // cleans up if it does.
        op->start(token);
        sched_->work_started();

        if (op->empty_buffer)
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release(), [op](::io_uring_sqe* sqe) {
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
        auto op_guard = std::make_unique<uring_connect_op>();
        auto* op = op_guard.get();
        op->h                   = h;
        op->ex                  = ex;
        op->ec_out              = ec;
        op->fd                  = fd_;
        op->impl_ptr            = shared_from_this();
        op->addrlen             = endpoint_to_sockaddr(ep, op->addr);
        op->target_endpoint     = ep;
        op->remote_endpoint_out = &remote_endpoint_;

        // start() may throw (stop_callback ctor allocates); unique_ptr
        // cleans up if it does.
        op->start(token);
        sched_->work_started();

        io_uring_submit_op(*sched_, op_guard.release(), [op](::io_uring_sqe* sqe) {
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

/** TCP socket service for io_uring.

    Owns all `io_uring_tcp_socket` implementations for an `io_context`.
    Satisfies the `tcp_service` interface so the generic `tcp_socket`
    front-end can call `open_socket` and `bind_socket` transparently.

    Socket impls are reference-counted inside the service map; raw
    pointers returned from `construct()` remain valid until `destroy()`
    or `shutdown()` is called.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_tcp_service final
    : public tcp_service
{
public:
    /// Identifies this service for `execution_context` lookup.
    using key_type = tcp_service;

    /** Construct the TCP service.

        @param ctx The owning execution context. The io_uring scheduler
            must already be registered.
    */
    explicit io_uring_tcp_service(capy::execution_context& ctx)
        : sched_(&ctx.use_service<io_uring_scheduler>())
    {}

    void shutdown() override
    {
        std::vector<std::shared_ptr<io_uring_tcp_socket>> live;
        {
            std::lock_guard lk(mutex_);
            live.reserve(impls_.size());
            for (auto& [_, p] : impls_)
                live.push_back(p);
        }
        // Cancel without the lock held to avoid inversion if cancel()
        // ever needs to re-enter the service.
        for (auto& p : live)
            p->cancel();
    }

    io_object::implementation* construct() override
    {
        auto p   = std::make_shared<io_uring_tcp_socket>(*this, *sched_);
        auto* raw = p.get();
        std::lock_guard lk(mutex_);
        impls_.emplace(raw, std::move(p));
        return raw;
    }

    void destroy(io_object::implementation* p) override
    {
        if (!p)
            return;
        std::lock_guard lk(mutex_);
        impls_.erase(static_cast<io_uring_tcp_socket*>(p));
    }

    // Close the fd eagerly when tcp_socket::close() is called, before
    // destroy() drops the shared_ptr and the destructor runs.
    void close(io_object::handle& h) override
    {
        auto* sock = static_cast<io_uring_tcp_socket*>(h.get());
        if (sock && sock->fd_ >= 0)
        {
            ::close(sock->fd_);
            sock->fd_ = -1;
        }
    }

    /** Open a socket fd and associate it with an impl.

        Creates a non-blocking, close-on-exec socket via `socket(2)`.

        @param impl   The socket implementation to initialise.
        @param family Address family (e.g. `AF_INET`, `AF_INET6`).
        @param type   Socket type (e.g. `SOCK_STREAM`).
        @param protocol Protocol number (e.g. `IPPROTO_TCP`).
        @return Error code on failure, empty on success.
    */
    std::error_code open_socket(
        tcp_socket::implementation& impl,
        int family, int type, int protocol) override
    {
        auto& sock = static_cast<io_uring_tcp_socket&>(impl);
        int fd = ::socket(
            family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if (fd < 0)
            return make_err(errno);
        // TODO(task14): cancel in-flight ops before re-opening; once cancel()
        // is wired (Task 14), this path must drain pending ops referencing
        // the old fd before close() to avoid dangling op pointers.
        if (sock.fd_ >= 0)
            ::close(sock.fd_);
        sock.fd_ = fd;
        return {};
    }

    /** Bind the socket and capture the local endpoint via `getsockname`.

        @param impl The socket implementation to bind.
        @param ep   The local endpoint to bind to.
        @return Error code on failure, empty on success.
    */
    std::error_code bind_socket(
        tcp_socket::implementation& impl, endpoint ep) override
    {
        auto& sock = static_cast<io_uring_tcp_socket&>(impl);
        sockaddr_storage addr{};
        socklen_t len = endpoint_to_sockaddr(ep, addr);
        if (::bind(
                sock.fd_,
                reinterpret_cast<sockaddr*>(&addr), len) < 0)
            return make_err(errno);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(
                sock.fd_,
                reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            sock.local_endpoint_ = sockaddr_to_endpoint(local);
        return {};
    }

    /** Wrap an already-accepted fd as a new socket impl.

        Called by the acceptor service (Task 17) after `accept(2)`
        returns a connected fd. Captures both endpoints via the provided
        peer address and a `getsockname` call.

        @param fd   Accepted file descriptor (must be non-blocking).
        @param peer Peer endpoint from `accept(2)`.
        @return Raw pointer to the registered impl.
    */
    io_uring_tcp_socket* adopt_fd(int fd, endpoint const& peer)
    {
        auto p = std::make_shared<io_uring_tcp_socket>(*this, *sched_);
        p->fd_              = fd;
        p->remote_endpoint_ = peer;

        sockaddr_storage local{};
        socklen_t len = sizeof(local);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) == 0)
            p->local_endpoint_ = sockaddr_to_endpoint(local);

        std::lock_guard lk(mutex_);
        auto* raw = p.get();
        impls_.emplace(raw, std::move(p));
        return raw;
    }

    /// Return the scheduler used by sockets created by this service.
    io_uring_scheduler& scheduler() noexcept { return *sched_; }

private:
    io_uring_scheduler*  sched_;
    std::mutex           mutex_;
    std::unordered_map<io_uring_tcp_socket*,
                       std::shared_ptr<io_uring_tcp_socket>> impls_;
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_TYPES_HPP
