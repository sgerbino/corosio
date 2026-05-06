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

#include <boost/corosio/detail/intrusive.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_acceptor_ops.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_buffer.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_dgram_ops.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_scheduler.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_multishot_acceptor.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_socket_ops.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/detail/local_datagram_service.hpp>
#include <boost/corosio/detail/local_stream_acceptor_service.hpp>
#include <boost/corosio/detail/local_stream_service.hpp>
#include <boost/corosio/detail/tcp_acceptor_service.hpp>
#include <boost/corosio/detail/tcp_service.hpp>
#include <boost/corosio/detail/udp_service.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/local_datagram_socket.hpp>
#include <boost/corosio/local_stream_acceptor.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/udp_socket.hpp>

#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace boost::corosio::detail {

class io_uring_tcp_service;
class io_uring_tcp_acceptor_service;  // Task 18
class io_uring_local_stream_service;
class io_uring_local_stream_acceptor_service;
class io_uring_udp_service;
class io_uring_local_datagram_service;

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

    int                   fd_     = -1;
    int                   family_ = AF_UNSPEC;  // cached at open_socket
    io_uring_scheduler*   sched_  = nullptr;
    io_uring_tcp_service* svc_    = nullptr;

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
        op->sched_    = sched_;
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

        // If stop was already requested before start(), the canceller fired
        // inline inside start(). No SQE was in flight to cancel, so bypass
        // the kernel and complete immediately as cancelled.
        if (op->empty_buffer ||
            op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
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
        op->sched_    = sched_;
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

        // Pre-cancelled (stop was requested before start()): bypass the
        // kernel and complete immediately as cancelled.
        if (op->empty_buffer ||
            op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
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
        op->sched_              = sched_;
        op->impl_ptr            = shared_from_this();
        // Use the family-aware overload so IPv4 endpoints are mapped to
        // ::ffff:x.x.x.x when the socket is AF_INET6 (dual-stack
        // connect). family_ was cached at open_socket time, avoiding
        // a per-connect getsockname syscall.
        op->addrlen             = to_sockaddr(ep, family_, op->addr);
        op->target_endpoint     = ep;
        op->remote_endpoint_out = &remote_endpoint_;
        op->local_endpoint_out  = &local_endpoint_;

        // start() may throw (stop_callback ctor allocates); unique_ptr
        // cleans up if it does.
        op->start(token);
        sched_->work_started();

        // Pre-cancelled (stop was requested before start()): bypass the
        // kernel and complete immediately as cancelled.
        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
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
        if (fd_ >= 0)
            sched_->submit_cancel_by_fd(fd_);
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
            // Cancel pending SQEs before closing. The cancel SQE must
            // be submitted to the kernel while the fd is still open;
            // otherwise IORING_ASYNC_CANCEL_FD resolves to the wrong
            // file if the fd number is immediately recycled.
            sched_->cancel_and_flush(sock->fd_);
            ::close(sock->fd_);
            sock->fd_              = -1;
            sock->local_endpoint_  = endpoint{};
            sock->remote_endpoint_ = endpoint{};
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
        if (sock.fd_ >= 0)
        {
            sched_->submit_cancel_by_fd(sock.fd_);
            ::close(sock.fd_);
        }
        sock.fd_     = fd;
        sock.family_ = family;
        // Mirror epoll/select: IPv6 sockets default to v6-only so they
        // behave consistently across platforms regardless of the kernel
        // default for /proc/sys/net/ipv6/bindv6only.
        if (family == AF_INET6)
        {
            int one = 1;
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        }
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

/** TCP acceptor implementation for io_uring.

    Inherits the multishot machinery (parked-fd queue, waiter queue,
    CQE drain on destruction) from `io_uring_multishot_acceptor_base`.
    This class adds only the `accept()` override (matching
    `tcp_acceptor::implementation`'s exact signature) and the
    `adopt_thunk` static that wraps an accepted fd via
    `io_uring_tcp_service::adopt_fd`.
*/
class BOOST_COROSIO_DECL io_uring_tcp_acceptor final
    : public io_uring_multishot_acceptor_base<
          io_uring_tcp_acceptor,
          tcp_acceptor::implementation,
          endpoint,
          io_uring_tcp_service>
{
    friend io_uring_tcp_acceptor_service;

    using base_type = io_uring_multishot_acceptor_base<
        io_uring_tcp_acceptor,
        tcp_acceptor::implementation,
        endpoint,
        io_uring_tcp_service>;

public:
    explicit io_uring_tcp_acceptor(
        io_uring_tcp_acceptor_service&,
        io_uring_scheduler&   sched,
        io_uring_tcp_service& peer_svc) noexcept
        : base_type(sched, peer_svc)
    {}

    std::coroutine_handle<> accept(
        std::coroutine_handle<>     h,
        capy::executor_ref          ex,
        std::stop_token             token,
        std::error_code*            ec,
        io_object::implementation** impl_out) override
    {
        base_type::dispatch_or_queue(h, ex, std::move(token), ec, impl_out);
        return std::noop_coroutine();
    }

    static io_object::implementation* adopt_thunk(
        void* peer_service, int fd,
        sockaddr_storage const& peer, socklen_t /*peer_len*/) noexcept
    {
        auto* svc = static_cast<io_uring_tcp_service*>(peer_service);
        return svc->adopt_fd(fd, sockaddr_to_endpoint(peer));
    }
};

/** TCP acceptor service for io_uring.

    Owns all `io_uring_tcp_acceptor` implementations for an `io_context`.
    Satisfies the `tcp_acceptor_service` interface so the generic
    `tcp_acceptor` front-end can call `open_acceptor_socket`,
    `bind_acceptor`, and `listen_acceptor` transparently.

    Acceptor impls are reference-counted inside the service map; raw
    pointers returned from `construct()` remain valid until `destroy()`
    or `shutdown()` is called.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_tcp_acceptor_service final
    : public tcp_acceptor_service
{
public:
    /// Identifies this service for `execution_context` lookup.
    using key_type = tcp_acceptor_service;

    /** Construct the TCP acceptor service.

        @param ctx The owning execution context. Both the io_uring scheduler
            and the TCP socket service must already be registered.
    */
    explicit io_uring_tcp_acceptor_service(capy::execution_context& ctx)
        : sched_(&ctx.use_service<io_uring_scheduler>())
        , peer_svc_(&ctx.use_service<io_uring_tcp_service>())
    {}

    void shutdown() override
    {
        std::vector<std::shared_ptr<io_uring_tcp_acceptor>> live;
        {
            std::lock_guard lk(mutex_);
            live.reserve(impls_.size());
            for (auto& [_, p] : impls_)
                live.push_back(p);
        }
        // Cancel without the lock held to avoid inversion if cancel()
        // re-enters the service.
        for (auto& p : live)
            p->cancel();
    }

    io_object::implementation* construct() override
    {
        auto p   = std::make_shared<io_uring_tcp_acceptor>(
            *this, *sched_, *peer_svc_);
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
        impls_.erase(static_cast<io_uring_tcp_acceptor*>(p));
    }

    // Close the fd eagerly when tcp_acceptor::close() is called, before
    // destroy() drops the shared_ptr and the destructor runs.
    void close(io_object::handle& h) override
    {
        auto* acc = static_cast<io_uring_tcp_acceptor*>(h.get());
        if (acc && acc->fd_ >= 0)
        {
            // Flush the cancel SQE before closing the fd so the kernel
            // resolves the file from the fd number while it is still
            // valid. drain_waiters_only avoids submitting cancel-by-fd
            // a second time (cancel_and_flush already did it).
            sched_->cancel_and_flush(acc->fd_);
            acc->drain_waiters_only();
            ::close(acc->fd_);
            acc->fd_ = -1;

            // Break the multi_op_ -> impl_ptr (shared_ptr<this>) cycle
            // start_multishot established. The acceptor destructor's
            // drain_cqes_for(multi_op_.get()) is the safety net; here
            // we just drop the cycle so the impl can be released when
            // the user's last shared_ptr does.
            if (acc->multi_op_)
                acc->multi_op_->impl_ptr.reset();
        }
    }

    /** Create a non-blocking, close-on-exec socket for accepting.

        @param impl   The acceptor implementation to initialise.
        @param family Address family (e.g. `AF_INET`, `AF_INET6`).
        @param type   Socket type (e.g. `SOCK_STREAM`).
        @param protocol Protocol number (e.g. `IPPROTO_TCP`).
        @return Error code on failure, empty on success.
    */
    std::error_code open_acceptor_socket(
        tcp_acceptor::implementation& impl,
        int family,
        int type,
        int protocol) override
    {
        auto& acc = static_cast<io_uring_tcp_acceptor&>(impl);
        int fd = ::socket(
            family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if (fd < 0)
            return make_err(errno);
        if (acc.fd_ >= 0)
        {
            sched_->submit_cancel_by_fd(acc.fd_);
            ::close(acc.fd_);
        }
        acc.fd_ = fd;
        // Match epoll/select: IPv6 acceptors default to dual-stack
        // (v6-only=false) so they accept both IPv4 and IPv6 connections.
        if (family == AF_INET6)
        {
            int zero = 0;
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        }
        return {};
    }

    /** Bind an open acceptor and capture the local endpoint.

        @param impl The acceptor implementation to bind.
        @param ep   The local endpoint to bind to.
        @return Error code on failure, empty on success.
    */
    std::error_code bind_acceptor(
        tcp_acceptor::implementation& impl, endpoint ep) override
    {
        auto& acc = static_cast<io_uring_tcp_acceptor&>(impl);
        sockaddr_storage addr{};
        socklen_t len = endpoint_to_sockaddr(ep, addr);
        if (::bind(
                acc.fd_,
                reinterpret_cast<sockaddr*>(&addr), len) < 0)
            return make_err(errno);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(
                acc.fd_,
                reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            acc.local_endpoint_ = sockaddr_to_endpoint(local);
        return {};
    }

    /** Start listening and submit the multishot accept SQE.

        Calls `::listen(2)` then arms the io_uring multishot accept
        operation that delivers one CQE per accepted connection.

        @param impl    The acceptor implementation to listen on.
        @param backlog Maximum pending-connection queue length.
        @return Error code on failure, empty on success.
    */
    std::error_code listen_acceptor(
        tcp_acceptor::implementation& impl, int backlog) override
    {
        auto& acc = static_cast<io_uring_tcp_acceptor&>(impl);
        if (::listen(acc.fd_, backlog) < 0)
            return make_err(errno);
        acc.start_multishot();
        return {};
    }

    /// Return the scheduler used by acceptors created by this service.
    io_uring_scheduler& scheduler() noexcept { return *sched_; }

private:
    io_uring_scheduler*   sched_;
    io_uring_tcp_service* peer_svc_;
    std::mutex            mutex_;
    std::unordered_map<io_uring_tcp_acceptor*,
                       std::shared_ptr<io_uring_tcp_acceptor>> impls_;
};

/** Unix domain stream socket implementation for io_uring.

    Implements `local_stream_socket::implementation` using a proactor
    model: read, write, and connect operations are submitted to the
    kernel via `io_uring_submit_op` and complete through the ring's
    CQE path.

    The object is always owned by a `shared_ptr` managed by the service.
    In-flight ops hold an additional `shared_ptr` copy (`impl_ptr`) so
    the kernel's user-data pointer remains valid until the CQE arrives.

    @par Thread Safety
    Distinct objects: Safe.
    Shared objects: Unsafe. A socket must not have two operations of
    the same type in flight simultaneously.
*/
class BOOST_COROSIO_DECL io_uring_local_stream_socket final
    : public local_stream_socket::implementation
    , public std::enable_shared_from_this<io_uring_local_stream_socket>
{
    friend io_uring_local_stream_service;

    int                           fd_    = -1;
    io_uring_scheduler*           sched_ = nullptr;
    io_uring_local_stream_service* svc_  = nullptr;

    corosio::local_endpoint local_endpoint_;
    corosio::local_endpoint remote_endpoint_;

public:
    /** Construct with service and scheduler references.

        Both refs must outlive this socket.

        @param svc   The owning service.
        @param sched The io_uring scheduler owned by the context.
    */
    explicit io_uring_local_stream_socket(
        io_uring_local_stream_service& svc,
        io_uring_scheduler&            sched) noexcept
        : sched_(&sched)
        , svc_(&svc)
    {}

    ~io_uring_local_stream_socket() override
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
        op->sched_    = sched_;
        op->impl_ptr  = shared_from_this();

        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));
        op->empty_buffer = (op->iovec_count == 0);

        op->start(token);
        sched_->work_started();

        if (op->empty_buffer ||
            op->cancelled.load(std::memory_order_acquire))
        {
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
        op->sched_    = sched_;
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

        op->start(token);
        sched_->work_started();

        if (op->empty_buffer ||
            op->cancelled.load(std::memory_order_acquire))
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
    // local_stream_socket::implementation
    // ----------------------------------------------------------------

    std::coroutine_handle<> connect(
        std::coroutine_handle<>  h,
        capy::executor_ref       ex,
        corosio::local_endpoint  ep,
        std::stop_token          token,
        std::error_code*         ec) override
    {
        auto op_guard = std::make_unique<uring_local_connect_op>();
        auto* op = op_guard.get();
        op->h                   = h;
        op->ex                  = ex;
        op->ec_out              = ec;
        op->fd                  = fd_;
        op->sched_              = sched_;
        op->impl_ptr            = shared_from_this();
        op->addrlen             = to_sockaddr(ep, op->addr);
        op->target_endpoint     = ep;
        op->remote_endpoint_out = &remote_endpoint_;
        op->local_endpoint_out  = &local_endpoint_;

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    std::error_code shutdown(local_stream_socket::shutdown_type what) noexcept override
    {
        if (::shutdown(fd_, static_cast<int>(what)) != 0)
            return make_err(errno);
        return {};
    }

    native_handle_type native_handle() const noexcept override
    {
        return fd_;
    }

    native_handle_type release_socket() noexcept override
    {
        int fd = fd_;
        fd_ = -1;
        local_endpoint_  = corosio::local_endpoint{};
        remote_endpoint_ = corosio::local_endpoint{};
        return fd;
    }

    void cancel() noexcept override
    {
        if (fd_ >= 0)
            sched_->submit_cancel_by_fd(fd_);
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

    corosio::local_endpoint local_endpoint() const noexcept override
    {
        return local_endpoint_;
    }

    corosio::local_endpoint remote_endpoint() const noexcept override
    {
        return remote_endpoint_;
    }
};

/** Unix domain stream socket service for io_uring.

    Owns all `io_uring_local_stream_socket` implementations for an
    `io_context`. Satisfies the `local_stream_service` interface so the
    generic `local_stream_socket` front-end can call `open_socket` and
    `assign_socket` transparently.

    Socket impls are reference-counted inside the service map; raw
    pointers returned from `construct()` remain valid until `destroy()`
    or `shutdown()` is called.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_local_stream_service final
    : public local_stream_service
{
public:
    /// Identifies this service for `execution_context` lookup.
    using key_type = local_stream_service;

    /** Construct the local stream service.

        @param ctx The owning execution context. The io_uring scheduler
            must already be registered.
    */
    explicit io_uring_local_stream_service(capy::execution_context& ctx)
        : sched_(&ctx.use_service<io_uring_scheduler>())
    {}

    void shutdown() override
    {
        std::vector<std::shared_ptr<io_uring_local_stream_socket>> live;
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
        auto p   = std::make_shared<io_uring_local_stream_socket>(*this, *sched_);
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
        impls_.erase(static_cast<io_uring_local_stream_socket*>(p));
    }

    // Close the fd eagerly when local_stream_socket::close() is called,
    // before destroy() drops the shared_ptr and the destructor runs.
    void close(io_object::handle& h) override
    {
        auto* sock = static_cast<io_uring_local_stream_socket*>(h.get());
        if (sock && sock->fd_ >= 0)
        {
            // Cancel pending SQEs before closing. The cancel SQE must
            // be submitted to the kernel while the fd is still open;
            // otherwise IORING_ASYNC_CANCEL_FD resolves to the wrong
            // file if the fd number is immediately recycled.
            sched_->cancel_and_flush(sock->fd_);
            ::close(sock->fd_);
            sock->fd_              = -1;
            sock->local_endpoint_  = corosio::local_endpoint{};
            sock->remote_endpoint_ = corosio::local_endpoint{};
        }
    }

    /** Open an AF_UNIX stream socket and associate it with an impl.

        Creates a non-blocking, close-on-exec socket via `socket(2)`.
        `family` is always `AF_UNIX` for local stream sockets.

        @param impl     The socket implementation to initialise.
        @param family   Address family (`AF_UNIX`).
        @param type     Socket type (`SOCK_STREAM`).
        @param protocol Protocol number (typically 0).
        @return Error code on failure, empty on success.
    */
    std::error_code open_socket(
        local_stream_socket::implementation& impl,
        int family, int type, int protocol) override
    {
        auto& sock = static_cast<io_uring_local_stream_socket&>(impl);
        int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if (fd < 0)
            return make_err(errno);
        if (sock.fd_ >= 0)
        {
            sched_->submit_cancel_by_fd(sock.fd_);
            ::close(sock.fd_);
        }
        sock.fd_ = fd;
        return {};
    }

    /** Adopt a pre-created fd into an impl (e.g. from `socketpair`).

        Takes ownership of `fd` on success; the caller retains ownership
        on failure.

        @param impl The socket implementation to assign to.
        @param fd   A valid, open, non-blocking AF_UNIX stream fd.
        @return Error code on failure, empty on success.
    */
    std::error_code assign_socket(
        local_stream_socket::implementation& impl,
        native_handle_type fd) override
    {
        auto& sock = static_cast<io_uring_local_stream_socket&>(impl);
        if (sock.fd_ >= 0)
        {
            sched_->cancel_and_flush(sock.fd_);
            ::close(sock.fd_);
        }
        sock.fd_ = static_cast<int>(fd);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(sock.fd_,
                reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            sock.local_endpoint_ = sockaddr_to_local_endpoint(local, local_len);

        sockaddr_storage remote{};
        socklen_t remote_len = sizeof(remote);
        if (::getpeername(sock.fd_,
                reinterpret_cast<sockaddr*>(&remote), &remote_len) == 0)
            sock.remote_endpoint_ = sockaddr_to_local_endpoint(remote, remote_len);

        return {};
    }

    /** Wrap an already-accepted fd as a new socket impl.

        Called by the acceptor service after `accept(2)` returns a
        connected fd. Captures both endpoints via the provided peer
        address and a `getsockname` call.

        @param fd   Accepted file descriptor (must be non-blocking).
        @param peer Peer endpoint from `accept(2)`.
        @return Raw pointer to the registered impl.
    */
    io_uring_local_stream_socket* adopt_fd(
        int fd, corosio::local_endpoint const& peer)
    {
        auto p = std::make_shared<io_uring_local_stream_socket>(*this, *sched_);
        p->fd_              = fd;
        p->remote_endpoint_ = peer;

        sockaddr_storage local{};
        socklen_t len = sizeof(local);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) == 0)
            p->local_endpoint_ = sockaddr_to_local_endpoint(local, len);

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
    std::unordered_map<io_uring_local_stream_socket*,
                       std::shared_ptr<io_uring_local_stream_socket>> impls_;
};

/** Local-stream (Unix domain) acceptor for io_uring.

    Inherits all multishot machinery (parked-fd queue, waiter queue,
    CQE drain on destruction) from `io_uring_multishot_acceptor_base`.
    Adds only the `accept()` override, the `adopt_thunk` static that
    wraps an accepted fd via `io_uring_local_stream_service::adopt_fd`,
    and `release_socket()` (a pure virtual in
    `local_stream_acceptor::implementation` absent from the base).
*/
class BOOST_COROSIO_DECL io_uring_local_stream_acceptor final
    : public io_uring_multishot_acceptor_base<
          io_uring_local_stream_acceptor,
          local_stream_acceptor::implementation,
          corosio::local_endpoint,
          io_uring_local_stream_service>
{
    friend io_uring_local_stream_acceptor_service;

    using base_type = io_uring_multishot_acceptor_base<
        io_uring_local_stream_acceptor,
        local_stream_acceptor::implementation,
        corosio::local_endpoint,
        io_uring_local_stream_service>;

public:
    explicit io_uring_local_stream_acceptor(
        io_uring_local_stream_acceptor_service&,
        io_uring_scheduler&            sched,
        io_uring_local_stream_service& peer_svc) noexcept
        : base_type(sched, peer_svc)
    {}

    std::coroutine_handle<> accept(
        std::coroutine_handle<>     h,
        capy::executor_ref          ex,
        std::stop_token             token,
        std::error_code*            ec,
        io_object::implementation** impl_out) override
    {
        base_type::dispatch_or_queue(h, ex, std::move(token), ec, impl_out);
        return std::noop_coroutine();
    }

    // release_socket() is pure virtual in local_stream_acceptor::implementation
    // but not in tcp_acceptor::implementation, so the base does not cover it.
    native_handle_type release_socket() noexcept override
    {
        int fd = fd_;
        fd_ = -1;
        local_endpoint_ = corosio::local_endpoint{};
        return fd;
    }

    static io_object::implementation* adopt_thunk(
        void* peer_service, int fd,
        sockaddr_storage const& peer, socklen_t peer_len) noexcept
    {
        auto* svc = static_cast<io_uring_local_stream_service*>(peer_service);
        return svc->adopt_fd(fd, sockaddr_to_local_endpoint(peer, peer_len));
    }
};

/** Unix domain stream acceptor service for io_uring.

    Owns all `io_uring_local_stream_acceptor` implementations for an
    `io_context`. Satisfies the `local_stream_acceptor_service` interface
    so the generic `local_stream_acceptor` front-end can call
    `open_acceptor_socket`, `bind_acceptor`, and `listen_acceptor`
    transparently.

    Acceptor impls are reference-counted inside the service map; raw
    pointers returned from `construct()` remain valid until `destroy()`
    or `shutdown()` is called.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_local_stream_acceptor_service final
    : public local_stream_acceptor_service
{
public:
    /// Identifies this service for `execution_context` lookup.
    using key_type = local_stream_acceptor_service;

    /** Construct the local stream acceptor service.

        @param ctx The owning execution context. Both the io_uring scheduler
            and the local stream socket service must already be registered.
    */
    explicit io_uring_local_stream_acceptor_service(capy::execution_context& ctx)
        : sched_(&ctx.use_service<io_uring_scheduler>())
        , peer_svc_(&ctx.use_service<io_uring_local_stream_service>())
    {}

    void shutdown() override
    {
        std::vector<std::shared_ptr<io_uring_local_stream_acceptor>> live;
        {
            std::lock_guard lk(mutex_);
            live.reserve(impls_.size());
            for (auto& [_, p] : impls_)
                live.push_back(p);
        }
        // Cancel without the lock held to avoid inversion if cancel()
        // re-enters the service.
        for (auto& p : live)
            p->cancel();
    }

    io_object::implementation* construct() override
    {
        auto p   = std::make_shared<io_uring_local_stream_acceptor>(
            *this, *sched_, *peer_svc_);
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
        impls_.erase(static_cast<io_uring_local_stream_acceptor*>(p));
    }

    // Close the fd eagerly when local_stream_acceptor::close() is called,
    // before destroy() drops the shared_ptr and the destructor runs.
    void close(io_object::handle& h) override
    {
        auto* acc = static_cast<io_uring_local_stream_acceptor*>(h.get());
        if (acc && acc->fd_ >= 0)
        {
            // cancel_and_flush submits cancel-by-fd; drain_waiters_only
            // drains queued waiters without re-submitting it.
            sched_->cancel_and_flush(acc->fd_);
            acc->drain_waiters_only();
            ::close(acc->fd_);
            acc->fd_ = -1;

            // Break the multi_op_ -> impl_ptr (shared_ptr<this>) cycle
            // start_multishot established. See the symmetric comment
            // in io_uring_tcp_acceptor_service::close.
            if (acc->multi_op_)
                acc->multi_op_->impl_ptr.reset();
        }
    }

    /** Create a non-blocking, close-on-exec AF_UNIX socket for accepting.

        @param impl     The acceptor implementation to initialise.
        @param family   Address family (`AF_UNIX`).
        @param type     Socket type (`SOCK_STREAM`).
        @param protocol Protocol number (typically 0).
        @return Error code on failure, empty on success.
    */
    std::error_code open_acceptor_socket(
        local_stream_acceptor::implementation& impl,
        int family,
        int type,
        int protocol) override
    {
        auto& acc = static_cast<io_uring_local_stream_acceptor&>(impl);
        int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if (fd < 0)
            return make_err(errno);
        if (acc.fd_ >= 0)
        {
            sched_->submit_cancel_by_fd(acc.fd_);
            ::close(acc.fd_);
        }
        acc.fd_ = fd;
        return {};
    }

    /** Bind an open acceptor and capture the local endpoint.

        @param impl The acceptor implementation to bind.
        @param ep   The local endpoint (path) to bind to.
        @return Error code on failure, empty on success.
    */
    std::error_code bind_acceptor(
        local_stream_acceptor::implementation& impl,
        corosio::local_endpoint ep) override
    {
        auto& acc = static_cast<io_uring_local_stream_acceptor&>(impl);
        sockaddr_storage addr{};
        socklen_t len = endpoint_to_sockaddr(ep, addr);
        if (::bind(acc.fd_, reinterpret_cast<sockaddr*>(&addr), len) < 0)
            return make_err(errno);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(
                acc.fd_,
                reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            acc.local_endpoint_ = sockaddr_to_local_endpoint(local, local_len);
        return {};
    }

    /** Start listening and submit the multishot accept SQE.

        Calls `::listen(2)` then arms the io_uring multishot accept
        operation that delivers one CQE per accepted connection.

        @param impl    The acceptor implementation to listen on.
        @param backlog Maximum pending-connection queue length.
        @return Error code on failure, empty on success.
    */
    std::error_code listen_acceptor(
        local_stream_acceptor::implementation& impl,
        int backlog) override
    {
        auto& acc = static_cast<io_uring_local_stream_acceptor&>(impl);
        if (::listen(acc.fd_, backlog) < 0)
            return make_err(errno);
        acc.start_multishot();
        return {};
    }

    /// Return the scheduler used by acceptors created by this service.
    io_uring_scheduler& scheduler() noexcept { return *sched_; }

private:
    io_uring_scheduler*             sched_;
    io_uring_local_stream_service*  peer_svc_;
    std::mutex                      mutex_;
    std::unordered_map<io_uring_local_stream_acceptor*,
        std::shared_ptr<io_uring_local_stream_acceptor>> impls_;
};

/** UDP socket implementation for io_uring.

    Implements `udp_socket::implementation` using a proactor model:
    send_to, recv_from, send, recv, and connect operations are submitted
    to the kernel via `io_uring_submit_op` and complete through the ring's
    CQE path.

    The object is always owned by a `shared_ptr` managed by the service.
    In-flight ops hold an additional `shared_ptr` copy (`impl_ptr`) so
    the kernel's user-data pointer remains valid until the CQE arrives.

    @par Thread Safety
    Distinct objects: Safe.
    Shared objects: Unsafe. One send and one recv may be in flight
    simultaneously, but two sends or two recvs must not overlap.
*/
class BOOST_COROSIO_DECL io_uring_udp_socket final
    : public udp_socket::implementation
    , public std::enable_shared_from_this<io_uring_udp_socket>
{
    friend io_uring_udp_service;

    int                    fd_     = -1;
    int                    family_ = AF_UNSPEC;  // cached at open_socket
    io_uring_scheduler*    sched_  = nullptr;
    io_uring_udp_service*  svc_    = nullptr;

    corosio::endpoint local_endpoint_;
    corosio::endpoint remote_endpoint_;

public:
    /** Construct with service and scheduler references.

        Both refs must outlive this socket.

        @param svc   The owning service.
        @param sched The io_uring scheduler owned by the context.
    */
    explicit io_uring_udp_socket(
        io_uring_udp_service& svc,
        io_uring_scheduler&   sched) noexcept
        : sched_(&sched)
        , svc_(&svc)
    {}

    ~io_uring_udp_socket() override
    {
        if (fd_ >= 0)
            ::close(fd_);
    }

    // ----------------------------------------------------------------
    // udp_socket::implementation
    // ----------------------------------------------------------------

    std::coroutine_handle<> send_to(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buf,
        endpoint                dest,
        int                     flags,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes_out) override
    {
        sockaddr_storage addr{};
        socklen_t len = endpoint_to_sockaddr(dest, addr);
        return submit_send(h, ex, buf, len, addr, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> recv_from(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buf,
        endpoint*               source,
        int                     flags,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes_out) override
    {
        return submit_recv(h, ex, buf, source != nullptr, source, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> send(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buf,
        int                     flags,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes_out) override
    {
        sockaddr_storage empty{};
        return submit_send(h, ex, buf, 0, empty, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> recv(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buf,
        int                     flags,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes_out) override
    {
        return submit_recv(h, ex, buf, false, nullptr, flags,
            std::move(token), ec, bytes_out);
    }

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
        op->sched_              = sched_;
        op->impl_ptr            = shared_from_this();
        // family_ cached at open_socket time (avoids per-connect
        // getsockname).
        op->addrlen             = to_sockaddr(ep, family_, op->addr);
        op->target_endpoint     = ep;
        op->remote_endpoint_out = &remote_endpoint_;
        op->local_endpoint_out  = &local_endpoint_;

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    native_handle_type native_handle() const noexcept override
    {
        return fd_;
    }

    void cancel() noexcept override
    {
        if (fd_ >= 0)
            sched_->submit_cancel_by_fd(fd_);
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
        int          level,
        int          optname,
        void*        data,
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

private:
    std::coroutine_handle<> submit_send(
        std::coroutine_handle<>        h,
        capy::executor_ref             ex,
        buffer_param                   buffers,
        socklen_t                      dest_len,
        sockaddr_storage const&        dest_storage,
        int                            flags,
        std::stop_token                token,
        std::error_code*               ec,
        std::size_t*                   bytes)
    {
        auto op_guard = std::make_unique<uring_dgram_send_op>();
        auto* op = op_guard.get();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->sched_    = sched_;
        op->impl_ptr  = shared_from_this();
        op->msg_flags = to_native_msg_flags(flags);

        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));

        op->msg.msg_iov    = op->iovecs;
        op->msg.msg_iovlen = static_cast<decltype(op->msg.msg_iovlen)>(
            op->iovec_count);
        if (dest_len > 0)
        {
            op->dest_storage = dest_storage;
            op->dest_len     = dest_len;
            op->msg.msg_name    = &op->dest_storage;
            op->msg.msg_namelen = dest_len;
        }
        else
        {
            op->msg.msg_name    = nullptr;
            op->msg.msg_namelen = 0;
        }

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    std::coroutine_handle<> submit_recv(
        std::coroutine_handle<>  h,
        capy::executor_ref       ex,
        buffer_param             buffers,
        bool                     want_source,
        corosio::endpoint*       source_out,
        int                      flags,
        std::stop_token          token,
        std::error_code*         ec,
        std::size_t*             bytes)
    {
        auto op_guard = std::make_unique<uring_dgram_recv_op>();
        auto* op = op_guard.get();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->sched_    = sched_;
        op->impl_ptr  = shared_from_this();
        op->msg_flags = to_native_msg_flags(flags);

        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));

        // Zero-iovec recvmsg would block forever waiting for a datagram.
        // Complete immediately with 0 bytes, matching the reactor's behaviour.
        if (op->iovec_count == 0)
        {
            op->res = 0;
            op->start(token);
            sched_->work_started();
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        op->msg.msg_iov    = op->iovecs;
        op->msg.msg_iovlen = static_cast<decltype(op->msg.msg_iovlen)>(
            op->iovec_count);
        if (want_source)
        {
            op->msg.msg_name    = &op->source_storage;
            op->msg.msg_namelen = sizeof(op->source_storage);
        }
        else
        {
            op->msg.msg_name    = nullptr;
            op->msg.msg_namelen = 0;
        }

        op->source_writer_ctx = source_out;
        op->source_writer     = want_source ? &write_ip_source : nullptr;

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    static void write_ip_source(
        void* ctx, sockaddr_storage const& s, socklen_t /*len*/) noexcept
    {
        if (auto* out = static_cast<corosio::endpoint*>(ctx))
            *out = sockaddr_to_endpoint(s);
    }
};

/** UDP socket service for io_uring.

    Owns all `io_uring_udp_socket` implementations for an `io_context`.
    Satisfies the `udp_service` interface so the generic `udp_socket`
    front-end can call `open_datagram_socket` and `bind_datagram`
    transparently.

    Socket impls are reference-counted inside the service map; raw
    pointers returned from `construct()` remain valid until `destroy()`
    or `shutdown()` is called.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_udp_service final
    : public udp_service
{
public:
    /// Identifies this service for `execution_context` lookup.
    using key_type = udp_service;

    /** Construct the UDP service.

        @param ctx The owning execution context. The io_uring scheduler
            must already be registered.
    */
    explicit io_uring_udp_service(capy::execution_context& ctx)
        : sched_(&ctx.use_service<io_uring_scheduler>())
    {}

    void shutdown() override
    {
        std::vector<std::shared_ptr<io_uring_udp_socket>> live;
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
        auto p   = std::make_shared<io_uring_udp_socket>(*this, *sched_);
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
        impls_.erase(static_cast<io_uring_udp_socket*>(p));
    }

    // Close the fd eagerly when udp_socket::close() is called, before
    // destroy() drops the shared_ptr and the destructor runs.
    void close(io_object::handle& h) override
    {
        auto* sock = static_cast<io_uring_udp_socket*>(h.get());
        if (sock && sock->fd_ >= 0)
        {
            // Cancel pending SQEs before closing so the kernel resolves
            // the fd number while it is still valid.
            sched_->cancel_and_flush(sock->fd_);
            ::close(sock->fd_);
            sock->fd_              = -1;
            sock->local_endpoint_  = endpoint{};
            sock->remote_endpoint_ = endpoint{};
        }
    }

    /** Open a datagram socket and associate it with an impl.

        Creates a non-blocking, close-on-exec socket via `socket(2)`.

        @param impl     The socket implementation to initialise.
        @param family   Address family (e.g. `AF_INET`, `AF_INET6`).
        @param type     Socket type (`SOCK_DGRAM`).
        @param protocol Protocol number (`IPPROTO_UDP`).
        @return Error code on failure, empty on success.
    */
    std::error_code open_datagram_socket(
        udp_socket::implementation& impl,
        int family, int type, int protocol) override
    {
        auto& sock = static_cast<io_uring_udp_socket&>(impl);
        int fd = ::socket(
            family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if (fd < 0)
            return make_err(errno);
        if (sock.fd_ >= 0)
        {
            sched_->submit_cancel_by_fd(sock.fd_);
            ::close(sock.fd_);
        }
        sock.fd_     = fd;
        sock.family_ = family;
        if (family == AF_INET6)
        {
            int one = 1;
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        }
        return {};
    }

    /** Bind the socket and capture the local endpoint via `getsockname`.

        @param impl The socket implementation to bind.
        @param ep   The local endpoint to bind to.
        @return Error code on failure, empty on success.
    */
    std::error_code bind_datagram(
        udp_socket::implementation& impl, endpoint ep) override
    {
        auto& sock = static_cast<io_uring_udp_socket&>(impl);
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

    /// Return the scheduler used by sockets created by this service.
    io_uring_scheduler& scheduler() noexcept { return *sched_; }

private:
    io_uring_scheduler*  sched_;
    std::mutex           mutex_;
    std::unordered_map<io_uring_udp_socket*,
                       std::shared_ptr<io_uring_udp_socket>> impls_;
};

/** Unix domain datagram socket implementation for io_uring.

    Implements `local_datagram_socket::implementation` using a proactor
    model: send_to, recv_from, send, recv, and connect operations are
    submitted to the kernel via `io_uring_submit_op` and complete through
    the ring's CQE path.

    The object is always owned by a `shared_ptr` managed by the service.
    In-flight ops hold an additional `shared_ptr` copy (`impl_ptr`) so
    the kernel's user-data pointer remains valid until the CQE arrives.

    @par Thread Safety
    Distinct objects: Safe.
    Shared objects: Unsafe. One send and one recv may be in flight
    simultaneously, but two sends or two recvs must not overlap.
*/
class BOOST_COROSIO_DECL io_uring_local_datagram_socket final
    : public local_datagram_socket::implementation
    , public std::enable_shared_from_this<io_uring_local_datagram_socket>
{
    friend io_uring_local_datagram_service;

    int                              fd_    = -1;
    io_uring_scheduler*              sched_ = nullptr;
    io_uring_local_datagram_service* svc_   = nullptr;

    corosio::local_endpoint local_endpoint_;
    corosio::local_endpoint remote_endpoint_;

public:
    /** Construct with service and scheduler references.

        Both refs must outlive this socket.

        @param svc   The owning service.
        @param sched The io_uring scheduler owned by the context.
    */
    explicit io_uring_local_datagram_socket(
        io_uring_local_datagram_service& svc,
        io_uring_scheduler&              sched) noexcept
        : sched_(&sched)
        , svc_(&svc)
    {}

    ~io_uring_local_datagram_socket() override
    {
        if (fd_ >= 0)
            ::close(fd_);
    }

    // ----------------------------------------------------------------
    // local_datagram_socket::implementation
    // ----------------------------------------------------------------

    std::coroutine_handle<> send_to(
        std::coroutine_handle<>  h,
        capy::executor_ref       ex,
        buffer_param             buf,
        corosio::local_endpoint  dest,
        int                      flags,
        std::stop_token          token,
        std::error_code*         ec,
        std::size_t*             bytes_out) override
    {
        sockaddr_storage addr{};
        socklen_t len = endpoint_to_sockaddr(dest, addr);
        return submit_send(h, ex, buf, len, addr, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> recv_from(
        std::coroutine_handle<>    h,
        capy::executor_ref         ex,
        buffer_param               buf,
        corosio::local_endpoint*   source,
        int                        flags,
        std::stop_token            token,
        std::error_code*           ec,
        std::size_t*               bytes_out) override
    {
        return submit_recv(h, ex, buf, source != nullptr, source, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> send(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buf,
        int                     flags,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes_out) override
    {
        sockaddr_storage empty{};
        return submit_send(h, ex, buf, 0, empty, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> recv(
        std::coroutine_handle<> h,
        capy::executor_ref      ex,
        buffer_param            buf,
        int                     flags,
        std::stop_token         token,
        std::error_code*        ec,
        std::size_t*            bytes_out) override
    {
        return submit_recv(h, ex, buf, false, nullptr, flags,
            std::move(token), ec, bytes_out);
    }

    std::coroutine_handle<> connect(
        std::coroutine_handle<>  h,
        capy::executor_ref       ex,
        corosio::local_endpoint  ep,
        std::stop_token          token,
        std::error_code*         ec) override
    {
        auto op_guard = std::make_unique<uring_local_connect_op>();
        auto* op = op_guard.get();
        op->h                   = h;
        op->ex                  = ex;
        op->ec_out              = ec;
        op->fd                  = fd_;
        op->sched_              = sched_;
        op->impl_ptr            = shared_from_this();
        op->addrlen             = to_sockaddr(ep, op->addr);
        op->target_endpoint     = ep;
        op->remote_endpoint_out = &remote_endpoint_;
        op->local_endpoint_out  = &local_endpoint_;

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    std::error_code shutdown(
        local_datagram_socket::shutdown_type what) noexcept override
    {
        if (::shutdown(fd_, static_cast<int>(what)) != 0)
            return make_err(errno);
        return {};
    }

    native_handle_type native_handle() const noexcept override
    {
        return fd_;
    }

    native_handle_type release_socket() noexcept override
    {
        int fd = fd_;
        fd_ = -1;
        local_endpoint_  = corosio::local_endpoint{};
        remote_endpoint_ = corosio::local_endpoint{};
        return fd;
    }

    void cancel() noexcept override
    {
        if (fd_ >= 0)
            sched_->submit_cancel_by_fd(fd_);
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
        int          level,
        int          optname,
        void*        data,
        std::size_t* size) const noexcept override
    {
        socklen_t len = static_cast<socklen_t>(*size);
        if (::getsockopt(fd_, level, optname,
                reinterpret_cast<char*>(data), &len) != 0)
            return make_err(errno);
        *size = static_cast<std::size_t>(len);
        return {};
    }

    corosio::local_endpoint local_endpoint() const noexcept override
    {
        return local_endpoint_;
    }

    corosio::local_endpoint remote_endpoint() const noexcept override
    {
        return remote_endpoint_;
    }

    std::error_code bind(corosio::local_endpoint ep) noexcept override
    {
        sockaddr_storage addr{};
        socklen_t len = endpoint_to_sockaddr(ep, addr);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), len) != 0)
            return make_err(errno);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(
                fd_,
                reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            local_endpoint_ = sockaddr_to_local_endpoint(local, local_len);
        return {};
    }

private:
    std::coroutine_handle<> submit_send(
        std::coroutine_handle<>        h,
        capy::executor_ref             ex,
        buffer_param                   buffers,
        socklen_t                      dest_len,
        sockaddr_storage const&        dest_storage,
        int                            flags,
        std::stop_token                token,
        std::error_code*               ec,
        std::size_t*                   bytes)
    {
        auto op_guard = std::make_unique<uring_dgram_send_op>();
        auto* op = op_guard.get();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->sched_    = sched_;
        op->impl_ptr  = shared_from_this();
        op->msg_flags = to_native_msg_flags(flags);

        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));

        op->msg.msg_iov    = op->iovecs;
        op->msg.msg_iovlen = static_cast<decltype(op->msg.msg_iovlen)>(
            op->iovec_count);
        if (dest_len > 0)
        {
            op->dest_storage = dest_storage;
            op->dest_len     = dest_len;
            op->msg.msg_name    = &op->dest_storage;
            op->msg.msg_namelen = dest_len;
        }
        else
        {
            op->msg.msg_name    = nullptr;
            op->msg.msg_namelen = 0;
        }

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    std::coroutine_handle<> submit_recv(
        std::coroutine_handle<>    h,
        capy::executor_ref         ex,
        buffer_param               buffers,
        bool                       want_source,
        corosio::local_endpoint*   source_out,
        int                        flags,
        std::stop_token            token,
        std::error_code*           ec,
        std::size_t*               bytes)
    {
        auto op_guard = std::make_unique<uring_dgram_recv_op>();
        auto* op = op_guard.get();
        op->h         = h;
        op->ex        = ex;
        op->ec_out    = ec;
        op->bytes_out = bytes;
        op->fd        = fd_;
        op->sched_    = sched_;
        op->impl_ptr  = shared_from_this();
        op->msg_flags = to_native_msg_flags(flags);

        op->iovec_count = static_cast<int>(
            buffers.copy_to(
                reinterpret_cast<capy::mutable_buffer*>(op->iovecs),
                io_uring_max_iov));

        // Zero-iovec recvmsg would block forever waiting for a datagram.
        // Complete immediately with 0 bytes, matching the reactor's behaviour.
        if (op->iovec_count == 0)
        {
            op->res = 0;
            op->start(token);
            sched_->work_started();
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        op->msg.msg_iov    = op->iovecs;
        op->msg.msg_iovlen = static_cast<decltype(op->msg.msg_iovlen)>(
            op->iovec_count);
        if (want_source)
        {
            op->msg.msg_name    = &op->source_storage;
            op->msg.msg_namelen = sizeof(op->source_storage);
        }
        else
        {
            op->msg.msg_name    = nullptr;
            op->msg.msg_namelen = 0;
        }

        op->source_writer_ctx = source_out;
        op->source_writer     = want_source ? &write_local_source : nullptr;

        op->start(token);
        sched_->work_started();

        if (op->cancelled.load(std::memory_order_acquire))
        {
            io_uring_scheduler::lock_type lock(sched_->dispatch_mutex());
            sched_->push_completed_locked(op_guard.release());
            return std::noop_coroutine();
        }

        io_uring_submit_op(*sched_, op_guard.release());
        return std::noop_coroutine();
    }

    static void write_local_source(
        void* ctx, sockaddr_storage const& s, socklen_t len) noexcept
    {
        if (auto* out = static_cast<corosio::local_endpoint*>(ctx))
            *out = sockaddr_to_local_endpoint(s, len);
    }
};

/** Unix domain datagram socket service for io_uring.

    Owns all `io_uring_local_datagram_socket` implementations for an
    `io_context`. Satisfies the `local_datagram_service` interface so the
    generic `local_datagram_socket` front-end can call `open_socket` and
    `bind_socket` transparently.

    Socket impls are reference-counted inside the service map; raw
    pointers returned from `construct()` remain valid until `destroy()`
    or `shutdown()` is called.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_local_datagram_service final
    : public local_datagram_service
{
public:
    /// Identifies this service for `execution_context` lookup.
    using key_type = local_datagram_service;

    /** Construct the local datagram service.

        @param ctx The owning execution context. The io_uring scheduler
            must already be registered.
    */
    explicit io_uring_local_datagram_service(capy::execution_context& ctx)
        : sched_(&ctx.use_service<io_uring_scheduler>())
    {}

    void shutdown() override
    {
        std::vector<std::shared_ptr<io_uring_local_datagram_socket>> live;
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
        auto p   = std::make_shared<io_uring_local_datagram_socket>(
            *this, *sched_);
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
        impls_.erase(static_cast<io_uring_local_datagram_socket*>(p));
    }

    // Close the fd eagerly when local_datagram_socket::close() is called,
    // before destroy() drops the shared_ptr and the destructor runs.
    void close(io_object::handle& h) override
    {
        auto* sock = static_cast<io_uring_local_datagram_socket*>(h.get());
        if (sock && sock->fd_ >= 0)
        {
            // Cancel pending SQEs before closing so the kernel resolves
            // the fd number while it is still valid.
            sched_->cancel_and_flush(sock->fd_);
            ::close(sock->fd_);
            sock->fd_              = -1;
            sock->local_endpoint_  = corosio::local_endpoint{};
            sock->remote_endpoint_ = corosio::local_endpoint{};
        }
    }

    /** Open an AF_UNIX datagram socket and associate it with an impl.

        Creates a non-blocking, close-on-exec socket via `socket(2)`.
        `family` is always `AF_UNIX` for local datagram sockets.

        @param impl     The socket implementation to initialise.
        @param family   Address family (`AF_UNIX`).
        @param type     Socket type (`SOCK_DGRAM`).
        @param protocol Protocol number (typically 0).
        @return Error code on failure, empty on success.
    */
    std::error_code open_socket(
        local_datagram_socket::implementation& impl,
        int family, int type, int protocol) override
    {
        auto& sock = static_cast<io_uring_local_datagram_socket&>(impl);
        int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if (fd < 0)
            return make_err(errno);
        if (sock.fd_ >= 0)
        {
            sched_->submit_cancel_by_fd(sock.fd_);
            ::close(sock.fd_);
        }
        sock.fd_ = fd;
        return {};
    }

    /** Adopt a pre-created fd into an impl (e.g. from `socketpair`).

        Takes ownership of `fd` on success; the caller retains ownership
        on failure.

        @param impl The socket implementation to assign to.
        @param fd   A valid, open, non-blocking AF_UNIX datagram fd.
        @return Error code on failure, empty on success.
    */
    std::error_code assign_socket(
        local_datagram_socket::implementation& impl,
        native_handle_type fd) override
    {
        auto& sock = static_cast<io_uring_local_datagram_socket&>(impl);
        if (sock.fd_ >= 0)
        {
            sched_->cancel_and_flush(sock.fd_);
            ::close(sock.fd_);
        }
        sock.fd_ = static_cast<int>(fd);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(sock.fd_,
                reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            sock.local_endpoint_ = sockaddr_to_local_endpoint(local, local_len);

        sockaddr_storage remote{};
        socklen_t remote_len = sizeof(remote);
        if (::getpeername(sock.fd_,
                reinterpret_cast<sockaddr*>(&remote), &remote_len) == 0)
            sock.remote_endpoint_ = sockaddr_to_local_endpoint(remote, remote_len);

        return {};
    }

    /** Bind the socket and capture the local endpoint via `getsockname`.

        @param impl The socket implementation to bind.
        @param ep   The local endpoint (path) to bind to.
        @return Error code on failure, empty on success.
    */
    std::error_code bind_socket(
        local_datagram_socket::implementation& impl,
        corosio::local_endpoint ep) override
    {
        auto& sock = static_cast<io_uring_local_datagram_socket&>(impl);
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
            sock.local_endpoint_ = sockaddr_to_local_endpoint(local, local_len);
        return {};
    }

    /// Return the scheduler used by sockets created by this service.
    io_uring_scheduler& scheduler() noexcept { return *sched_; }

private:
    io_uring_scheduler*  sched_;
    std::mutex           mutex_;
    std::unordered_map<io_uring_local_datagram_socket*,
                       std::shared_ptr<io_uring_local_datagram_socket>> impls_;
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_TYPES_HPP
