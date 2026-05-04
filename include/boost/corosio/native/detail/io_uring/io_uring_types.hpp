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
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_scheduler.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_socket_ops.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/detail/tcp_acceptor_service.hpp>
#include <boost/corosio/detail/tcp_service.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace boost::corosio::detail {

class io_uring_tcp_service;
class io_uring_tcp_acceptor_service;  // Task 18

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
        op->sched_              = sched_;
        op->impl_ptr            = shared_from_this();
        // Use the family-aware overload so IPv4 endpoints are mapped to
        // ::ffff:x.x.x.x when the socket is AF_INET6 (dual-stack connect).
        op->addrlen             = to_sockaddr(ep, socket_family(fd_), op->addr);
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
        sock.fd_ = fd;
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

/** TCP acceptor implementation for the io_uring backend.

    Uses IORING_OP_ACCEPT_MULTI: a single SQE submitted at `listen()`
    produces a CQE per accepted connection. The kernel re-arms the
    op automatically. Accepts are surfaced via two queues:

    - `ready_fds_` — CQEs that arrived before any `async_accept`
      was issued (parked).
    - `waiters_` — `async_accept` calls that arrived before any
      multishot CQE.

    A CQE arriving with a waiter present pops the waiter and completes
    it. A CQE with no waiter parks the fd. An `async_accept` with a
    parked fd matches inline. Otherwise a waiter is queued.

    On cancel/close, both queues drain: parked fds are closed and
    waiters are completed with `operation_canceled`.
*/
class BOOST_COROSIO_DECL io_uring_tcp_acceptor final
    : public tcp_acceptor::implementation
    , public std::enable_shared_from_this<io_uring_tcp_acceptor>
{
    friend io_uring_tcp_acceptor_service;
    friend io_uring_tcp_service;

    // Parked node: kernel accepted but no waiter was queued yet.
    struct ready_fd_node : intrusive_list<ready_fd_node>::node
    {
        int              fd       = -1;
        sockaddr_storage peer{};
        socklen_t        peer_len = 0;
    };

    // Waiter node: user called async_accept with no ready fd yet.
    struct waiter_node : intrusive_list<waiter_node>::node
    {
        struct canceller
        {
            waiter_node* w;
            void operator()() const noexcept;
        };

        std::coroutine_handle<>                        h;
        capy::executor_ref                             ex;
        std::error_code*                               ec_out            = nullptr;
        io_object::implementation**                    impl_out          = nullptr;
        endpoint*                                      peer_endpoint_out = nullptr;
        io_uring_tcp_acceptor*                         owner             = nullptr;
        std::optional<std::stop_callback<canceller>>   stop_cb;
    };

    int                                    fd_           = -1;
    io_uring_scheduler*                    sched_        = nullptr;
    io_uring_tcp_acceptor_service*         svc_          = nullptr;
    io_uring_tcp_service*                  peer_service_ = nullptr;

    endpoint                               local_endpoint_{};

    std::mutex                             mutex_;
    intrusive_list<ready_fd_node>          ready_fds_;
    intrusive_list<waiter_node>            waiters_;
    std::unique_ptr<uring_multi_accept_op> multi_op_;
    bool                                   closing_ = false;

public:
    /** Construct with service and scheduler references.

        @param svc       The owning acceptor service (Task 18).
        @param sched     The io_uring scheduler.
        @param peer_svc  The TCP socket service for wrapping accepted fds.
    */
    explicit io_uring_tcp_acceptor(
        io_uring_tcp_acceptor_service& svc,
        io_uring_scheduler&            sched,
        io_uring_tcp_service&          peer_svc) noexcept
        : sched_(&sched)
        , svc_(&svc)
        , peer_service_(&peer_svc)
    {}

    ~io_uring_tcp_acceptor() override;

    // ----------------------------------------------------------------
    // tcp_acceptor::implementation
    // ----------------------------------------------------------------

    std::coroutine_handle<> accept(
        std::coroutine_handle<>      h,
        capy::executor_ref           ex,
        std::stop_token              token,
        std::error_code*             ec,
        io_object::implementation**  impl_out) override;

    endpoint local_endpoint() const noexcept override
    {
        return local_endpoint_;
    }

    bool is_open() const noexcept override
    {
        return fd_ >= 0;
    }

    void cancel() noexcept override;

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

    // ----------------------------------------------------------------
    // Internal — called by the acceptor service (Task 18)
    // ----------------------------------------------------------------

    /// Submit the multishot accept SQE. Called once after ::listen().
    void start_multishot();

private:
    static io_object::implementation* adopt_thunk(
        void*                    peer_service,
        int                      fd,
        sockaddr_storage const&  peer,
        socklen_t                peer_len) noexcept;

    void on_accept_cqe_impl(int new_fd, int err, bool more) noexcept;

    static void on_accept_cqe(
        void* self_ptr, int new_fd, int err, bool more) noexcept
    {
        static_cast<io_uring_tcp_acceptor*>(self_ptr)
            ->on_accept_cqe_impl(new_fd, err, more);
    }

    // Cancel a specific waiter (called from its stop_callback).
    void cancel_waiter(waiter_node* w) noexcept;
};

// ----------------------------------------------------------------
// waiter_node::canceller
// ----------------------------------------------------------------

inline void
io_uring_tcp_acceptor::waiter_node::canceller::operator()() const noexcept
{
    w->owner->cancel_waiter(w);
}

// ----------------------------------------------------------------
// io_uring_tcp_acceptor out-of-line definitions
// ----------------------------------------------------------------

inline
io_uring_tcp_acceptor::~io_uring_tcp_acceptor()
{
    {
        std::lock_guard lk(mutex_);
        closing_ = true;
    }
    if (fd_ >= 0)
    {
        sched_->submit_cancel_by_fd(fd_);
        // Drain parked fds — no waiter will consume them now.
        intrusive_list<ready_fd_node> drained;
        {
            std::lock_guard lk(mutex_);
            while (auto* r = ready_fds_.pop_front())
                drained.push_back(r);
        }
        while (auto* r = drained.pop_front())
        {
            ::close(r->fd);
            delete r;
        }
        ::close(fd_);
        fd_ = -1;
    }
}

inline void
io_uring_tcp_acceptor::start_multishot()
{
    multi_op_ = std::make_unique<uring_multi_accept_op>();
    multi_op_->listen_fd     = fd_;
    multi_op_->acceptor_impl = this;
    multi_op_->on_cqe        = &io_uring_tcp_acceptor::on_accept_cqe;
    multi_op_->impl_ptr      = shared_from_this();  // keep alive in flight

    auto* op = multi_op_.get();
    io_uring_submit_op(*sched_, op, [this](::io_uring_sqe* sqe) {
        ::io_uring_prep_multishot_accept(
            sqe, fd_,
            reinterpret_cast<sockaddr*>(&multi_op_->peer_storage),
            &multi_op_->peer_len,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
    });
    // Deliberately no work_started(): the multishot SQE is a persistent
    // internal mechanism. User-visible work is tracked per-accept call.
}

inline std::coroutine_handle<>
io_uring_tcp_acceptor::accept(
    std::coroutine_handle<>     h,
    capy::executor_ref          ex,
    std::stop_token             token,
    std::error_code*            ec,
    io_object::implementation** impl_out)
{
    uring_accept_op* ready_op = nullptr;
    {
        std::lock_guard lk(mutex_);

        if (auto* r = ready_fds_.pop_front())
        {
            // A parked fd is available — build op under lock, post after.
            ready_op              = new uring_accept_op();
            ready_op->h           = h;
            ready_op->ex          = ex;
            ready_op->ec_out      = ec;
            ready_op->impl_out    = impl_out;
            ready_op->peer_service = peer_service_;
            ready_op->adopt_fn    = &io_uring_tcp_acceptor::adopt_thunk;
            ready_op->accepted_fd = r->fd;
            ready_op->peer_storage = r->peer;
            ready_op->peer_len    = r->peer_len;
            delete r;
        }
        else
        {
            // No ready fd — queue a waiter.
            auto* w          = new waiter_node{};
            w->h             = h;
            w->ex            = ex;
            w->ec_out        = ec;
            w->impl_out      = impl_out;
            w->owner         = this;
            if (token.stop_possible())
                w->stop_cb.emplace(token, waiter_node::canceller{w});
            sched_->work_started();
            waiters_.push_back(w);
        }
    }

    if (ready_op)
        sched_->post(ready_op);

    return std::noop_coroutine();
}

inline void
io_uring_tcp_acceptor::cancel() noexcept
{
    intrusive_list<waiter_node> drained;
    {
        std::lock_guard lk(mutex_);
        closing_ = true;
        // Drain locally — the kernel cancel may not produce a !more CQE
        // before the fd is closed, so we can't rely on on_accept_cqe_impl
        // to surface operation_aborted to queued waiters.
        while (auto* w = waiters_.pop_front())
            drained.push_back(w);
    }

    if (fd_ >= 0)
        sched_->submit_cancel_by_fd(fd_);

    // Synthesize cancellation completions for the drained waiters.
    while (auto* w = drained.pop_front())
    {
        auto* op = new uring_accept_op();
        op->h        = w->h;
        op->ex       = w->ex;
        op->ec_out   = w->ec_out;
        op->impl_out = w->impl_out;
        op->cancelled.store(true, std::memory_order_release);
        delete w;

        // post() does outstanding_work_++; the run loop's work_finished
        // after dispatch decrements. The waiter's own work_started (from
        // accept()) is balanced here.
        sched_->post(op);
        sched_->work_finished();
    }
}

inline void
io_uring_tcp_acceptor::cancel_waiter(waiter_node* w) noexcept
{
    {
        std::lock_guard lk(mutex_);
        if (closing_)
            return;  // on_accept_cqe_impl will drain with closing_ set
        waiters_.remove(w);
    }
    auto* op      = new uring_accept_op();
    op->h         = w->h;
    op->ex        = w->ex;
    op->ec_out    = w->ec_out;
    op->impl_out  = w->impl_out;
    op->cancelled.store(true, std::memory_order_release);
    delete w;

    // post() increments outstanding_work_; balances the work_started()
    // from accept() when the waiter was queued.
    sched_->post(op);
    sched_->work_finished();  // balance the work_started() from accept()
}

inline void
io_uring_tcp_acceptor::on_accept_cqe_impl(
    int new_fd, int err, bool more) noexcept
{
    bool was_closing = false;
    waiter_node* matched = nullptr;
    intrusive_list<waiter_node> closing_waiters;

    {
        std::lock_guard lk(mutex_);
        was_closing = closing_;
        if (was_closing)
        {
            if (new_fd >= 0)
                ::close(new_fd);
            if (!more)
            {
                // Collect waiters to drain after the lock is released.
                while (auto* w = waiters_.pop_front())
                    closing_waiters.push_back(w);
            }
        }
        else
        {
            if (!waiters_.empty())
                matched = waiters_.pop_front();
            else if (new_fd >= 0)
            {
                auto* node      = new ready_fd_node{};
                node->fd        = new_fd;
                node->peer      = multi_op_->peer_storage;
                node->peer_len  = multi_op_->peer_len;
                ready_fds_.push_back(node);
            }
        }
    }

    if (was_closing)
    {
        if (!more)
        {
            while (auto* w = closing_waiters.pop_front())
            {
                w->stop_cb.reset();
                auto* op      = new uring_accept_op();
                op->h         = w->h;
                op->ex        = w->ex;
                op->ec_out    = w->ec_out;
                op->impl_out  = w->impl_out;
                op->cancelled.store(true, std::memory_order_release);
                delete w;
                sched_->post(op);
                sched_->work_finished();  // balance waiter's work_started
            }
        }
        return;
    }

    if (matched)
    {
        matched->stop_cb.reset();
        auto* op         = new uring_accept_op();
        op->h            = matched->h;
        op->ex           = matched->ex;
        op->ec_out       = matched->ec_out;
        op->impl_out     = matched->impl_out;
        op->peer_service = peer_service_;
        op->adopt_fn     = &io_uring_tcp_acceptor::adopt_thunk;
        if (err)
            op->err = err;
        else
        {
            op->accepted_fd  = new_fd;
            op->peer_storage = multi_op_->peer_storage;
            op->peer_len     = multi_op_->peer_len;
        }
        delete matched;
        sched_->post(op);
        sched_->work_finished();  // balance waiter's work_started
    }

    if (!more)
    {
        // Kernel terminated multishot (e.g. -ENOMEM). Re-arm unless closing.
        struct rearm_op final : scheduler_op
        {
            std::shared_ptr<io_uring_tcp_acceptor> self;
            explicit rearm_op(
                std::shared_ptr<io_uring_tcp_acceptor> s) noexcept
                : scheduler_op(&do_fn)
                , self(std::move(s))
            {}
            static void do_fn(
                void*, scheduler_op* base,
                std::uint32_t, std::uint32_t) noexcept
            {
                auto* r = static_cast<rearm_op*>(base);
                auto  s = std::move(r->self);
                delete r;
                {
                    std::lock_guard lk(s->mutex_);
                    if (s->closing_)
                        return;
                }
                s->start_multishot();
            }
            void operator()() override { complete(this, 0, 0); }
            void destroy() override { delete this; }
        };
        if (!closing_)
            sched_->post(new rearm_op(shared_from_this()));
    }
}

inline io_object::implementation*
io_uring_tcp_acceptor::adopt_thunk(
    void*                    peer_service,
    int                      fd,
    sockaddr_storage const&  peer,
    socklen_t                peer_len) noexcept
{
    auto* svc = static_cast<io_uring_tcp_service*>(peer_service);
    return svc->adopt_fd(fd, sockaddr_to_endpoint(peer));
}

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
            // resolves the file from the fd number while it is still valid.
            sched_->cancel_and_flush(acc->fd_);
            acc->cancel();           // drain waiters
            ::close(acc->fd_);
            acc->fd_ = -1;

            // Break the multi_op_ → impl_ptr (shared_ptr<this>) ref cycle
            // start_multishot established. The cancel_and_flush above has
            // submitted the cancel SQE and the fd is closed, so further
            // multishot CQEs would carry the cancel result; we let the
            // run loop drain them on the next ioc.run() iteration.
            //
            // Known limitation: if the user destroys the io_context
            // immediately after close() without an intervening run()
            // pass, ASan flags multi_op_ as a leak — the kernel-side
            // CQE never gets pulled. Tracked as plan-2-blocker debt.
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

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_TYPES_HPP
