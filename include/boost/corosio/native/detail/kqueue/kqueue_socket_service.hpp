//
// Copyright (c) 2026 Michael Vandeberg
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_SOCKET_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_SOCKET_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_KQUEUE

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/detail/socket_service.hpp>

#include <boost/corosio/native/detail/kqueue/kqueue_socket.hpp>
#include <boost/corosio/native/detail/kqueue/kqueue_scheduler.hpp>

#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_socket_ops.hpp>
#include <boost/corosio/native/detail/reactor_op_complete.hpp>
#include <boost/corosio/native/detail/reactor_socket_service.hpp>
#include <boost/corosio/native/detail/reactor_socket_io.hpp>
#include <boost/corosio/detail/except.hpp>
#include <boost/capy/buffers.hpp>

#include <coroutine>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

/*
    kqueue Socket Implementation
    ============================

    Each I/O operation follows the same pattern:
      1. Try the syscall speculatively (readv/writev) before suspending
      2. On success, return via symmetric transfer (the "pump" fast path)
      3. On budget exhaustion, post to the scheduler queue for fairness
      4. On EAGAIN, register_op() parks the op in the descriptor_state

    The speculative path avoids scheduler queue, mutex, and reactor
    round-trips entirely. An inline budget limits consecutive inline
    completions to prevent starvation of other connections.

    Cancellation
    ------------
    See op.hpp for the completion/cancellation race handling via the
    descriptor_state mutex. cancel() must complete pending operations (post
    them with cancelled flag) so coroutines waiting on them can resume.
    close_socket() calls cancel() first to ensure this.

    Impl Lifetime with shared_ptr
    -----------------------------
    Socket impls use enable_shared_from_this. The service owns impls via
    shared_ptr maps (socket_ptrs_) keyed by raw pointer for O(1) lookup and
    removal. When a user calls close(), we call cancel() which posts pending
    ops to the scheduler.

    CRITICAL: The posted ops must keep the impl alive until they complete.
    Otherwise the scheduler would process a freed op (use-after-free). The
    cancel() method captures shared_from_this() into op.impl_ptr before
    posting. When the op completes, impl_ptr is cleared, allowing the impl
    to be destroyed if no other references exist.

    Service Ownership
    -----------------
    kqueue_socket_service owns all socket impls. destroy_impl() removes the
    shared_ptr from the map, but the impl may survive if ops still hold
    impl_ptr refs. shutdown() closes all sockets and clears the map; any
    in-flight ops will complete and release their refs.
*/

/*
    kqueue socket implementation
    ============================

    Each kqueue_socket owns a descriptor_state that is persistently
    registered with kqueue (EVFILT_READ + EVFILT_WRITE, both EV_CLEAR for
    edge-triggered semantics). The descriptor_state tracks three operation
    slots (read_op, write_op, connect_op) and two ready flags
    (read_ready, write_ready) under a per-descriptor mutex.

    Speculative I/O and the pump
    ----------------------------
    read_some() and write_some() attempt the syscall (readv/writev)
    speculatively before suspending the caller. If data is available the
    result is returned via symmetric transfer — no scheduler queue, no
    mutex, no reactor round-trip. An inline budget limits consecutive
    inline completions to prevent starvation of other connections.

    When the speculative attempt returns EAGAIN, register_op() parks the
    operation in its descriptor_state slot under the per-descriptor mutex.
    If a cached ready flag fires before parking, register_op() retries
    the I/O once under the mutex. This eliminates the cached_initiator
    coroutine frame that previously trampolined into do_read_io() /
    do_write_io() after the caller suspended.

    Ready-flag protocol
    -------------------
    When a kqueue event fires and no operation is pending for that
    direction, the reactor sets the corresponding ready flag instead of
    dropping the event. When register_op() finds the ready flag set, it
    performs I/O immediately rather than parking. This prevents lost
    wakeups under edge-triggered notification.
*/

namespace boost::corosio::detail {

/** kqueue socket service implementation.

    Inherits from socket_service to enable runtime polymorphism.
    Uses key_type = socket_service for service lookup.
*/
class BOOST_COROSIO_DECL kqueue_socket_service final
    : public socket_service
    , public reactor_socket_service<
          kqueue_socket_service,
          kqueue_socket,
          kqueue_scheduler>
{
    using base_type = reactor_socket_service<
        kqueue_socket_service,
        kqueue_socket,
        kqueue_scheduler>;

public:
    explicit kqueue_socket_service(capy::execution_context& ctx);
    ~kqueue_socket_service();

    kqueue_socket_service(kqueue_socket_service const&)            = delete;
    kqueue_socket_service& operator=(kqueue_socket_service const&) = delete;

    void shutdown() override;

    io_object::implementation* construct() override;
    void destroy(io_object::implementation*) override;
    void close(io_object::handle&) override;
    std::error_code open_socket(
        tcp_socket::implementation& impl,
        int family,
        int type,
        int protocol) override;

    kqueue_scheduler& scheduler() const noexcept
    {
        return do_scheduler();
    }
    void post(kqueue_op* op);
    void work_started() noexcept;
    void work_finished() noexcept;

    // CRTP hooks: clear SO_LINGER before close so destructor doesn't
    // block and close() sends FIN instead of RST.
    void on_pre_shutdown(kqueue_socket* impl) noexcept;
    void on_pre_destroy(kqueue_socket* impl) noexcept;
};

// -- Implementation ---------------------------------------------------------

inline void
kqueue_read_op::operator()()
{
    socket_impl_->desc_state_.scheduler_->reset_inline_budget();
    reactor_io_op_complete(*this);
}

inline void
kqueue_write_op::operator()()
{
    socket_impl_->desc_state_.scheduler_->reset_inline_budget();
    reactor_io_op_complete(*this);
}

inline void
kqueue_connect_op::operator()()
{
    socket_impl_->desc_state_.scheduler_->reset_inline_budget();
    reactor_connect_op_complete<kqueue_socket>(*this);
}

inline kqueue_socket::kqueue_socket(kqueue_socket_service& svc) noexcept
    : svc_(svc)
{
}

inline kqueue_socket::~kqueue_socket() = default;

inline std::coroutine_handle<>
kqueue_socket::connect(
    std::coroutine_handle<> h,
    capy::executor_ref ex,
    endpoint ep,
    std::stop_token token,
    std::error_code* ec)
{
    return reactor_socket_io::do_connect(*this, h, ex, ep, token, ec);
}

inline std::coroutine_handle<>
kqueue_socket::read_some(
    std::coroutine_handle<> h,
    capy::executor_ref ex,
    buffer_param param,
    std::stop_token token,
    std::error_code* ec,
    std::size_t* bytes_out)
{
    return reactor_socket_io::do_read_some(
        *this, h, ex, param, token, ec, bytes_out);
}

inline std::coroutine_handle<>
kqueue_socket::write_some(
    std::coroutine_handle<> h,
    capy::executor_ref ex,
    buffer_param param,
    std::stop_token token,
    std::error_code* ec,
    std::size_t* bytes_out)
{
    return reactor_socket_io::do_write_some(
        *this, h, ex, param, token, ec, bytes_out);
}

inline std::error_code
kqueue_socket::shutdown(tcp_socket::shutdown_type what) noexcept
{
    return posix::do_shutdown(fd_, what);
}

inline std::error_code
kqueue_socket::set_option(
    int level, int optname, void const* data, std::size_t size) noexcept
{
    auto ec = posix::do_set_option(fd_, level, optname, data, size);
    if (!ec && level == SOL_SOCKET && optname == SO_LINGER &&
        size >= sizeof(struct ::linger))
        user_set_linger_ =
            static_cast<struct ::linger const*>(data)->l_onoff != 0;
    return ec;
}

inline std::error_code
kqueue_socket::get_option(
    int level, int optname, void* data, std::size_t* size) const noexcept
{
    return posix::do_get_option(fd_, level, optname, data, size);
}

inline void
kqueue_socket::cancel() noexcept
{
    do_cancel();
}

inline void
kqueue_socket::cancel_single_op(kqueue_op& op) noexcept
{
    do_cancel_single_op(op);
}

inline void
kqueue_socket::close_socket() noexcept
{
    do_close_socket();
}

inline kqueue_socket_service::kqueue_socket_service(
    capy::execution_context& ctx)
    : base_type(ctx)
{
}

inline kqueue_socket_service::~kqueue_socket_service() {}

inline void
kqueue_socket_service::shutdown()
{
    do_shutdown();
}

inline io_object::implementation*
kqueue_socket_service::construct()
{
    return do_construct();
}

inline void
kqueue_socket_service::destroy(io_object::implementation* impl)
{
    do_destroy(impl);
}

inline void
kqueue_socket_service::on_pre_shutdown(kqueue_socket* impl) noexcept
{
    if (impl->user_set_linger_ && impl->fd_ >= 0)
    {
        struct ::linger lg;
        lg.l_onoff  = 0;
        lg.l_linger = 0;
        ::setsockopt(impl->fd_, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    }
}

inline void
kqueue_socket_service::on_pre_destroy(kqueue_socket* impl) noexcept
{
    on_pre_shutdown(impl);
}

inline std::error_code
kqueue_socket_service::open_socket(
    tcp_socket::implementation& impl, int family, int type, int protocol)
{
    auto* kq_impl = static_cast<kqueue_socket*>(&impl);
    kq_impl->close_socket();

    int fd = ::socket(family, type, protocol);
    if (fd < 0)
        return make_err(errno);

    if (family == AF_INET6)
    {
        int v6only = 1;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    // Set non-blocking
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        int errn = errno;
        ::close(fd);
        return make_err(errn);
    }
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        int errn = errno;
        ::close(fd);
        return make_err(errn);
    }

    // Set close-on-exec
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        int errn = errno;
        ::close(fd);
        return make_err(errn);
    }

    // Suppress SIGPIPE on this socket; writev() has no MSG_NOSIGNAL
    // equivalent, so SO_NOSIGPIPE is required on macOS/FreeBSD.
    int one = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0)
    {
        int errn = errno;
        ::close(fd);
        return make_err(errn);
    }

    kq_impl->fd_ = fd;

    // Register fd with kqueue (edge-triggered mode via EV_CLEAR)
    kq_impl->desc_state_.fd = fd;
    kq_impl->desc_state_.init_ops();
    scheduler().register_descriptor(fd, &kq_impl->desc_state_);

    return {};
}

inline void
kqueue_socket_service::close(io_object::handle& h)
{
    do_close(h);
}

inline void
kqueue_socket_service::post(kqueue_op* op)
{
    do_post(op);
}

inline void
kqueue_socket_service::work_started() noexcept
{
    do_work_started();
}

inline void
kqueue_socket_service::work_finished() noexcept
{
    do_work_finished();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_KQUEUE

#endif // BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_SOCKET_SERVICE_HPP
