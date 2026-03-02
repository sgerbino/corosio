//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_SOCKET_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_SOCKET_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/detail/socket_service.hpp>

#include <boost/corosio/native/detail/epoll/epoll_socket.hpp>
#include <boost/corosio/native/detail/epoll/epoll_scheduler.hpp>

#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_socket_ops.hpp>
#include <boost/corosio/native/detail/reactor_op_complete.hpp>
#include <boost/corosio/native/detail/reactor_socket_service.hpp>
#include <boost/corosio/native/detail/reactor_socket_io.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/detail/except.hpp>
#include <boost/capy/buffers.hpp>

#include <coroutine>

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/*
    epoll Socket Implementation
    ===========================

    Each I/O operation follows the same pattern:
      1. Try the syscall immediately (non-blocking socket)
      2. If it succeeds or fails with a real error, post to completion queue
      3. If EAGAIN/EWOULDBLOCK, register with epoll and wait

    This "try first" approach avoids unnecessary epoll round-trips for
    operations that can complete immediately (common for small reads/writes
    on fast local connections).

    One-Shot Registration
    ---------------------
    We use one-shot epoll registration: each operation registers, waits for
    one event, then unregisters. This simplifies the state machine since we
    don't need to track whether an fd is currently registered or handle
    re-arming. The tradeoff is slightly more epoll_ctl calls, but the
    simplicity is worth it.

    Cancellation
    ------------
    See op.hpp for the completion/cancellation race handling via the
    `registered` atomic. cancel() must complete pending operations (post
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
    epoll_socket_service owns all socket impls. destroy_impl() removes the
    shared_ptr from the map, but the impl may survive if ops still hold
    impl_ptr refs. shutdown() closes all sockets and clears the map; any
    in-flight ops will complete and release their refs.
*/

namespace boost::corosio::detail {

/** epoll socket service implementation.

    Inherits from socket_service to enable runtime polymorphism.
    Uses key_type = socket_service for service lookup.
*/
class BOOST_COROSIO_DECL epoll_socket_service final
    : public socket_service
    , public reactor_socket_service<
          epoll_socket_service,
          epoll_socket,
          epoll_scheduler>
{
    using base_type = reactor_socket_service<
        epoll_socket_service,
        epoll_socket,
        epoll_scheduler>;

public:
    explicit epoll_socket_service(capy::execution_context& ctx);
    ~epoll_socket_service() override;

    epoll_socket_service(epoll_socket_service const&)            = delete;
    epoll_socket_service& operator=(epoll_socket_service const&) = delete;

    void shutdown() override;

    io_object::implementation* construct() override;
    void destroy(io_object::implementation*) override;
    void close(io_object::handle&) override;
    std::error_code open_socket(
        tcp_socket::implementation& impl,
        int family,
        int type,
        int protocol) override;

    epoll_scheduler& scheduler() const noexcept
    {
        return do_scheduler();
    }
    void post(epoll_op* op);
    void work_started() noexcept;
    void work_finished() noexcept;
};

//--------------------------------------------------------------------------
//
// Implementation
//
//--------------------------------------------------------------------------

inline void
epoll_socket::on_pre_close_fd() noexcept
{
    if (desc_state_.registered_events != 0)
        svc_.scheduler().deregister_descriptor(fd_);
}

inline void
epoll_read_op::operator()()
{
    socket_impl_->svc_.scheduler().reset_inline_budget();
    reactor_io_op_complete(*this);
}

inline void
epoll_write_op::operator()()
{
    socket_impl_->svc_.scheduler().reset_inline_budget();
    reactor_io_op_complete(*this);
}

inline void
epoll_connect_op::operator()()
{
    socket_impl_->svc_.scheduler().reset_inline_budget();
    reactor_connect_op_complete<epoll_socket>(*this);
}

inline epoll_socket::epoll_socket(epoll_socket_service& svc) noexcept
    : svc_(svc)
{
}

inline epoll_socket::~epoll_socket() = default;

inline std::coroutine_handle<>
epoll_socket::connect(
    std::coroutine_handle<> h,
    capy::executor_ref ex,
    endpoint ep,
    std::stop_token token,
    std::error_code* ec)
{
    return reactor_socket_io::do_connect(*this, h, ex, ep, token, ec);
}

inline std::coroutine_handle<>
epoll_socket::read_some(
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
epoll_socket::write_some(
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
epoll_socket::shutdown(tcp_socket::shutdown_type what) noexcept
{
    return posix::do_shutdown(fd_, what);
}

inline std::error_code
epoll_socket::set_option(
    int level, int optname, void const* data, std::size_t size) noexcept
{
    return posix::do_set_option(fd_, level, optname, data, size);
}

inline std::error_code
epoll_socket::get_option(
    int level, int optname, void* data, std::size_t* size) const noexcept
{
    return posix::do_get_option(fd_, level, optname, data, size);
}

inline void
epoll_socket::cancel() noexcept
{
    do_cancel();
}

inline void
epoll_socket::cancel_single_op(epoll_op& op) noexcept
{
    do_cancel_single_op(op);
}

inline void
epoll_socket::close_socket() noexcept
{
    do_close_socket();
}

inline epoll_socket_service::epoll_socket_service(capy::execution_context& ctx)
    : base_type(ctx)
{
}

inline epoll_socket_service::~epoll_socket_service() {}

inline void
epoll_socket_service::shutdown()
{
    do_shutdown();
}

inline io_object::implementation*
epoll_socket_service::construct()
{
    return do_construct();
}

inline void
epoll_socket_service::destroy(io_object::implementation* impl)
{
    do_destroy(impl);
}

inline std::error_code
epoll_socket_service::open_socket(
    tcp_socket::implementation& impl, int family, int type, int protocol)
{
    auto* epoll_impl = static_cast<epoll_socket*>(&impl);
    epoll_impl->close_socket();

    int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    if (fd < 0)
        return make_err(errno);

    if (family == AF_INET6)
    {
        int one = 1;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }

    epoll_impl->fd_ = fd;

    // Register fd with epoll (edge-triggered mode)
    epoll_impl->desc_state_.fd = fd;
    epoll_impl->desc_state_.init_ops();
    scheduler().register_descriptor(fd, &epoll_impl->desc_state_);

    return {};
}

inline void
epoll_socket_service::close(io_object::handle& h)
{
    do_close(h);
}

inline void
epoll_socket_service::post(epoll_op* op)
{
    do_post(op);
}

inline void
epoll_socket_service::work_started() noexcept
{
    do_work_started();
}

inline void
epoll_socket_service::work_finished() noexcept
{
    do_work_finished();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL

#endif // BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_SOCKET_SERVICE_HPP
