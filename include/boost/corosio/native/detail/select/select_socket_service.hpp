//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_SOCKET_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_SOCKET_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/detail/socket_service.hpp>

#include <boost/corosio/native/detail/select/select_socket.hpp>
#include <boost/corosio/native/detail/select/select_scheduler.hpp>

#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_socket_ops.hpp>
#include <boost/corosio/native/detail/reactor_op_complete.hpp>
#include <boost/corosio/native/detail/reactor_socket_service.hpp>
#include <boost/corosio/native/detail/reactor_socket_io.hpp>

#include <boost/corosio/detail/except.hpp>

#include <boost/capy/buffers.hpp>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

/*
    select Socket Implementation
    ============================

    This mirrors the epoll_sockets design for behavioral consistency.
    Each I/O operation follows the same pattern:
      1. Try the syscall immediately (non-blocking socket)
      2. If it succeeds or fails with a real error, complete inline or post
      3. If EAGAIN/EWOULDBLOCK, register with descriptor_state and wait

    Persistent Descriptor Registration
    -----------------------------------
    File descriptors are registered via descriptor_state once and stay
    registered until closed. The descriptor_state tracks pending operations
    and handles the deferred I/O model matching epoll/kqueue.

    Cancellation
    ------------
    Uses mutex-based claiming via descriptor_state matching epoll/kqueue.
    cancel() acquires the descriptor_state mutex, claims pending ops, posts
    them as cancelled. close_socket() calls cancel first.

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
    select_socket_service owns all socket impls. destroy() removes the
    shared_ptr from the map, but the impl may survive if ops still hold
    impl_ptr refs. shutdown() closes all sockets and clears the map; any
    in-flight ops will complete and release their refs.
*/

namespace boost::corosio::detail {

/** select socket service implementation.

    Inherits from socket_service to enable runtime polymorphism.
    Uses key_type = socket_service for service lookup.
*/
class BOOST_COROSIO_DECL select_socket_service final
    : public socket_service
    , public reactor_socket_service<
          select_socket_service,
          select_socket,
          select_scheduler>
{
    using base_type = reactor_socket_service<
        select_socket_service,
        select_socket,
        select_scheduler>;

public:
    explicit select_socket_service(capy::execution_context& ctx);
    ~select_socket_service() override;

    select_socket_service(select_socket_service const&)            = delete;
    select_socket_service& operator=(select_socket_service const&) = delete;

    void shutdown() override;

    io_object::implementation* construct() override;
    void destroy(io_object::implementation*) override;
    void close(io_object::handle&) override;
    std::error_code open_socket(
        tcp_socket::implementation& impl,
        int family,
        int type,
        int protocol) override;

    select_scheduler& scheduler() const noexcept
    {
        return do_scheduler();
    }
    void post(select_op* op);
    void work_started() noexcept;
    void work_finished() noexcept;
};

// Backward compatibility alias
using select_sockets = select_socket_service;

inline void
select_socket::on_pre_close_fd() noexcept
{
    if (desc_state_.registered_events != 0)
        svc_.scheduler().deregister_descriptor(fd_);
}

inline void
select_socket::on_register_read() noexcept
{
    svc_.scheduler().start_op(fd_, select_scheduler::event_read);
}

inline void
select_socket::on_register_write() noexcept
{
    svc_.scheduler().start_op(fd_, select_scheduler::event_write);
}

inline void
select_read_op::operator()()
{
    socket_impl_->svc_.scheduler().reset_inline_budget();
    reactor_io_op_complete(*this);
}

inline void
select_write_op::operator()()
{
    socket_impl_->svc_.scheduler().reset_inline_budget();
    reactor_io_op_complete(*this);
}

inline void
select_connect_op::operator()()
{
    socket_impl_->svc_.scheduler().reset_inline_budget();
    reactor_connect_op_complete<select_socket>(*this);
}

inline select_socket::select_socket(select_socket_service& svc) noexcept
    : svc_(svc)
{
}

inline select_socket::~select_socket() = default;

inline std::coroutine_handle<>
select_socket::connect(
    std::coroutine_handle<> h,
    capy::executor_ref ex,
    endpoint ep,
    std::stop_token token,
    std::error_code* ec)
{
    return reactor_socket_io::do_connect(*this, h, ex, ep, token, ec);
}

inline std::coroutine_handle<>
select_socket::read_some(
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
select_socket::write_some(
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
select_socket::shutdown(tcp_socket::shutdown_type what) noexcept
{
    return posix::do_shutdown(fd_, what);
}

inline std::error_code
select_socket::set_option(
    int level, int optname, void const* data, std::size_t size) noexcept
{
    return posix::do_set_option(fd_, level, optname, data, size);
}

inline std::error_code
select_socket::get_option(
    int level, int optname, void* data, std::size_t* size) const noexcept
{
    return posix::do_get_option(fd_, level, optname, data, size);
}

inline void
select_socket::cancel() noexcept
{
    do_cancel();
}

inline void
select_socket::cancel_single_op(select_op& op) noexcept
{
    do_cancel_single_op(op);
}

inline void
select_socket::close_socket() noexcept
{
    do_close_socket();
}

inline select_socket_service::select_socket_service(
    capy::execution_context& ctx)
    : base_type(ctx)
{
}

inline select_socket_service::~select_socket_service() {}

inline void
select_socket_service::shutdown()
{
    do_shutdown();
}

inline io_object::implementation*
select_socket_service::construct()
{
    return do_construct();
}

inline void
select_socket_service::destroy(io_object::implementation* impl)
{
    do_destroy(impl);
}

inline std::error_code
select_socket_service::open_socket(
    tcp_socket::implementation& impl, int family, int type, int protocol)
{
    auto* select_impl = static_cast<select_socket*>(&impl);
    select_impl->close_socket();

    int fd = ::socket(family, type, protocol);
    if (fd < 0)
        return make_err(errno);

    if (family == AF_INET6)
    {
        int one = 1;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }

    // Set non-blocking and close-on-exec
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
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        int errn = errno;
        ::close(fd);
        return make_err(errn);
    }

    // Check fd is within select() limits
    if (fd >= FD_SETSIZE)
    {
        ::close(fd);
        return make_err(EMFILE);
    }

    select_impl->fd_ = fd;

    // Register fd with scheduler for persistent monitoring
    select_impl->desc_state_.fd = fd;
    select_impl->desc_state_.init_ops();
    scheduler().register_descriptor(fd, &select_impl->desc_state_);

    return {};
}

inline void
select_socket_service::close(io_object::handle& h)
{
    do_close(h);
}

inline void
select_socket_service::post(select_op* op)
{
    do_post(op);
}

inline void
select_socket_service::work_started() noexcept
{
    do_work_started();
}

inline void
select_socket_service::work_finished() noexcept
{
    do_work_finished();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_SOCKET_SERVICE_HPP
