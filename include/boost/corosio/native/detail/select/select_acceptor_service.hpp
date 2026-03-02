//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_ACCEPTOR_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_ACCEPTOR_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/detail/acceptor_service.hpp>

#include <boost/corosio/native/detail/select/select_acceptor.hpp>
#include <boost/corosio/native/detail/select/select_socket_service.hpp>
#include <boost/corosio/native/detail/select/select_scheduler.hpp>

#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_socket_ops.hpp>
#include <boost/corosio/native/detail/reactor_acceptor_service.hpp>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace boost::corosio::detail {

/** select acceptor service implementation.

    Inherits from acceptor_service to enable runtime polymorphism.
    Uses key_type = acceptor_service for service lookup.
*/
class BOOST_COROSIO_DECL select_acceptor_service final
    : public acceptor_service
    , public reactor_acceptor_service<
          select_acceptor_service,
          select_acceptor,
          select_scheduler,
          select_socket_service>
{
    using base_type = reactor_acceptor_service<
        select_acceptor_service,
        select_acceptor,
        select_scheduler,
        select_socket_service>;

public:
    explicit select_acceptor_service(capy::execution_context& ctx);
    ~select_acceptor_service() override;

    select_acceptor_service(select_acceptor_service const&)            = delete;
    select_acceptor_service& operator=(select_acceptor_service const&) = delete;

    void shutdown() override;

    io_object::implementation* construct() override;
    void destroy(io_object::implementation*) override;
    void close(io_object::handle&) override;
    std::error_code open_acceptor_socket(
        tcp_acceptor::implementation& impl,
        int family,
        int type,
        int protocol) override;
    std::error_code
    bind_acceptor(tcp_acceptor::implementation& impl, endpoint ep) override;
    std::error_code
    listen_acceptor(tcp_acceptor::implementation& impl, int backlog) override;

    select_scheduler& scheduler() const noexcept
    {
        return do_scheduler();
    }
    void post(select_op* op);
    void work_started() noexcept;
    void work_finished() noexcept;

    /** Get the socket service for creating peer sockets during accept. */
    select_socket_service* socket_service() const noexcept;
};

inline void
select_accept_op::operator()()
{
    auto& svc = static_cast<select_acceptor*>(acceptor_impl_)->service();
    svc.scheduler().reset_inline_budget();
    reactor_accept_op_complete<select_socket>(*this, svc.socket_service());
}

inline select_acceptor::select_acceptor(select_acceptor_service& svc) noexcept
    : svc_(svc)
{
}

inline std::coroutine_handle<>
select_acceptor::accept(
    std::coroutine_handle<> h,
    capy::executor_ref ex,
    std::stop_token token,
    std::error_code* ec,
    io_object::implementation** impl_out)
{
    auto& op = acc_;
    op.reset();
    op.h        = h;
    op.ex       = ex;
    op.ec_out   = ec;
    op.impl_out = impl_out;
    op.fd       = fd_;
    op.start(token, this);

    sockaddr_storage peer_storage{};
    socklen_t addrlen = sizeof(peer_storage);
    int accepted =
        ::accept(fd_, reinterpret_cast<sockaddr*>(&peer_storage), &addrlen);

    if (accepted >= 0)
    {
        // Reject fds that exceed select()'s FD_SETSIZE limit.
        if (accepted >= FD_SETSIZE)
        {
            ::close(accepted);
            op.accepted_fd = -1;
            op.complete(EINVAL, 0);
            op.impl_ptr = shared_from_this();
            svc_.post(&op);
            return std::noop_coroutine();
        }

        // Set non-blocking and close-on-exec flags.
        int flags = ::fcntl(accepted, F_GETFL, 0);
        if (flags == -1)
        {
            int err = errno;
            ::close(accepted);
            op.accepted_fd = -1;
            op.complete(err, 0);
            op.impl_ptr = shared_from_this();
            svc_.post(&op);
            return std::noop_coroutine();
        }

        if (::fcntl(accepted, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            int err = errno;
            ::close(accepted);
            op.accepted_fd = -1;
            op.complete(err, 0);
            op.impl_ptr = shared_from_this();
            svc_.post(&op);
            return std::noop_coroutine();
        }

        if (::fcntl(accepted, F_SETFD, FD_CLOEXEC) == -1)
        {
            int err = errno;
            ::close(accepted);
            op.accepted_fd = -1;
            op.complete(err, 0);
            op.impl_ptr = shared_from_this();
            svc_.post(&op);
            return std::noop_coroutine();
        }

        {
            std::lock_guard lock(desc_state_.mutex);
            desc_state_.read_ready = false;
        }

        if (svc_.scheduler().try_consume_inline_budget())
        {
            auto* socket_svc = svc_.socket_service();
            if (socket_svc)
            {
                auto* peer = setup_accepted_socket<select_socket>(
                    *socket_svc, accepted, local_endpoint_,
                    from_sockaddr(peer_storage));
                *ec = {};
                if (impl_out)
                    *impl_out = peer;
            }
            else
            {
                ::close(accepted);
                *ec = make_err(ENOENT);
                if (impl_out)
                    *impl_out = nullptr;
            }
            return dispatch_coro(ex, h);
        }

        op.accepted_fd  = accepted;
        op.peer_storage = peer_storage;
        op.complete(0, 0);
        op.impl_ptr = shared_from_this();
        svc_.post(&op);
        return std::noop_coroutine();
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
        op.impl_ptr = shared_from_this();
        svc_.work_started();

        std::lock_guard lock(desc_state_.mutex);
        bool io_done = false;
        if (desc_state_.read_ready)
        {
            desc_state_.read_ready = false;
            op.perform_io();
            io_done = (op.errn != EAGAIN && op.errn != EWOULDBLOCK);
            if (!io_done)
                op.errn = 0;
        }

        if (io_done || op.cancelled.load(std::memory_order_acquire))
        {
            svc_.post(&op);
            svc_.work_finished();
        }
        else
        {
            desc_state_.read_op = &op;
        }

        // Tell scheduler to monitor this fd for read events
        svc_.scheduler().start_op(fd_, select_scheduler::event_read);
        return std::noop_coroutine();
    }

    op.complete(errno, 0);
    op.impl_ptr = shared_from_this();
    svc_.post(&op);
    return std::noop_coroutine();
}

inline void
select_acceptor::on_pre_close_fd() noexcept
{
    if (desc_state_.registered_events != 0)
        svc_.scheduler().deregister_descriptor(fd_);
}

inline void
select_acceptor::cancel() noexcept
{
    do_cancel_single_op(acc_);
}

inline void
select_acceptor::cancel_single_op(select_op& op) noexcept
{
    do_cancel_single_op(op);
}

inline void
select_acceptor::close_socket() noexcept
{
    do_close_socket();
}

inline select_acceptor_service::select_acceptor_service(
    capy::execution_context& ctx)
    : base_type(ctx)
{
}

inline select_acceptor_service::~select_acceptor_service() {}

inline void
select_acceptor_service::shutdown()
{
    do_shutdown();
}

inline io_object::implementation*
select_acceptor_service::construct()
{
    return do_construct();
}

inline void
select_acceptor_service::destroy(io_object::implementation* impl)
{
    do_destroy(impl);
}

inline void
select_acceptor_service::close(io_object::handle& h)
{
    do_close(h);
}

inline std::error_code
select_acceptor::set_option(
    int level, int optname, void const* data, std::size_t size) noexcept
{
    return posix::do_set_option(fd_, level, optname, data, size);
}

inline std::error_code
select_acceptor::get_option(
    int level, int optname, void* data, std::size_t* size) const noexcept
{
    return posix::do_get_option(fd_, level, optname, data, size);
}

inline std::error_code
select_acceptor_service::open_acceptor_socket(
    tcp_acceptor::implementation& impl, int family, int type, int protocol)
{
    auto* select_impl = static_cast<select_acceptor*>(&impl);
    select_impl->close_socket();

    int fd = ::socket(family, type, protocol);
    if (fd < 0)
        return make_err(errno);

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

    if (fd >= FD_SETSIZE)
    {
        ::close(fd);
        return make_err(EMFILE);
    }

    if (family == AF_INET6)
    {
        int val = 0; // dual-stack default
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
    }

    select_impl->fd_ = fd;

    // Set up descriptor state but do NOT register with scheduler yet
    select_impl->desc_state_.fd = fd;
    select_impl->desc_state_.init_ops();

    return {};
}

inline std::error_code
select_acceptor_service::bind_acceptor(
    tcp_acceptor::implementation& impl, endpoint ep)
{
    return do_bind_acceptor(impl, ep);
}

inline std::error_code
select_acceptor_service::listen_acceptor(
    tcp_acceptor::implementation& impl, int backlog)
{
    return do_listen_acceptor(impl, backlog);
}

inline void
select_acceptor_service::post(select_op* op)
{
    do_post(op);
}

inline void
select_acceptor_service::work_started() noexcept
{
    do_work_started();
}

inline void
select_acceptor_service::work_finished() noexcept
{
    do_work_finished();
}

inline select_socket_service*
select_acceptor_service::socket_service() const noexcept
{
    return do_socket_service();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_ACCEPTOR_SERVICE_HPP
