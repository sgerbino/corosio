//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_ACCEPTOR_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_ACCEPTOR_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/detail/acceptor_service.hpp>

#include <boost/corosio/native/detail/epoll/epoll_acceptor.hpp>
#include <boost/corosio/native/detail/epoll/epoll_socket_service.hpp>
#include <boost/corosio/native/detail/epoll/epoll_scheduler.hpp>

#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_socket_ops.hpp>
#include <boost/corosio/native/detail/reactor_acceptor_service.hpp>

#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

#include <errno.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace boost::corosio::detail {

/** epoll acceptor service implementation.

    Inherits from acceptor_service to enable runtime polymorphism.
    Uses key_type = acceptor_service for service lookup.
*/
class BOOST_COROSIO_DECL epoll_acceptor_service final
    : public acceptor_service
    , public reactor_acceptor_service<
          epoll_acceptor_service,
          epoll_acceptor,
          epoll_scheduler,
          epoll_socket_service>
{
    using base_type = reactor_acceptor_service<
        epoll_acceptor_service,
        epoll_acceptor,
        epoll_scheduler,
        epoll_socket_service>;

public:
    explicit epoll_acceptor_service(capy::execution_context& ctx);
    ~epoll_acceptor_service() override;

    epoll_acceptor_service(epoll_acceptor_service const&)            = delete;
    epoll_acceptor_service& operator=(epoll_acceptor_service const&) = delete;

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

    epoll_scheduler& scheduler() const noexcept
    {
        return do_scheduler();
    }
    void post(epoll_op* op);
    void work_started() noexcept;
    void work_finished() noexcept;

    /** Get the socket service for creating peer sockets during accept. */
    epoll_socket_service* socket_service() const noexcept;
};

//--------------------------------------------------------------------------
//
// Implementation
//
//--------------------------------------------------------------------------

inline void
epoll_accept_op::operator()()
{
    auto& svc = static_cast<epoll_acceptor*>(acceptor_impl_)->service();
    svc.scheduler().reset_inline_budget();
    reactor_accept_op_complete<epoll_socket>(*this, svc.socket_service());
}

inline epoll_acceptor::epoll_acceptor(epoll_acceptor_service& svc) noexcept
    : svc_(svc)
{
}

inline std::coroutine_handle<>
epoll_acceptor::accept(
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
    int accepted;
    do
    {
        accepted = ::accept4(
            fd_, reinterpret_cast<sockaddr*>(&peer_storage), &addrlen,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
    }
    while (accepted < 0 && errno == EINTR);

    if (accepted >= 0)
    {
        {
            std::lock_guard lock(desc_state_.mutex);
            desc_state_.read_ready = false;
        }

        if (svc_.scheduler().try_consume_inline_budget())
        {
            auto* socket_svc = svc_.socket_service();
            if (socket_svc)
            {
                auto* peer = setup_accepted_socket<epoll_socket>(
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
        return std::noop_coroutine();
    }

    op.complete(errno, 0);
    op.impl_ptr = shared_from_this();
    svc_.post(&op);
    // completion is always posted to scheduler queue, never inline.
    return std::noop_coroutine();
}

inline void
epoll_acceptor::on_pre_close_fd() noexcept
{
    if (desc_state_.registered_events != 0)
        svc_.scheduler().deregister_descriptor(fd_);
}

inline void
epoll_acceptor::cancel() noexcept
{
    do_cancel_single_op(acc_);
}

inline void
epoll_acceptor::cancel_single_op(epoll_op& op) noexcept
{
    do_cancel_single_op(op);
}

inline void
epoll_acceptor::close_socket() noexcept
{
    do_close_socket();
}

inline epoll_acceptor_service::epoll_acceptor_service(
    capy::execution_context& ctx)
    : base_type(ctx)
{
}

inline epoll_acceptor_service::~epoll_acceptor_service() {}

inline void
epoll_acceptor_service::shutdown()
{
    do_shutdown();
}

inline io_object::implementation*
epoll_acceptor_service::construct()
{
    return do_construct();
}

inline void
epoll_acceptor_service::destroy(io_object::implementation* impl)
{
    do_destroy(impl);
}

inline void
epoll_acceptor_service::close(io_object::handle& h)
{
    do_close(h);
}

inline std::error_code
epoll_acceptor::set_option(
    int level, int optname, void const* data, std::size_t size) noexcept
{
    return posix::do_set_option(fd_, level, optname, data, size);
}

inline std::error_code
epoll_acceptor::get_option(
    int level, int optname, void* data, std::size_t* size) const noexcept
{
    return posix::do_get_option(fd_, level, optname, data, size);
}

inline std::error_code
epoll_acceptor_service::open_acceptor_socket(
    tcp_acceptor::implementation& impl, int family, int type, int protocol)
{
    auto* epoll_impl = static_cast<epoll_acceptor*>(&impl);
    epoll_impl->close_socket();

    int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    if (fd < 0)
        return make_err(errno);

    if (family == AF_INET6)
    {
        int val = 0; // dual-stack default
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
    }

    epoll_impl->fd_ = fd;

    // Set up descriptor state but do NOT register with epoll yet
    epoll_impl->desc_state_.fd = fd;
    epoll_impl->desc_state_.init_ops();

    return {};
}

inline std::error_code
epoll_acceptor_service::bind_acceptor(
    tcp_acceptor::implementation& impl, endpoint ep)
{
    return do_bind_acceptor(impl, ep);
}

inline std::error_code
epoll_acceptor_service::listen_acceptor(
    tcp_acceptor::implementation& impl, int backlog)
{
    return do_listen_acceptor(impl, backlog);
}

inline void
epoll_acceptor_service::post(epoll_op* op)
{
    do_post(op);
}

inline void
epoll_acceptor_service::work_started() noexcept
{
    do_work_started();
}

inline void
epoll_acceptor_service::work_finished() noexcept
{
    do_work_finished();
}

inline epoll_socket_service*
epoll_acceptor_service::socket_service() const noexcept
{
    return do_socket_service();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL

#endif // BOOST_COROSIO_NATIVE_DETAIL_EPOLL_EPOLL_ACCEPTOR_SERVICE_HPP
