//
// Copyright (c) 2026 Michael Vandeberg
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_ACCEPTOR_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_ACCEPTOR_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_KQUEUE

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/detail/acceptor_service.hpp>

#include <boost/corosio/native/detail/kqueue/kqueue_acceptor.hpp>
#include <boost/corosio/native/detail/kqueue/kqueue_socket_service.hpp>
#include <boost/corosio/native/detail/kqueue/kqueue_scheduler.hpp>

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
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace boost::corosio::detail {

/** kqueue acceptor service implementation.

    Inherits from acceptor_service to enable runtime polymorphism.
    Uses key_type = acceptor_service for service lookup.
*/
class BOOST_COROSIO_DECL kqueue_acceptor_service final
    : public acceptor_service
    , public reactor_acceptor_service<
          kqueue_acceptor_service,
          kqueue_acceptor,
          kqueue_scheduler,
          kqueue_socket_service>
{
    using base_type = reactor_acceptor_service<
        kqueue_acceptor_service,
        kqueue_acceptor,
        kqueue_scheduler,
        kqueue_socket_service>;

public:
    explicit kqueue_acceptor_service(capy::execution_context& ctx);
    ~kqueue_acceptor_service();

    kqueue_acceptor_service(kqueue_acceptor_service const&)            = delete;
    kqueue_acceptor_service& operator=(kqueue_acceptor_service const&) = delete;

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

    kqueue_scheduler& scheduler() const noexcept
    {
        return do_scheduler();
    }
    void post(kqueue_op* op);
    void work_started() noexcept;
    void work_finished() noexcept;

    /** Get the socket service for creating peer sockets during accept. */
    kqueue_socket_service* socket_service() const noexcept;
};

inline void
kqueue_accept_op::operator()()
{
    auto& svc = static_cast<kqueue_acceptor*>(acceptor_impl_)->service();
    svc.scheduler().reset_inline_budget();

    // kqueue: resolve remote via getpeername (accept doesn't populate
    // peer_storage reliably across all BSDs)
    auto resolve_via_getpeername = [](auto const&, int fd) noexcept {
        sockaddr_storage storage{};
        socklen_t len = sizeof(storage);
        endpoint ep;
        if (::getpeername(fd, reinterpret_cast<sockaddr*>(&storage), &len) == 0)
            ep = from_sockaddr(storage);
        return ep;
    };

    // Suppress SIGPIPE on the accepted socket; macOS lacks MSG_NOSIGNAL
    auto set_nosigpipe = [](int fd) noexcept -> std::error_code {
        int one = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) == -1)
            return make_err(errno);
        return {};
    };

    reactor_accept_op_complete<kqueue_socket>(
        *this, svc.socket_service(), resolve_via_getpeername, set_nosigpipe);
}

inline kqueue_acceptor::kqueue_acceptor(kqueue_acceptor_service& svc) noexcept
    : svc_(svc)
{
}

inline std::coroutine_handle<>
kqueue_acceptor::accept(
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

    // FreeBSD: Can use accept4(fd_, addr, addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC)
    int accepted =
        ::accept(fd_, reinterpret_cast<sockaddr*>(&peer_storage), &addrlen);

    if (accepted >= 0)
    {
        // Set non-blocking and close-on-exec on the accepted socket
        int flags = ::fcntl(accepted, F_GETFL, 0);
        if (flags == -1 || ::fcntl(accepted, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            int errn = errno;
            ::close(accepted);
            op.complete(errn, 0);
            op.impl_ptr = shared_from_this();
            svc_.post(&op);
            return std::noop_coroutine();
        }
        if (::fcntl(accepted, F_SETFD, FD_CLOEXEC) == -1)
        {
            int errn = errno;
            ::close(accepted);
            op.complete(errn, 0);
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
                // SO_NOSIGPIPE on accepted socket (macOS lacks MSG_NOSIGNAL)
                int one = 1;
                if (::setsockopt(
                        accepted, SOL_SOCKET, SO_NOSIGPIPE, &one,
                        sizeof(one)) == -1)
                {
                    int saved_errno = errno;
                    ::close(accepted);
                    if (ec)
                        *ec = make_err(saved_errno);
                    if (impl_out)
                        *impl_out = nullptr;
                }
                else
                {
                    // Resolve local endpoint via getsockname
                    sockaddr_storage local_storage{};
                    socklen_t local_len = sizeof(local_storage);
                    endpoint local_ep;
                    if (::getsockname(
                            accepted,
                            reinterpret_cast<sockaddr*>(&local_storage),
                            &local_len) == 0)
                        local_ep = from_sockaddr(local_storage);

                    auto* peer = setup_accepted_socket<kqueue_socket>(
                        *socket_svc, accepted, local_ep,
                        from_sockaddr(peer_storage));
                    if (ec)
                        *ec = {};
                    if (impl_out)
                        *impl_out = peer;
                }
                return dispatch_coro(ex, h);
            }
            else
            {
                ::close(accepted);
                if (ec)
                    *ec = make_err(ENOENT);
                if (impl_out)
                    *impl_out = nullptr;
                return dispatch_coro(ex, h);
            }
        }

        op.accepted_fd = accepted;
        op.complete(0, 0);
        op.impl_ptr = shared_from_this();
        svc_.post(&op);
        return std::noop_coroutine();
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
        svc_.work_started();
        op.impl_ptr = shared_from_this();

        bool perform_now = false;
        {
            std::lock_guard lock(desc_state_.mutex);
            if (desc_state_.read_ready)
            {
                desc_state_.read_ready = false;
                perform_now            = true;
            }
            else
            {
                desc_state_.read_op = &op;
            }
        }

        if (perform_now)
        {
            for (;;)
            {
                op.perform_io();
                if (op.errn != EAGAIN && op.errn != EWOULDBLOCK)
                {
                    svc_.post(&op);
                    svc_.work_finished();
                    break;
                }
                op.errn = 0;
                std::lock_guard lock(desc_state_.mutex);
                if (desc_state_.read_ready)
                {
                    desc_state_.read_ready = false;
                    continue;
                }
                desc_state_.read_op = &op;
                break;
            }
            return std::noop_coroutine();
        }

        if (op.cancelled.load(std::memory_order_acquire))
        {
            kqueue_op* claimed = nullptr;
            {
                std::lock_guard lock(desc_state_.mutex);
                if (desc_state_.read_op == &op)
                    claimed = std::exchange(desc_state_.read_op, nullptr);
            }
            if (claimed)
            {
                svc_.post(claimed);
                svc_.work_finished();
            }
        }
        return std::noop_coroutine();
    }

    op.complete(errno, 0);
    op.impl_ptr = shared_from_this();
    svc_.post(&op);
    return std::noop_coroutine();
}

inline void
kqueue_acceptor::cancel() noexcept
{
    do_cancel_single_op(acc_);
}

inline void
kqueue_acceptor::cancel_single_op(kqueue_op& op) noexcept
{
    do_cancel_single_op(op);
}

inline void
kqueue_acceptor::close_socket() noexcept
{
    do_close_socket();
}

inline kqueue_acceptor_service::kqueue_acceptor_service(
    capy::execution_context& ctx)
    : base_type(ctx)
{
}

inline kqueue_acceptor_service::~kqueue_acceptor_service() = default;

inline void
kqueue_acceptor_service::shutdown()
{
    do_shutdown();
}

inline io_object::implementation*
kqueue_acceptor_service::construct()
{
    return do_construct();
}

inline void
kqueue_acceptor_service::destroy(io_object::implementation* impl)
{
    do_destroy(impl);
}

inline void
kqueue_acceptor_service::close(io_object::handle& h)
{
    do_close(h);
}

inline std::error_code
kqueue_acceptor::set_option(
    int level, int optname, void const* data, std::size_t size) noexcept
{
    return posix::do_set_option(fd_, level, optname, data, size);
}

inline std::error_code
kqueue_acceptor::get_option(
    int level, int optname, void* data, std::size_t* size) const noexcept
{
    return posix::do_get_option(fd_, level, optname, data, size);
}

inline std::error_code
kqueue_acceptor_service::open_acceptor_socket(
    tcp_acceptor::implementation& impl, int family, int type, int protocol)
{
    auto* kq_impl = static_cast<kqueue_acceptor*>(&impl);
    kq_impl->close_socket();

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

    if (family == AF_INET6)
    {
        int val = 0; // dual-stack default
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
    }

    // SO_NOSIGPIPE on macOS (where MSG_NOSIGNAL doesn't exist)
#ifdef SO_NOSIGPIPE
    int nosig = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosig, sizeof(nosig));
#endif

    kq_impl->fd_ = fd;

    // Set up descriptor state but do NOT register with kqueue yet
    kq_impl->desc_state_.fd = fd;
    kq_impl->desc_state_.init_ops();

    return {};
}

inline std::error_code
kqueue_acceptor_service::bind_acceptor(
    tcp_acceptor::implementation& impl, endpoint ep)
{
    return do_bind_acceptor(impl, ep);
}

inline std::error_code
kqueue_acceptor_service::listen_acceptor(
    tcp_acceptor::implementation& impl, int backlog)
{
    return do_listen_acceptor(impl, backlog);
}

inline void
kqueue_acceptor_service::post(kqueue_op* op)
{
    do_post(op);
}

inline void
kqueue_acceptor_service::work_started() noexcept
{
    do_work_started();
}

inline void
kqueue_acceptor_service::work_finished() noexcept
{
    do_work_finished();
}

inline kqueue_socket_service*
kqueue_acceptor_service::socket_service() const noexcept
{
    return do_socket_service();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_KQUEUE

#endif // BOOST_COROSIO_NATIVE_DETAIL_KQUEUE_KQUEUE_ACCEPTOR_SERVICE_HPP
