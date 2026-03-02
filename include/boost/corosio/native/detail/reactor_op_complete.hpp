//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_OP_COMPLETE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_OP_COMPLETE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/endpoint_convert.hpp>

#include <boost/capy/error.hpp>

#include <netinet/in.h>
#include <sys/socket.h>

#include <unistd.h>

/*
    Reactor Operation Completion
    =============================

    Shared completion dispatch for read, write, connect, and accept
    operations. The caller must reset the inline budget before calling
    these — the budget reset path varies per-backend.
*/

namespace boost::corosio::detail {

/** Complete a read or write operation.

    Maps error/cancelled/EOF state to ec_out, sets bytes_out, then
    resumes the waiting coroutine. Moves impl_ptr to a local to
    prevent use-after-free if the coroutine destroys the socket.

    @par Preconditions
    Caller has already called reset_inline_budget().

    @param op The operation to complete.
*/
template<typename Op>
inline void
reactor_io_op_complete(Op& op) noexcept
{
    op.stop_cb.reset();

    if (op.ec_out)
    {
        if (op.cancelled.load(std::memory_order_acquire))
            *op.ec_out = capy::error::canceled;
        else if (op.errn != 0)
            *op.ec_out = make_err(op.errn);
        else if (op.is_read_operation() && op.bytes_transferred == 0)
            *op.ec_out = capy::error::eof;
        else
            *op.ec_out = {};
    }

    if (op.bytes_out)
        *op.bytes_out = op.bytes_transferred;

    // Move to stack before resuming — coroutine may close the socket,
    // releasing the last ref. Local prevents use-after-free.
    capy::executor_ref saved_ex(std::move(op.ex));
    std::coroutine_handle<> saved_h(std::move(op.h));
    auto prevent_premature_destruction = std::move(op.impl_ptr);
    dispatch_coro(saved_ex, saved_h).resume();
}

/** Complete a connect operation.

    Caches local and remote endpoints on success, maps error state
    to ec_out, then resumes the waiting coroutine.

    @par Preconditions
    Caller has already called reset_inline_budget().

    @tparam Socket The concrete socket type (for endpoint caching).
    @param op The connect operation to complete.
*/
template<typename Socket, typename Op>
inline void
reactor_connect_op_complete(Op& op) noexcept
{
    op.stop_cb.reset();

    bool success =
        (op.errn == 0 && !op.cancelled.load(std::memory_order_acquire));

    if (success && op.socket_impl_)
    {
        endpoint local_ep;
        sockaddr_storage local_storage{};
        socklen_t local_len = sizeof(local_storage);
        if (::getsockname(
                op.fd, reinterpret_cast<sockaddr*>(&local_storage),
                &local_len) == 0)
            local_ep = from_sockaddr(local_storage);
        static_cast<Socket*>(op.socket_impl_)
            ->set_endpoints(local_ep, op.target_endpoint);
    }

    if (op.ec_out)
    {
        if (op.cancelled.load(std::memory_order_acquire))
            *op.ec_out = capy::error::canceled;
        else if (op.errn != 0)
            *op.ec_out = make_err(op.errn);
        else
            *op.ec_out = {};
    }

    capy::executor_ref saved_ex(std::move(op.ex));
    std::coroutine_handle<> saved_h(std::move(op.h));
    auto prevent_premature_destruction = std::move(op.impl_ptr);
    dispatch_coro(saved_ex, saved_h).resume();
}

/** Construct a peer socket for an accepted fd.

    Initializes the socket impl, registers the fd with the scheduler,
    and sets both endpoints.

    @tparam Socket Concrete socket type (e.g. epoll_socket).
    @tparam SocketService Service that owns the socket impls.

    @param svc Service to construct the new socket from.
    @param fd The accepted file descriptor.
    @param local_ep Local endpoint of the accepted connection.
    @param remote_ep Remote endpoint of the accepted connection.

    @return Pointer to the constructed socket impl.
*/
template<typename Socket, typename SocketService>
inline Socket*
setup_accepted_socket(
    SocketService& svc, int fd, endpoint local_ep, endpoint remote_ep) noexcept
{
    auto& impl = static_cast<Socket&>(*svc.construct());
    impl.set_socket(fd);
    impl.desc_state_.fd = fd;
    impl.desc_state_.init_ops();
    svc.scheduler().register_descriptor(fd, &impl.desc_state_);
    impl.set_endpoints(local_ep, remote_ep);
    return &impl;
}

// Default resolve-remote: read peer address from op.peer_storage
struct resolve_remote_from_op
{
    template<typename Op>
    endpoint operator()(Op const& op, int) const noexcept
    {
        return from_sockaddr(op.peer_storage);
    }
};

// Default post-accept hook: no-op
struct post_accept_noop
{
    std::error_code operator()(int) const noexcept
    {
        return {};
    }
};

/** Complete an accept operation.

    Handles error/cancelled mapping, peer socket construction via
    setup_accepted_socket, and coroutine resumption. Backend-specific
    behavior is injected through two callables:

    - ResolveRemote: `endpoint(Op const& op, int fd)` — resolves the
      remote endpoint. Default reads from `op.peer_storage`.
    - PostAccept: `error_code(int fd)` — called after registration but
      before setting endpoints. Default is a no-op.

    @par Preconditions
    Caller has already called reset_inline_budget().

    @tparam Socket Concrete socket type.
    @tparam SocketService Service that owns socket impls.
    @param op The accept operation to complete.
    @param socket_svc Socket service for constructing peer sockets.
    @param resolve_remote Callable to resolve the remote endpoint.
    @param post_accept Callable for post-registration setup.
*/
template<
    typename Socket,
    typename SocketService,
    typename Op,
    typename ResolveRemote = resolve_remote_from_op,
    typename PostAccept    = post_accept_noop>
inline void
reactor_accept_op_complete(
    Op& op,
    SocketService* socket_svc,
    ResolveRemote resolve_remote = {},
    PostAccept post_accept       = {}) noexcept
{
    op.stop_cb.reset();

    bool success =
        (op.errn == 0 && !op.cancelled.load(std::memory_order_acquire));

    if (op.ec_out)
    {
        if (op.cancelled.load(std::memory_order_acquire))
            *op.ec_out = capy::error::canceled;
        else if (op.errn != 0)
            *op.ec_out = make_err(op.errn);
        else
            *op.ec_out = {};
    }

    if (success && op.accepted_fd >= 0 && socket_svc)
    {
        auto& impl = static_cast<Socket&>(*socket_svc->construct());
        impl.set_socket(op.accepted_fd);
        impl.desc_state_.fd = op.accepted_fd;
        impl.desc_state_.init_ops();
        socket_svc->scheduler().register_descriptor(
            op.accepted_fd, &impl.desc_state_);

        std::error_code post_ec = post_accept(op.accepted_fd);
        if (post_ec)
        {
            if (op.ec_out)
                *op.ec_out = post_ec;
            socket_svc->destroy(&impl);
            op.accepted_fd = -1;
            if (op.impl_out)
                *op.impl_out = nullptr;
        }
        else
        {
            // Resolve endpoints
            endpoint local_ep;
            sockaddr_storage local_storage{};
            socklen_t local_len = sizeof(local_storage);
            if (::getsockname(
                    op.accepted_fd, reinterpret_cast<sockaddr*>(&local_storage),
                    &local_len) == 0)
                local_ep = from_sockaddr(local_storage);

            endpoint remote_ep = resolve_remote(op, op.accepted_fd);
            impl.set_endpoints(local_ep, remote_ep);

            if (op.impl_out)
                *op.impl_out = &impl;
            op.accepted_fd = -1;
        }
    }
    else
    {
        if (op.accepted_fd >= 0)
        {
            ::close(op.accepted_fd);
            op.accepted_fd = -1;
        }
        if (op.impl_out)
            *op.impl_out = nullptr;
    }

    capy::executor_ref saved_ex(std::move(op.ex));
    std::coroutine_handle<> saved_h(std::move(op.h));
    auto prevent_premature_destruction = std::move(op.impl_ptr);
    dispatch_coro(saved_ex, saved_h).resume();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_OP_COMPLETE_HPP
