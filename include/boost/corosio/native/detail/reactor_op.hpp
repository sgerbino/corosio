//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_OP_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_OP_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/io/io_object.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/capy/ex/executor_ref.hpp>
#include <boost/corosio/detail/scheduler_op.hpp>

#include <unistd.h>
#include <errno.h>

#include <atomic>
#include <coroutine>
#include <cstddef>
#include <memory>
#include <optional>
#include <stop_token>
#include <system_error>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

/*
    Reactor Operation Templates
    ============================

    Shared operation state templates for the reactor backends (epoll, kqueue,
    select). Each backend defines a traits struct that provides the
    socket and acceptor types:

        struct epoll_backend {
            using socket_type   = epoll_socket;
            using acceptor_type = epoll_acceptor;
        };

    The base op, connect, read, write, and accept operation structs are
    parameterized on this backend type. Backend-specific code (perform_io,
    operator(), cancel) is overridden in final derived classes.

    operator()() inherits a default empty body from scheduler_op
    and is overridden by the final backend op classes.

    cancel() has a default implementation on each typed op template
    (connect, read, write, accept) that delegates to the owning
    socket or acceptor impl. Backends only override cancel() if
    they need different behavior.

    Operation Lifetime
    ------------------
    Each async I/O operation uses a fixed slot in the socket/acceptor impl
    (conn_, rd_, wr_, acc_). Only one operation of each type can be pending
    per socket at a time. The `impl_ptr` member holds a shared_ptr to the
    owning impl, keeping it alive until the op completes.
*/

namespace boost::corosio::detail {

/** Base operation for reactor I/O backends.

    Holds all state shared across epoll, kqueue, and select operations:
    coroutine handle, executor, error/bytes output, cancellation support,
    and impl lifetime management.

    cancel() is pure virtual here; default implementations live on
    each typed op template (connect, read, write, accept).

    @tparam Backend Traits struct providing socket_type and acceptor_type.
*/
template<typename Backend>
struct reactor_op : scheduler_op
{
    using socket_type   = typename Backend::socket_type;
    using acceptor_type = typename Backend::acceptor_type;

    /// Stop-token cancellation callback.
    struct canceller
    {
        reactor_op* op;
        void operator()() const noexcept;
    };

    std::coroutine_handle<> h;
    capy::executor_ref ex;
    std::error_code* ec_out = nullptr;
    std::size_t* bytes_out  = nullptr;

    int fd                        = -1;
    int errn                      = 0;
    std::size_t bytes_transferred = 0;

    std::atomic<bool> cancelled{false};
    std::optional<std::stop_callback<canceller>> stop_cb;

    /// Prevents use-after-free when socket is closed with pending ops.
    std::shared_ptr<void> impl_ptr;

    /// For stop_token cancellation — pointer to owning socket/acceptor impl.
    socket_type* socket_impl_     = nullptr;
    acceptor_type* acceptor_impl_ = nullptr;

    reactor_op() = default;

    void reset() noexcept
    {
        fd                = -1;
        errn              = 0;
        bytes_transferred = 0;
        cancelled.store(false, std::memory_order_relaxed);
        impl_ptr.reset();
        socket_impl_   = nullptr;
        acceptor_impl_ = nullptr;
    }

    virtual bool is_read_operation() const noexcept
    {
        return false;
    }

    /// Must be overridden by final backend op classes.
    virtual void cancel() noexcept = 0;

    void destroy() override
    {
        stop_cb.reset();
        impl_ptr.reset();
    }

    void request_cancel() noexcept
    {
        cancelled.store(true, std::memory_order_release);
    }

    /// Arm stop-token callback for a socket-owned operation.
    void start(std::stop_token const& token, socket_type* impl)
    {
        cancelled.store(false, std::memory_order_release);
        stop_cb.reset();
        socket_impl_   = impl;
        acceptor_impl_ = nullptr;

        if (token.stop_possible())
            stop_cb.emplace(token, canceller{this});
    }

    /// Arm stop-token callback for an acceptor-owned operation.
    void start(std::stop_token const& token, acceptor_type* impl)
    {
        cancelled.store(false, std::memory_order_release);
        stop_cb.reset();
        socket_impl_   = nullptr;
        acceptor_impl_ = impl;

        if (token.stop_possible())
            stop_cb.emplace(token, canceller{this});
    }

    void complete(int err, std::size_t bytes) noexcept
    {
        errn              = err;
        bytes_transferred = bytes;
    }

    virtual void perform_io() noexcept {}
};

template<typename Backend>
inline void
reactor_op<Backend>::canceller::operator()() const noexcept
{
    op->cancel();
}

/** Connect operation shared state.

    The connect completion status is always retrieved via SO_ERROR,
    which is identical across all reactor backends.

    @tparam Backend Traits struct providing socket_type and acceptor_type.
*/
template<typename Backend>
struct reactor_connect_op : reactor_op<Backend>
{
    endpoint target_endpoint;

    void reset() noexcept
    {
        reactor_op<Backend>::reset();
        target_endpoint = endpoint{};
    }

    void cancel() noexcept override
    {
        if (this->socket_impl_)
            this->socket_impl_->cancel_single_op(*this);
        else
            this->request_cancel();
    }

    /// Retrieve connect result via SO_ERROR (identical across backends).
    void perform_io() noexcept override
    {
        int err       = 0;
        socklen_t len = sizeof(err);
        if (::getsockopt(this->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
            err = errno;
        this->complete(err, 0);
    }
};

/** Read operation shared state.

    Contains the iovec buffer array and empty-buffer tracking.
    perform_io() uses readv() with EINTR retry, shared across
    all reactor backends.

    @tparam Backend Traits struct providing socket_type and acceptor_type.
*/
template<typename Backend>
struct reactor_read_op : reactor_op<Backend>
{
    static constexpr std::size_t max_buffers = 16;
    iovec iovecs[max_buffers];
    int iovec_count        = 0;
    bool empty_buffer_read = false;

    void cancel() noexcept override
    {
        if (this->socket_impl_)
            this->socket_impl_->cancel_single_op(*this);
        else
            this->request_cancel();
    }

    bool is_read_operation() const noexcept override
    {
        return !empty_buffer_read;
    }

    void perform_io() noexcept override
    {
        ssize_t n;
        do
        {
            n = ::readv(this->fd, iovecs, iovec_count);
        }
        while (n < 0 && errno == EINTR);

        if (n >= 0)
            this->complete(0, static_cast<std::size_t>(n));
        else
            this->complete(errno, 0);
    }

    void reset() noexcept
    {
        reactor_op<Backend>::reset();
        iovec_count       = 0;
        empty_buffer_read = false;
    }
};

/** Write operation shared state.

    Contains the iovec buffer array. On platforms with MSG_NOSIGNAL
    (Linux), a default sendmsg perform_io() is provided. Kqueue
    overrides with writev (SO_NOSIGPIPE set at socket creation).

    @tparam Backend Traits struct providing socket_type and acceptor_type.
*/
template<typename Backend>
struct reactor_write_op : reactor_op<Backend>
{
    static constexpr std::size_t max_buffers = 16;
    iovec iovecs[max_buffers];
    int iovec_count = 0;

    void cancel() noexcept override
    {
        if (this->socket_impl_)
            this->socket_impl_->cancel_single_op(*this);
        else
            this->request_cancel();
    }

#ifdef MSG_NOSIGNAL
    void perform_io() noexcept override
    {
        msghdr msg{};
        msg.msg_iov    = iovecs;
        msg.msg_iovlen = static_cast<std::size_t>(iovec_count);

        ssize_t n;
        do
        {
            n = ::sendmsg(this->fd, &msg, MSG_NOSIGNAL);
        }
        while (n < 0 && errno == EINTR);

        if (n >= 0)
            this->complete(0, static_cast<std::size_t>(n));
        else
            this->complete(errno, 0);
    }
#endif

    void reset() noexcept
    {
        reactor_op<Backend>::reset();
        iovec_count = 0;
    }
};

/** Accept operation shared state.

    Contains the accepted fd, output pointer, and peer address storage.
    perform_io() is backend-specific (accept4 vs accept+fcntl).

    @tparam Backend Traits struct providing socket_type and acceptor_type.
*/
template<typename Backend>
struct reactor_accept_op : reactor_op<Backend>
{
    int accepted_fd                      = -1;
    io_object::implementation** impl_out = nullptr;
    sockaddr_storage peer_storage{};

    void cancel() noexcept override
    {
        if (this->acceptor_impl_)
            this->acceptor_impl_->cancel_single_op(*this);
        else
            this->request_cancel();
    }

    void reset() noexcept
    {
        reactor_op<Backend>::reset();
        accepted_fd  = -1;
        impl_out     = nullptr;
        peer_storage = {};
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_OP_HPP
