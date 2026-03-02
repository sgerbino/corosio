//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_IO_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_IO_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/detail/buffer_param.hpp>
#include <boost/corosio/detail/dispatch_coro.hpp>
#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/executor_ref.hpp>

#include <coroutine>
#include <cstddef>
#include <stop_token>
#include <system_error>

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

/*
    Reactor Socket I/O
    ==================

    Shared connect/read_some/write_some logic for reactor socket
    backends (epoll, kqueue, select). Each backend delegates to
    these static template methods, injecting backend-specific
    behavior through:

    - Socket::on_register_read()  — select calls start_op; no-op elsewhere
    - Socket::on_register_write() — select calls start_op; no-op elsewhere
    - #ifdef MSG_NOSIGNAL          — sendmsg on Linux, writev on BSD

    All speculative I/O paths include EINTR retry loops.
*/

namespace boost::corosio::detail {

/** Shared I/O initiation for reactor socket backends.

    Each method follows a three-branch pattern:
    1. Speculative syscall succeeds and budget available — inline completion
    2. Budget exhausted — post completed op through scheduler queue
    3. EAGAIN — park op in descriptor_state via do_register_op()

    @par Thread Safety
    Methods must only be called from the thread owning the socket.
*/
struct reactor_socket_io
{
    /** Initiate an asynchronous connect.

        Tries ::connect() speculatively. On EINPROGRESS, registers
        with the reactor via do_register_op() and calls
        on_register_write().

        @tparam Socket Concrete socket type (e.g. epoll_socket).
    */
    template<typename Socket>
    static std::coroutine_handle<> do_connect(
        Socket& s,
        std::coroutine_handle<> h,
        capy::executor_ref ex,
        endpoint ep,
        std::stop_token token,
        std::error_code* ec)
    {
        auto& op = s.conn_;

        sockaddr_storage storage{};
        socklen_t addrlen = to_sockaddr(ep, socket_family(s.fd_), storage);
        int result =
            ::connect(s.fd_, reinterpret_cast<sockaddr*>(&storage), addrlen);

        if (result == 0)
        {
            sockaddr_storage local_storage{};
            socklen_t local_len = sizeof(local_storage);
            if (::getsockname(
                    s.fd_, reinterpret_cast<sockaddr*>(&local_storage),
                    &local_len) == 0)
                s.local_endpoint_ = from_sockaddr(local_storage);
            s.remote_endpoint_ = ep;
        }

        if (result == 0 || errno != EINPROGRESS)
        {
            int err = (result < 0) ? errno : 0;
            if (s.svc_.scheduler().try_consume_inline_budget())
            {
                *ec = err ? make_err(err) : std::error_code{};
                return dispatch_coro(ex, h);
            }
            op.reset();
            op.h               = h;
            op.ex              = ex;
            op.ec_out          = ec;
            op.fd              = s.fd_;
            op.target_endpoint = ep;
            op.start(token, &s);
            op.impl_ptr = s.shared_from_this();
            op.complete(err, 0);
            s.svc_.post(&op);
            return std::noop_coroutine();
        }

        // EINPROGRESS — register with reactor
        op.reset();
        op.h               = h;
        op.ex              = ex;
        op.ec_out          = ec;
        op.fd              = s.fd_;
        op.target_endpoint = ep;
        op.start(token, &s);
        op.impl_ptr = s.shared_from_this();

        s.do_register_op(
            op, s.desc_state_.connect_op, s.desc_state_.write_ready,
            s.desc_state_.connect_cancel_pending);
        s.on_register_write();
        return std::noop_coroutine();
    }

    /** Initiate an asynchronous read.

        Tries readv() speculatively with EINTR retry. On EAGAIN,
        registers with the reactor and calls on_register_read().

        @tparam Socket Concrete socket type.
    */
    template<typename Socket>
    static std::coroutine_handle<> do_read_some(
        Socket& s,
        std::coroutine_handle<> h,
        capy::executor_ref ex,
        buffer_param param,
        std::stop_token token,
        std::error_code* ec,
        std::size_t* bytes_out)
    {
        auto& op = s.rd_;
        op.reset();

        using read_op_type = std::remove_reference_t<decltype(op)>;
        capy::mutable_buffer bufs[read_op_type::max_buffers];
        op.iovec_count =
            static_cast<int>(param.copy_to(bufs, read_op_type::max_buffers));

        if (op.iovec_count == 0 || (op.iovec_count == 1 && bufs[0].size() == 0))
        {
            op.empty_buffer_read = true;
            op.h                 = h;
            op.ex                = ex;
            op.ec_out            = ec;
            op.bytes_out         = bytes_out;
            op.start(token, &s);
            op.impl_ptr = s.shared_from_this();
            op.complete(0, 0);
            s.svc_.post(&op);
            return std::noop_coroutine();
        }

        for (int i = 0; i < op.iovec_count; ++i)
        {
            op.iovecs[i].iov_base = bufs[i].data();
            op.iovecs[i].iov_len  = bufs[i].size();
        }

        // Speculative read with EINTR retry
        ssize_t n;
        do
        {
            n = ::readv(s.fd_, op.iovecs, op.iovec_count);
        }
        while (n < 0 && errno == EINTR);

        if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        {
            int err    = (n < 0) ? errno : 0;
            auto bytes = (n > 0) ? static_cast<std::size_t>(n) : std::size_t(0);

            if (s.svc_.scheduler().try_consume_inline_budget())
            {
                if (err)
                    *ec = make_err(err);
                else if (n == 0)
                    *ec = capy::error::eof;
                else
                    *ec = {};
                *bytes_out = bytes;
                return dispatch_coro(ex, h);
            }
            op.h         = h;
            op.ex        = ex;
            op.ec_out    = ec;
            op.bytes_out = bytes_out;
            op.start(token, &s);
            op.impl_ptr = s.shared_from_this();
            op.complete(err, bytes);
            s.svc_.post(&op);
            return std::noop_coroutine();
        }

        // EAGAIN — register with reactor
        op.h         = h;
        op.ex        = ex;
        op.ec_out    = ec;
        op.bytes_out = bytes_out;
        op.fd        = s.fd_;
        op.start(token, &s);
        op.impl_ptr = s.shared_from_this();

        s.do_register_op(
            op, s.desc_state_.read_op, s.desc_state_.read_ready,
            s.desc_state_.read_cancel_pending);
        s.on_register_read();
        return std::noop_coroutine();
    }

    /** Initiate an asynchronous write.

        On Linux uses sendmsg(MSG_NOSIGNAL); on macOS/BSD uses
        writev() (SO_NOSIGPIPE set at socket creation). On EAGAIN,
        registers with the reactor and calls on_register_write().

        @tparam Socket Concrete socket type.
    */
    template<typename Socket>
    static std::coroutine_handle<> do_write_some(
        Socket& s,
        std::coroutine_handle<> h,
        capy::executor_ref ex,
        buffer_param param,
        std::stop_token token,
        std::error_code* ec,
        std::size_t* bytes_out)
    {
        auto& op = s.wr_;
        op.reset();

        using write_op_type = std::remove_reference_t<decltype(op)>;
        capy::mutable_buffer bufs[write_op_type::max_buffers];
        op.iovec_count =
            static_cast<int>(param.copy_to(bufs, write_op_type::max_buffers));

        if (op.iovec_count == 0 || (op.iovec_count == 1 && bufs[0].size() == 0))
        {
            op.h         = h;
            op.ex        = ex;
            op.ec_out    = ec;
            op.bytes_out = bytes_out;
            op.start(token, &s);
            op.impl_ptr = s.shared_from_this();
            op.complete(0, 0);
            s.svc_.post(&op);
            return std::noop_coroutine();
        }

        for (int i = 0; i < op.iovec_count; ++i)
        {
            op.iovecs[i].iov_base = bufs[i].data();
            op.iovecs[i].iov_len  = bufs[i].size();
        }

        // Speculative write with EINTR retry
        ssize_t n = speculative_writev(s.fd_, op.iovecs, op.iovec_count);

        if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        {
            int err    = (n < 0) ? errno : 0;
            auto bytes = (n > 0) ? static_cast<std::size_t>(n) : std::size_t(0);

            if (s.svc_.scheduler().try_consume_inline_budget())
            {
                *ec        = err ? make_err(err) : std::error_code{};
                *bytes_out = bytes;
                return dispatch_coro(ex, h);
            }
            op.h         = h;
            op.ex        = ex;
            op.ec_out    = ec;
            op.bytes_out = bytes_out;
            op.start(token, &s);
            op.impl_ptr = s.shared_from_this();
            op.complete(err, bytes);
            s.svc_.post(&op);
            return std::noop_coroutine();
        }

        // EAGAIN — register with reactor
        op.h         = h;
        op.ex        = ex;
        op.ec_out    = ec;
        op.bytes_out = bytes_out;
        op.fd        = s.fd_;
        op.start(token, &s);
        op.impl_ptr = s.shared_from_this();

        s.do_register_op(
            op, s.desc_state_.write_op, s.desc_state_.write_ready,
            s.desc_state_.write_cancel_pending);
        s.on_register_write();
        return std::noop_coroutine();
    }

private:
    /// Platform-appropriate write: sendmsg(MSG_NOSIGNAL) or writev().
    static ssize_t speculative_writev(int fd, iovec* iovecs, int count) noexcept
    {
        ssize_t n;
#ifdef MSG_NOSIGNAL
        msghdr msg{};
        msg.msg_iov    = iovecs;
        msg.msg_iovlen = static_cast<std::size_t>(count);
        do
        {
            n = ::sendmsg(fd, &msg, MSG_NOSIGNAL);
        }
        while (n < 0 && errno == EINTR);
#else
        do
        {
            n = ::writev(fd, iovecs, count);
        }
        while (n < 0 && errno == EINTR);
#endif
        return n;
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_IO_HPP
