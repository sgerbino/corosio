//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_SOCKET_HPP
#define BOOST_COROSIO_SOCKET_HPP

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/detail/except.hpp>
#include <boost/capy/affine.hpp>
#include <boost/capy/execution_context.hpp>

#include <cassert>
#include <coroutine>
#include <cstddef>
#include <memory>
#include <stop_token>
#include <system_error>

namespace boost {
namespace corosio {
namespace detail { class socket_impl; }

/** An asynchronous socket for coroutine I/O.

    This class models an asynchronous socket that provides I/O operations
    returning awaitable types. It demonstrates the affine awaitable protocol
    where the awaitable receives the caller's executor for completion dispatch.

    @see async_read_some_t
*/
struct socket
{
    struct async_read_some_t
    {
        async_read_some_t(
            socket& s)
            : s_(s)
        {
        }

        bool await_ready() const noexcept
        {
            // Fast path: if already stopped, don't start the operation
            return token_.stop_requested();
        }

        std::error_code await_resume() const noexcept
        {
            if (token_.stop_requested())
                return std::make_error_code(std::errc::operation_canceled);
            return ec_;
        }

        // Affine awaitable: uses token from constructor
        template<capy::dispatcher Dispatcher>
        auto
        await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d) ->
                std::coroutine_handle<>
        {
            s_.do_read_some(h, d, token_, &ec_);
            return std::noop_coroutine();
        }

        // Stoppable awaitable: uses token from caller's coroutine chain
        template<capy::dispatcher Dispatcher>
        auto
        await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d,
            std::stop_token token) ->
                std::coroutine_handle<>
        {
            token_ = std::move(token);
            s_.do_read_some(h, d, token_, &ec_);
            return std::noop_coroutine();
        }

    private:
        socket& s_;
        std::stop_token token_;
        mutable std::error_code ec_;
    };

    BOOST_COROSIO_DECL
    ~socket();

    BOOST_COROSIO_DECL
    explicit socket(
        capy::execution_context& ctx);

    /** Move constructor.

        Transfers ownership of the socket from other.
        After the move, other.is_open() == false.

        @param other The socket to move from.
    */
    socket(socket&& other) noexcept
        : ctx_(other.ctx_)
        , impl_(other.impl_)
    {
        other.impl_ = nullptr;
    }

    /** Move assignment.

        Transfers ownership of the socket from other.
        If this socket was open, it is closed first.
        After the move, other.is_open() == false.

        @throws std::logic_error if other is on a different execution context.

        @param other The socket to move from.

        @return *this
    */
    socket& operator=(socket&& other)
    {
        if (this != &other)
        {
            if (ctx_ != other.ctx_)
                detail::throw_logic_error(
                    "cannot move socket across execution contexts");
            close();
            impl_ = other.impl_;
            other.impl_ = nullptr;
        }
        return *this;
    }

    socket(socket const&) = delete;
    socket& operator=(socket const&) = delete;

    /** Open the socket.

        Allocates the internal implementation if not already open.
        This must be called before initiating I/O operations.

        @note This is idempotent - calling on an already-open socket is a no-op.
    */
    BOOST_COROSIO_DECL
    void open();

    /** Close the socket.

        Releases the internal implementation. Pending operations are cancelled.
        The socket can be reopened by calling open() again.

        @note This is idempotent - calling on an already-closed socket is a no-op.
    */
    BOOST_COROSIO_DECL
    void close();

    /** Check if the socket is open.

        @return true if the socket has an allocated implementation.
    */
    bool is_open() const noexcept
    {
        return impl_ != nullptr;
    }

    /** Initiates an asynchronous read operation.

        @param token Optional stop token for cancellation support.
                     If the token's stop is requested, the operation
                     completes with operation_canceled error.

        @return An awaitable that completes with std::error_code.

        @pre is_open() == true
    */
    async_read_some_t
    async_read_some()
    {
        return async_read_some_t(*this);
    }

    /** Cancel any pending asynchronous operations.

        Pending operations will complete with operation_canceled error.
        This method is thread-safe.

        @pre is_open() == true
    */
    BOOST_COROSIO_DECL
    void cancel();

private:
    BOOST_COROSIO_DECL
    void do_read_some(
        std::coroutine_handle<>,
        capy::any_dispatcher,
        std::stop_token,
        std::error_code*);

    capy::execution_context* ctx_;
    detail::socket_impl* impl_ = nullptr;
};

} // namespace corosio
} // namespace boost

#endif
