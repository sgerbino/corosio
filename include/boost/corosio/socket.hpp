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
#include <boost/corosio/detail/socket_impl.hpp>
#include <boost/corosio/buffers_param.hpp>
#include <boost/corosio/tcp.hpp>
#include <boost/capy/affine.hpp>
#include <boost/capy/execution_context.hpp>
#include <boost/capy/executor.hpp>

#include <boost/system/error_code.hpp>

#include <cassert>
#include <coroutine>
#include <cstddef>
#include <stop_token>

namespace boost {
namespace corosio {

/** An asynchronous TCP socket for coroutine I/O.

    This class models an asynchronous socket that provides I/O operations
    returning awaitable types. It implements the affine awaitable protocol
    where the awaitable receives the caller's executor for completion dispatch.

    @par Example
    @code
    io_context ioc;
    socket s(ioc);
    s.open();
    co_await s.connect(tcp::endpoint(urls::ipv4_address::loopback(), 8080));
    char buf[1024];
    auto [ec, n] = co_await s.read_some(buffers::mutable_buffer(buf, sizeof(buf)));
    @endcode
*/
class socket
{
public:
    //--------------------------------------------------------------------------
    //
    // Awaitables
    //
    //--------------------------------------------------------------------------

    /** Awaitable for connect operations. */
    struct connect_awaitable
    {
        socket& s_;
        tcp::endpoint endpoint_;
        std::stop_token token_;
        mutable system::error_code ec_;

        connect_awaitable(socket& s, tcp::endpoint ep) noexcept
            : s_(s)
            , endpoint_(ep)
        {
        }

        bool await_ready() const noexcept
        {
            return token_.stop_requested();
        }

        system::error_code await_resume() const noexcept
        {
            if (token_.stop_requested())
                return make_error_code(system::errc::operation_canceled);
            return ec_;
        }

        template<capy::dispatcher Dispatcher>
        auto await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d) -> std::coroutine_handle<>
        {
            s_.impl_->connect(h, d, endpoint_, token_, &ec_);
            return std::noop_coroutine();
        }

        template<capy::dispatcher Dispatcher>
        auto await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d,
            std::stop_token token) -> std::coroutine_handle<>
        {
            token_ = std::move(token);
            s_.impl_->connect(h, d, endpoint_, token_, &ec_);
            return std::noop_coroutine();
        }
    };

    /** Awaitable for read operations.

        @tparam MutableBufferSequence The buffer sequence type.
    */
    template<class MutableBufferSequence>
    struct read_some_awaitable
    {
        socket& s_;
        MutableBufferSequence buffers_;
        std::stop_token token_;
        mutable system::error_code ec_;
        mutable std::size_t bytes_transferred_ = 0;

        read_some_awaitable(socket& s, MutableBufferSequence buffers) noexcept
            : s_(s)
            , buffers_(std::move(buffers))
        {
        }

        bool await_ready() const noexcept
        {
            return token_.stop_requested();
        }

        std::pair<system::error_code, std::size_t> await_resume() const noexcept
        {
            if (token_.stop_requested())
                return {make_error_code(system::errc::operation_canceled), 0};
            return {ec_, bytes_transferred_};
        }

        template<capy::dispatcher Dispatcher>
        auto await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d) -> std::coroutine_handle<>
        {
            buffers_param_impl param(buffers_);
            s_.impl_->read_some(h, d, param, token_, &ec_, &bytes_transferred_);
            return std::noop_coroutine();
        }

        template<capy::dispatcher Dispatcher>
        auto await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d,
            std::stop_token token) -> std::coroutine_handle<>
        {
            token_ = std::move(token);
            buffers_param_impl param(buffers_);
            s_.impl_->read_some(h, d, param, token_, &ec_, &bytes_transferred_);
            return std::noop_coroutine();
        }
    };

    /** Awaitable for write operations.

        @tparam ConstBufferSequence The buffer sequence type.
    */
    template<class ConstBufferSequence>
    struct write_some_awaitable
    {
        socket& s_;
        ConstBufferSequence buffers_;
        std::stop_token token_;
        mutable system::error_code ec_;
        mutable std::size_t bytes_transferred_ = 0;

        write_some_awaitable(socket& s, ConstBufferSequence buffers) noexcept
            : s_(s)
            , buffers_(std::move(buffers))
        {
        }

        bool await_ready() const noexcept
        {
            return token_.stop_requested();
        }

        std::pair<system::error_code, std::size_t> await_resume() const noexcept
        {
            if (token_.stop_requested())
                return {make_error_code(system::errc::operation_canceled), 0};
            return {ec_, bytes_transferred_};
        }

        template<capy::dispatcher Dispatcher>
        auto await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d) -> std::coroutine_handle<>
        {
            buffers_param_impl param(buffers_);
            s_.impl_->write_some(h, d, param, token_, &ec_, &bytes_transferred_);
            return std::noop_coroutine();
        }

        template<capy::dispatcher Dispatcher>
        auto await_suspend(
            std::coroutine_handle<> h,
            Dispatcher const& d,
            std::stop_token token) -> std::coroutine_handle<>
        {
            token_ = std::move(token);
            buffers_param_impl param(buffers_);
            s_.impl_->write_some(h, d, param, token_, &ec_, &bytes_transferred_);
            return std::noop_coroutine();
        }
    };

    //--------------------------------------------------------------------------
    //
    // Construction / Assignment
    //
    //--------------------------------------------------------------------------

    BOOST_COROSIO_DECL
    ~socket();

    BOOST_COROSIO_DECL
    explicit socket(capy::execution_context& ctx);

    /** Construct from an executor.

        @param ex The executor whose context will own the socket.
    */
    template<capy::executor Executor>
    explicit socket(Executor const& ex)
        : socket(ex.context())
    {
    }

    /** Move constructor. */
    socket(socket&& other) noexcept
        : ctx_(other.ctx_)
        , impl_(other.impl_)
    {
        other.impl_ = nullptr;
    }

    /** Move assignment. */
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

    //--------------------------------------------------------------------------
    //
    // Operations
    //
    //--------------------------------------------------------------------------

    /** Open the socket.

        Creates an IPv4 TCP socket and associates it with the IOCP.
        This must be called before initiating I/O operations.

        @throws std::system_error on failure.
    */
    BOOST_COROSIO_DECL
    void open();

    /** Close the socket.

        Releases the internal implementation. Pending operations are cancelled.
    */
    BOOST_COROSIO_DECL
    void close();

    /** Check if the socket is open. */
    bool is_open() const noexcept
    {
        return impl_ != nullptr;
    }

    /** Initiate an asynchronous connect operation.

        @param ep The endpoint to connect to.
        @return An awaitable that completes with system::error_code.
    */
    auto connect(tcp::endpoint ep)
    {
        assert(impl_ != nullptr);
        return connect_awaitable(*this, ep);
    }

    /** Initiate an asynchronous read operation.

        @param buffers The buffers to read into.
        @return An awaitable that completes with (error_code, bytes_transferred).
    */
    template<class MutableBufferSequence>
    auto read_some(MutableBufferSequence const& buffers)
    {
        assert(impl_ != nullptr);
        return read_some_awaitable<MutableBufferSequence>(*this, buffers);
    }

    /** Initiate an asynchronous write operation.

        @param buffers The buffers to write from.
        @return An awaitable that completes with (error_code, bytes_transferred).
    */
    template<class ConstBufferSequence>
    auto write_some(ConstBufferSequence const& buffers)
    {
        assert(impl_ != nullptr);
        return write_some_awaitable<ConstBufferSequence>(*this, buffers);
    }

    /** Cancel any pending asynchronous operations. */
    BOOST_COROSIO_DECL
    void cancel();

    /** Return the execution context. */
    auto
    context() const noexcept ->
        capy::execution_context&
    {
        return *ctx_;
    }

private:
    friend class tcp::acceptor;

    capy::execution_context* ctx_;
    detail::socket_impl* impl_ = nullptr;
};

} // namespace corosio
} // namespace boost

#endif
