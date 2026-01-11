//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_DETAIL_WIN_IOCP_SOCKETS_HPP
#define BOOST_COROSIO_DETAIL_WIN_IOCP_SOCKETS_HPP

#include <boost/corosio/detail/config.hpp>

#ifdef _WIN32

#include <boost/capy/affine.hpp>
#include <boost/capy/coro.hpp>
#include <boost/capy/execution_context.hpp>
#include <boost/capy/executor.hpp>
#include <boost/capy/intrusive_list.hpp>

#include <atomic>
#include <mutex>
#include <optional>
#include <stop_token>
#include <system_error>

namespace boost {
namespace corosio {
namespace detail {

class win_iocp_sockets;

/** Socket implementation for IOCP-based I/O.

    This class contains the state for a single socket, including
    pending read/write operations. It derives from intrusive_list::node
    to allow tracking by the win_iocp_sockets service.

    @note Internal implementation detail. Users interact with socket class.
*/
class socket_impl
    : public capy::intrusive_list<socket_impl>::node
{
    friend class win_iocp_sockets;

public:
    /** Read operation state.

        Tracks a pending asynchronous read operation with cancellation support.
    */
    struct read_op
        : capy::executor_work
    {
        /** Small invocable for stop_callback - avoids std::function overhead. */
        struct canceller
        {
            read_op* op;
            void operator()() const { op->cancel(); }
        };

        capy::coro h;
        capy::any_dispatcher d;
        std::atomic<bool> cancelled{false};
        std::error_code* ec_out = nullptr;
        std::optional<std::stop_callback<canceller>> stop_cb;

        void operator()() override
        {
            // Clear the stop callback before resuming
            stop_cb.reset();

            // Set error code if cancelled
            if (ec_out && cancelled.load(std::memory_order_acquire))
                *ec_out = std::make_error_code(std::errc::operation_canceled);

            d(h).resume();
        }

        void destroy() override
        {
            stop_cb.reset();
            // do not delete; owned by socket_impl
        }

        void cancel()
        {
            cancelled.store(true, std::memory_order_release);
        }

        void start(std::stop_token token)
        {
            cancelled.store(false, std::memory_order_release);
            stop_cb.reset();

            if (token.stop_possible())
                stop_cb.emplace(token, canceller{this});
        }
    };

    /** Construct a socket implementation.

        @param svc Reference to the owning sockets service.
    */
    explicit socket_impl(win_iocp_sockets& svc) noexcept
        : svc_(svc)
    {
    }

    /** Cancel any pending operations. */
    void cancel() noexcept
    {
        rd.cancel();
    }

    /** Release this implementation back to the service.

        Unregisters from the service and deallocates.
        After calling this, the socket_impl is destroyed.
    */
    void release();

    read_op rd;

private:
    win_iocp_sockets& svc_;
};

//------------------------------------------------------------------------------

/** Windows IOCP socket management service.

    This service owns all socket implementations and coordinates their
    lifecycle with the IOCP. It provides:

    - Socket implementation allocation and deallocation (with future recycling)
    - IOCP handle association
    - Graceful shutdown - destroys all implementations when io_context stops

    @par Thread Safety
    All public member functions are thread-safe.

    @note Only available on Windows platforms.
*/
class win_iocp_sockets
    : public capy::execution_context::service
{
public:
    using key_type = win_iocp_sockets;

    /** Construct the socket service.

        Obtains the IOCP handle from the scheduler service.

        @param ctx Reference to the owning execution_context.
    */
    explicit win_iocp_sockets(capy::execution_context& ctx);

    /** Destroy the socket service. */
    ~win_iocp_sockets();

    win_iocp_sockets(win_iocp_sockets const&) = delete;
    win_iocp_sockets& operator=(win_iocp_sockets const&) = delete;

    /** Shut down the service.

        Destroys all socket implementations.
        Called automatically when the execution_context is destroyed.
    */
    void shutdown() override;

    /** Create a new socket implementation.

        Allocates a socket_impl, registers it with the service,
        and associates it with the IOCP.

        @return Reference to the newly created implementation.
    */
    socket_impl& create_impl();

    /** Destroy a socket implementation.

        Unregisters the implementation from the service and deallocates it.
        Future versions may recycle implementations instead of deleting.

        @param impl Reference to the implementation to destroy.
    */
    void destroy_impl(socket_impl& impl);

    /** Return the IOCP handle.

        @return The Windows HANDLE to the I/O Completion Port.
    */
    void* native_handle() const noexcept { return iocp_; }

private:
    std::mutex mutex_;
    capy::intrusive_list<socket_impl> list_;
    void* iocp_;
};

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // _WIN32

#endif
