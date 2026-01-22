//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_DETAIL_EPOLL_RESOLVER_SERVICE_HPP
#define BOOST_COROSIO_DETAIL_EPOLL_RESOLVER_SERVICE_HPP

#include "src/detail/config_backend.hpp"

#if defined(BOOST_COROSIO_BACKEND_EPOLL)

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/resolver_results.hpp>
#include <boost/capy/ex/executor_ref.hpp>
#include <boost/capy/io_awaitable.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/coro.hpp>
#include <boost/capy/error.hpp>
#include "src/detail/intrusive.hpp"
#include "src/detail/scheduler_op.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <unordered_map>

/*
    Epoll Resolver Implementation
    =============================

    POSIX getaddrinfo() is a blocking call that cannot be monitored with epoll.
    We use a worker thread approach: each resolution spawns a dedicated thread
    that runs the blocking call and posts completion back to the scheduler.

    Thread-per-resolution Design
    ----------------------------
    Simple, no thread pool complexity. DNS lookups are infrequent enough that
    thread creation overhead is acceptable. Detached threads self-manage;
    shared_ptr capture keeps impl alive until completion.

    Cancellation
    ------------
    getaddrinfo() cannot be interrupted mid-call. We use an atomic flag to
    indicate cancellation was requested. The worker thread checks this flag
    after getaddrinfo() returns and reports the appropriate error.

    Impl Lifetime with shared_ptr
    -----------------------------
    Same pattern as sockets.hpp. The service owns impls via shared_ptr maps
    keyed by raw pointer for O(1) lookup and removal. Worker threads capture
    shared_from_this() to keep the impl alive until completion. The intrusive_list
    provides fast iteration for shutdown cleanup.
*/

namespace boost {
namespace corosio {
namespace detail {

class epoll_scheduler;
class epoll_resolver_service;
class epoll_resolver_impl;

//------------------------------------------------------------------------------

/** Resolve operation state for epoll backend.

    Inherits from scheduler_op (not epoll_op) because DNS resolution doesn't
    use epoll file descriptors - completion is posted from a worker thread.
*/
struct epoll_resolve_op : scheduler_op
{
    struct canceller
    {
        epoll_resolve_op* op;
        void operator()() const noexcept { op->request_cancel(); }
    };

    // Coroutine state
    capy::coro h;
    capy::executor_ref d;

    // Output parameters
    system::error_code* ec_out = nullptr;
    resolver_results* out = nullptr;

    // Input parameters (owned copies for thread safety)
    std::string host;
    std::string service;
    resolve_flags flags = resolve_flags::none;

    // Result storage (populated by worker thread)
    resolver_results stored_results;
    int gai_error = 0;

    // Thread coordination
    std::atomic<bool> cancelled{false};
    std::optional<std::stop_callback<canceller>> stop_cb;

    // Back-reference
    epoll_resolver_impl* impl = nullptr;

    epoll_resolve_op()
    {
        data_ = this;
    }

    void reset() noexcept;
    void operator()() override;
    void destroy() override;
    void request_cancel() noexcept;
    void start(std::stop_token token);
};

//------------------------------------------------------------------------------

/** Resolver implementation for epoll backend.

    Uses worker threads to run blocking getaddrinfo() and posts completion
    to the scheduler. Supports cancellation via atomic flag.
*/
class epoll_resolver_impl
    : public resolver::resolver_impl
    , public std::enable_shared_from_this<epoll_resolver_impl>
    , public intrusive_list<epoll_resolver_impl>::node
{
    friend class epoll_resolver_service;

public:
    explicit epoll_resolver_impl(epoll_resolver_service& svc) noexcept
        : svc_(svc)
    {
    }

    void release() override;

    void resolve(
        std::coroutine_handle<>,
        capy::executor_ref,
        std::string_view host,
        std::string_view service,
        resolve_flags flags,
        std::stop_token,
        system::error_code*,
        resolver_results*) override;

    void cancel() noexcept;

    epoll_resolve_op op_;

private:
    epoll_resolver_service& svc_;
};

//------------------------------------------------------------------------------

/** Linux epoll resolver management service.

    This service owns all resolver implementations and coordinates their
    lifecycle. It provides:

    - Resolver implementation allocation and deallocation
    - Async DNS resolution via worker threads calling getaddrinfo()
    - Graceful shutdown - destroys all implementations when io_context stops

    @par Thread Safety
    All public member functions are thread-safe.
*/
class epoll_resolver_service
    : public capy::execution_context::service
{
public:
    using key_type = epoll_resolver_service;

    /** Construct the resolver service.

        @param ctx Reference to the owning execution_context.
    */
    explicit epoll_resolver_service(capy::execution_context& ctx);

    /** Destroy the resolver service. */
    ~epoll_resolver_service();

    epoll_resolver_service(epoll_resolver_service const&) = delete;
    epoll_resolver_service& operator=(epoll_resolver_service const&) = delete;

    /** Shut down the service. */
    void shutdown() override;

    /** Create a new resolver implementation. */
    epoll_resolver_impl& create_impl();

    /** Destroy a resolver implementation. */
    void destroy_impl(epoll_resolver_impl& impl);

    /** Post an operation for completion. */
    void post(scheduler_op* op);

    /** Notify scheduler of pending I/O work. */
    void work_started() noexcept;

    /** Notify scheduler that I/O work completed. */
    void work_finished() noexcept;

private:
    epoll_scheduler& sched_;
    std::mutex mutex_;

    intrusive_list<epoll_resolver_impl> resolver_list_;
    std::unordered_map<epoll_resolver_impl*,
        std::shared_ptr<epoll_resolver_impl>> resolver_ptrs_;
};

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // BOOST_COROSIO_BACKEND_EPOLL

#endif // BOOST_COROSIO_DETAIL_EPOLL_RESOLVER_SERVICE_HPP
