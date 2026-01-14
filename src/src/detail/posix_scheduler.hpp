//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_DETAIL_POSIX_SCHEDULER_HPP
#define BOOST_COROSIO_DETAIL_POSIX_SCHEDULER_HPP

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/detail/scheduler.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/core/intrusive_queue.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace boost {
namespace corosio {
namespace detail {

using op_queue = capy::intrusive_queue<capy::execution_context::handler>;

/** POSIX scheduler using condition variables.

    This scheduler implements the scheduler interface using standard
    C++ threading primitives (std::mutex, std::condition_variable).
    It manages a queue of handlers and provides blocking/non-blocking
    execution methods.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class posix_scheduler
    : public scheduler
    , public capy::execution_context::service
{
public:
    using key_type = scheduler;

    /** Construct the scheduler.

        @param ctx Reference to the owning execution_context.
        @param concurrency_hint Hint for expected thread count (unused).
    */
    posix_scheduler(
        capy::execution_context& ctx,
        int concurrency_hint = -1);

    ~posix_scheduler();

    posix_scheduler(posix_scheduler const&) = delete;
    posix_scheduler& operator=(posix_scheduler const&) = delete;

    void shutdown() override;
    void post(capy::any_coro h) const override;
    void post(capy::execution_context::handler* h) const override;
    void on_work_started() noexcept override;
    void on_work_finished() noexcept override;
    bool running_in_this_thread() const noexcept override;
    void stop() override;
    bool stopped() const noexcept override;
    void restart() override;
    std::size_t run() override;
    std::size_t run_one() override;
    std::size_t wait_one(long usec) override;
    std::size_t poll() override;
    std::size_t poll_one() override;

private:
    std::size_t do_one(long timeout_us);

    mutable std::mutex mutex_;
    mutable std::condition_variable wakeup_;
    mutable op_queue completed_ops_;
    mutable std::atomic<long> outstanding_work_;
    std::atomic<bool> stopped_;
    bool shutdown_;
};

} // namespace detail
} // namespace corosio
} // namespace boost

#endif
