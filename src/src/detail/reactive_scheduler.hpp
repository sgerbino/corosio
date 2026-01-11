//
// Copyright (c) 2025 Vinnie Falco (vinnie.falco@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_DETAIL_REACTIVE_SCHEDULER_HPP
#define BOOST_COROSIO_DETAIL_REACTIVE_SCHEDULER_HPP

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/capy/execution_context.hpp>
#include <boost/capy/executor.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>

namespace boost {
namespace corosio {
namespace detail {

// Forward declaration for reactor (placeholder for future implementation)
class reactor;

/** Portable scheduler using mutex and condition variable.

    This scheduler provides a portable implementation that works on
    all platforms. It uses a mutex-protected work queue and condition
    variable for thread synchronization.

    @tparam isUnsafe When true, skips locking in certain operations.
        Only use when all operations are guaranteed to be single-threaded.

    @par Thread Safety
    When isUnsafe is false, this implementation is thread-safe.
    Multiple threads may call post() concurrently, and multiple
    threads may call run() to dequeue and execute work items.

    @see detail::scheduler
*/
template<bool isUnsafe = false>
class reactive_scheduler
    : public scheduler
    , public capy::execution_context::service
{
public:
    using key_type = scheduler;

    /** Constructs a reactive scheduler.

        @param ctx Reference to the owning execution_context.
        @param one_thread When true, enables thread-local private queue
            optimization for handlers posted from within run().
    */
    explicit reactive_scheduler(
        capy::execution_context& ctx,
        unsigned concurrency_hint);

    /** Destroys the scheduler.

        Any pending work items are destroyed without execution.
    */
    ~reactive_scheduler();

    reactive_scheduler(reactive_scheduler const&) = delete;
    reactive_scheduler& operator=(reactive_scheduler const&) = delete;

    /** Shuts down the scheduler.

        Destroys any remaining work items without executing them.
    */
    void shutdown() override;

    /** Initializes the reactor task.

        Called by I/O objects to lazily install the reactor. The first
        call creates the reactor and inserts the task sentinel into
        the work queue.
    */
    void init_task();

    /** Posts a coroutine for later execution.

        @param h The coroutine handle to post.
    */
    void post(capy::coro h) const override;

    /** Posts a work item for later execution.

        When one_thread_ is true and called from within run(), uses
        a fast path that pushes to a thread-local private queue
        without acquiring the mutex.

        @param w Pointer to the work item. Ownership is transferred
                 to the scheduler.

        @par Thread Safety
        When isUnsafe is false, this function is thread-safe.
    */
    void post(capy::executor_work* w) const override;

    /** Queue a coroutine for deferred execution.

        This is semantically identical to `post`, but conveys that
        `h` is a continuation of the current call context.

        @param h The coroutine handle to defer.

        @par Thread Safety
        When isUnsafe is false, this function is thread-safe.
    */
    void defer(capy::coro h) const override;

    /** Informs the scheduler that work is beginning.

        This increments the outstanding work count. Must be paired
        with on_work_finished().

        @par Thread Safety
        When isUnsafe is false, this function is thread-safe.
    */
    void on_work_started() noexcept override;

    /** Informs the scheduler that work has completed.

        This decrements the outstanding work count.

        @par Thread Safety
        When isUnsafe is false, this function is thread-safe.
    */
    void on_work_finished() noexcept override;

    /** Check if the current thread is running this scheduler.

        @return true if run() is being called on this thread.
    */
    bool running_in_this_thread() const noexcept override;

    /** Signal the scheduler to stop processing.

        This causes run() to return as soon as possible.
    */
    void stop() override;

    /** Return whether the scheduler has been stopped.

        @return true if stop() has been called and restart()
            has not been called since.
    */
    bool stopped() const noexcept override;

    /** Restart the scheduler after being stopped.

        This function must be called before run() can be called
        again after stop() has been called.
    */
    void restart() override;

    /** Processes pending work items.

        @param ec Set to indicate any error.

        @return The number of handlers executed.
    */
    std::size_t run(system::error_code& ec) override;

    /** Processes at most one pending work item.

        Blocks until one work item is executed or stop() is called.

        @param ec Set to indicate any error.

        @return The number of handlers executed (0 or 1).
    */
    std::size_t run_one(system::error_code& ec) override;

    /** Processes at most one pending work item with timeout.

        @param usec Timeout in microseconds.
        @param ec Set to indicate any error.

        @return The number of handlers executed (0 or 1).
    */
    std::size_t run_one(long usec, system::error_code& ec) override;

    /** Wait for at most one completion without executing.

        @param usec Timeout in microseconds.
        @param ec Set to indicate any error.

        @return The number of completions available (0 or 1).
    */
    std::size_t wait_one(long usec, system::error_code& ec) override;

    /** Processes work items for the specified duration.

        @param rel_time The duration for which to process work.

        @return The number of handlers executed.
    */
    std::size_t run_for(std::chrono::steady_clock::duration rel_time) override;

    /** Processes work items until the specified time.

        @param abs_time The time point until which to process work.

        @return The number of handlers executed.
    */
    std::size_t run_until(std::chrono::steady_clock::time_point abs_time) override;

    /** Processes all ready work items without blocking.

        @param ec Set to indicate any error.

        @return The number of handlers executed.
    */
    std::size_t poll(system::error_code& ec) override;

    /** Processes at most one ready work item without blocking.

        @param ec Set to indicate any error.

        @return The number of handlers executed (0 or 1).
    */
    std::size_t poll_one(system::error_code& ec) override;

private:
    struct thread_info;

    template<bool U>
    friend struct work_cleanup;

    template<bool U>
    friend struct task_cleanup;

    std::size_t do_run(
        std::unique_lock<std::mutex>& lock,
        thread_info& this_thread,
        std::size_t max_handlers);

    // Single-thread optimization flag
    bool one_thread_;

    // Synchronization
    mutable std::mutex mutex_;
    mutable std::condition_variable cv_;

    // Work queue (intrusive, no allocation for queue nodes)
    mutable capy::executor_work_queue queue_;

    // State
    std::size_t outstanding_work_ = 0;
    bool stopped_ = false;
    bool shutdown_ = false;

    // Reactor integration (null until I/O object triggers init_task)
    reactor* task_ = nullptr;
    struct task_op : capy::executor_work
    {
        void operator()() override {}
        void destroy() override {}
    } task_operation_;
    bool task_interrupted_ = true;
};

// Extern template declarations to prevent implicit instantiation
extern template class reactive_scheduler<false>;
extern template class reactive_scheduler<true>;

} // namespace detail
} // namespace corosio
} // namespace boost

#endif
