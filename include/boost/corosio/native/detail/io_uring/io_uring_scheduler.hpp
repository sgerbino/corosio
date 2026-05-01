//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SCHEDULER_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SCHEDULER_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

// Include before any project headers open a namespace — prevents the
// boost::corosio::io_uring tag variable from shadowing struct ::io_uring.
#include <liburing.h>

#include <boost/corosio/detail/conditionally_enabled_mutex.hpp>
#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/detail/except.hpp>
#include <boost/corosio/detail/scheduler.hpp>
#include <boost/corosio/detail/scheduler_op.hpp>
#include <boost/corosio/detail/timer_service.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_op.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_resolver_service.hpp>
#include <boost/corosio/native/detail/posix/posix_signal_service.hpp>
#include <boost/capy/ex/execution_context.hpp>

#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <limits>

#include <errno.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace boost::corosio::detail {

/** io_uring scheduler — proactor model on Linux 6.x+.

    Owns one io_uring per io_context. Lazy batched submit;
    cross-thread post wakes a registered eventfd via multishot
    POLL_ADD.

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL io_uring_scheduler final
    : public scheduler
    , public capy::execution_context::service
{
public:
    using key_type   = scheduler;
    using mutex_type = conditionally_enabled_mutex;
    using lock_type  = mutex_type::scoped_lock;

    io_uring_scheduler(capy::execution_context& ctx, int concurrency_hint = -1);
    ~io_uring_scheduler() override;
    io_uring_scheduler(io_uring_scheduler const&)            = delete;
    io_uring_scheduler& operator=(io_uring_scheduler const&) = delete;

    void shutdown() override;

    // scheduler virtuals — definitions in Task 6
    void post(std::coroutine_handle<>) const override;
    void post(scheduler_op*) const override;
    bool running_in_this_thread() const noexcept override;
    void stop() override;
    bool stopped() const noexcept override;
    void restart() override;
    std::size_t run() override;
    std::size_t run_one() override;
    std::size_t wait_one(long usec) override;
    std::size_t poll() override;
    std::size_t poll_one() override;
    void work_started() noexcept override;
    void work_finished() noexcept override;

    /// Return the underlying liburing ring (used by socket services).
    struct ::io_uring* ring() noexcept { return &ring_; }

    /// Return the dispatch mutex for SQE acquisition.
    mutex_type& dispatch_mutex() const noexcept { return dispatch_mutex_; }

    /** Submit `IORING_OP_ASYNC_CANCEL` targeting an in-flight op by its
        user_data pointer.

        The kernel delivers `-ECANCELED` on the target's CQE if it was
        still in flight; the op's completion handler then reports
        `operation_aborted`.  Best-effort: if the SQ is full after one
        flush attempt the function returns without cancelling (the op
        will complete normally on its own).

        @param target The in-flight op to cancel.
    */
    void submit_cancel_by_user_data(io_uring_op* target) noexcept;

    /** Submit `IORING_OP_ASYNC_CANCEL` with `IORING_ASYNC_CANCEL_FD`
        to cancel every in-flight op on the given fd in one SQE.

        Best-effort: if the SQ is full after one flush attempt the
        function returns without cancelling.

        @param fd The file descriptor whose in-flight ops should be
            cancelled.
    */
    void submit_cancel_by_fd(int fd) noexcept;

    /** Queue an already-counted op while the caller holds dispatch_mutex_.

        Does NOT increment `outstanding_work_`. Use for synchronous
        completion paths (e.g. SQE backpressure) where the caller called
        `work_started()` and already holds the dispatch lock.

        @pre `dispatch_mutex_` must be locked by the calling thread.
    */
    void push_completed_locked(scheduler_op* op) const noexcept
    {
        completed_ops_.push(op);
    }

    /// Single-threaded mode toggle (matches reactor_scheduler API).
    void configure_single_threaded(bool v) noexcept
    {
        single_threaded_ = v;
        dispatch_mutex_.set_enabled(!v);
    }

    /// Return true if single-threaded (lockless) mode is active.
    bool is_single_threaded() const noexcept { return single_threaded_; }

private:
    struct ::io_uring                  ring_{};
    int                               wakeup_eventfd_ = -1;
    timer_service*                    timer_svc_      = nullptr;

    mutable mutex_type                dispatch_mutex_{true};
    mutable op_queue                  completed_ops_;
    mutable std::atomic<std::int64_t> outstanding_work_{0};
    std::atomic<bool>                 stopped_{false};
    bool                              single_threaded_ = false;

    int                               cancel_sentinel_ = 0;
    mutable std::atomic<bool>         wakeup_armed_{false};

    std::size_t do_one(long timeout_us);
    void        process_completions();
    void        interrupt_reactor() const noexcept;
    void        drain_wakeup_eventfd() const noexcept;
};

inline
io_uring_scheduler::io_uring_scheduler(
    capy::execution_context& ctx, int /*concurrency_hint*/)
{
    io_uring_params params{};
    int rc = io_uring_queue_init_params(256, &ring_, &params);
    if (rc < 0)
        detail::throw_system_error(make_err(-rc), "io_uring_queue_init_params");

    wakeup_eventfd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wakeup_eventfd_ < 0)
    {
        int errn = errno;
        ::io_uring_queue_exit(&ring_);
        detail::throw_system_error(make_err(errn), "eventfd");
    }

    // Register multishot poll on the wakeup eventfd. user_data nullptr
    // is the wakeup-eventfd sentinel recognized by the run loop.
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe)
    {
        ::close(wakeup_eventfd_);
        ::io_uring_queue_exit(&ring_);
        detail::throw_system_error(
            make_err(ENOSPC), "io_uring_get_sqe (wakeup)");
    }
    io_uring_prep_poll_multishot(sqe, wakeup_eventfd_, POLLIN);
    io_uring_sqe_set_data(sqe, nullptr);
    int submit_rc = ::io_uring_submit(&ring_);
    if (submit_rc < 0)
    {
        ::close(wakeup_eventfd_);
        ::io_uring_queue_exit(&ring_);
        detail::throw_system_error(make_err(-submit_rc), "io_uring_submit (wakeup)");
    }

    // Wire timer service. on_earliest_changed wakes the run loop so it
    // recomputes its wait timeout.
    timer_svc_ = &get_timer_service(ctx, *this);
    timer_svc_->set_on_earliest_changed(
        timer_service::callback(this, [](void* p) {
            static_cast<io_uring_scheduler*>(p)->interrupt_reactor();
        }));

    get_resolver_service(ctx, *this);
    get_signal_service(ctx, *this);
}

inline
io_uring_scheduler::~io_uring_scheduler()
{
    if (wakeup_eventfd_ >= 0)
        ::close(wakeup_eventfd_);
    ::io_uring_queue_exit(&ring_);
}

inline void
io_uring_scheduler::shutdown()
{
    stopped_.store(true, std::memory_order_release);

    // Drain posted ops, calling destroy() on each so embedded handles
    // (coroutine frames, error_code outputs) get torn down rather than
    // leaked. Mirrors reactor_scheduler::shutdown_drain.
    lock_type lock(dispatch_mutex_);
    while (auto* op = completed_ops_.pop())
    {
        lock.unlock();
        op->destroy();
        lock.lock();
    }
}

inline void
io_uring_scheduler::stop()
{
    stopped_.store(true, std::memory_order_release);
}

inline bool
io_uring_scheduler::stopped() const noexcept
{
    return stopped_.load(std::memory_order_acquire);
}

inline void
io_uring_scheduler::restart()
{
    stopped_.store(false, std::memory_order_release);
}

inline void
io_uring_scheduler::work_started() noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}

inline void
io_uring_scheduler::work_finished() noexcept
{
    if (outstanding_work_.fetch_sub(1, std::memory_order_acq_rel) == 1)
        stop();
}

inline void
io_uring_scheduler::interrupt_reactor() const noexcept
{
    bool expected = false;
    if (wakeup_armed_.compare_exchange_strong(
            expected, true, std::memory_order_release,
            std::memory_order_relaxed))
    {
        std::uint64_t v = 1;
        [[maybe_unused]] auto r = ::write(wakeup_eventfd_, &v, sizeof(v));
    }
}

inline void
io_uring_scheduler::drain_wakeup_eventfd() const noexcept
{
    std::uint64_t v;
    [[maybe_unused]] auto r = ::read(wakeup_eventfd_, &v, sizeof(v));
    wakeup_armed_.store(false, std::memory_order_relaxed);
}

inline void
io_uring_scheduler::post(std::coroutine_handle<> h) const
{
    struct post_handler final : scheduler_op
    {
        std::coroutine_handle<> h_;
        explicit post_handler(std::coroutine_handle<> h) noexcept : h_(h) {}

        void operator()() override
        {
            auto saved = h_;
            delete this;
            std::atomic_thread_fence(std::memory_order_acquire);
            saved.resume();
        }

        void destroy() override
        {
            auto saved = h_;
            delete this;
            if (saved)
                saved.destroy();
        }
    };

    auto* op = new post_handler(h);
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
    {
        lock_type lock(dispatch_mutex_);
        completed_ops_.push(op);
    }
    interrupt_reactor();
}

inline void
io_uring_scheduler::post(scheduler_op* op) const
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
    {
        lock_type lock(dispatch_mutex_);
        completed_ops_.push(op);
    }
    interrupt_reactor();
}

inline bool
io_uring_scheduler::running_in_this_thread() const noexcept
{
    // v1: simple stub. A thread_local-based check is plan-4 territory;
    // returning false is safe — executor falls back to post(), always correct.
    return false;
}

inline std::size_t
io_uring_scheduler::run()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    std::size_t n = 0;
    for (;;)
    {
        std::size_t r = do_one(-1);
        if (r)
        {
            if (n != (std::numeric_limits<std::size_t>::max)())
                ++n;
            continue;
        }
        if (outstanding_work_.load(std::memory_order_acquire) == 0 ||
            stopped_.load(std::memory_order_acquire))
            break;
        // do_one returned 0 but work still outstanding (e.g. timer
        // expiry dispatched async work). Continue.
    }
    return n;
}

inline std::size_t
io_uring_scheduler::run_one()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }
    return do_one(-1);
}

inline std::size_t
io_uring_scheduler::wait_one(long usec)
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }
    return do_one(usec);
}

inline std::size_t
io_uring_scheduler::poll()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }
    std::size_t n = 0;
    while (do_one(0))
    {
        if (n != (std::numeric_limits<std::size_t>::max)())
            ++n;
    }
    return n;
}

inline std::size_t
io_uring_scheduler::poll_one()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }
    return do_one(0);
}

inline std::size_t
io_uring_scheduler::do_one(long timeout_us)
{
    if (stopped_.load(std::memory_order_acquire))
        return 0;

    // Drain any cross-thread-posted ops first.
    scheduler_op* op = nullptr;
    {
        lock_type lock(dispatch_mutex_);
        op = completed_ops_.pop();
    }

    if (!op)
    {
        // Compute kernel timeout: caller-driven OR timer-driven.
        __kernel_timespec ts{};
        __kernel_timespec* ts_ptr = nullptr;

        auto next_expiry = timer_svc_->nearest_expiry();
        auto now         = std::chrono::steady_clock::now();

        if (timeout_us == 0)
        {
            ts.tv_sec  = 0;
            ts.tv_nsec = 0;
            ts_ptr     = &ts;
        }
        else if (next_expiry != timer_service::time_point::max())
        {
            auto delta_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    next_expiry - now)
                    .count();
            if (delta_ns < 0) delta_ns = 0;
            ts.tv_sec  = delta_ns / 1'000'000'000;
            ts.tv_nsec = delta_ns % 1'000'000'000;
            ts_ptr     = &ts;
        }
        else if (timeout_us > 0)
        {
            ts.tv_sec  = timeout_us / 1'000'000;
            ts.tv_nsec = (timeout_us % 1'000'000) * 1000;
            ts_ptr     = &ts;
        }

        // Submit pending SQEs and wait for at least one CQE.
        ::io_uring_cqe* cqe = nullptr;
        int rc = ::io_uring_submit_and_wait_timeout(
            &ring_, &cqe, 1, ts_ptr, nullptr);
        if (rc < 0 && rc != -ETIME && rc != -EINTR)
            detail::throw_system_error(
                make_err(-rc), "io_uring_submit_and_wait_timeout");

        // Drain all available completions.
        process_completions();

        // Process any timer expirations.
        timer_svc_->process_expired();

        // Re-check for posted ops after the wait.
        lock_type lock(dispatch_mutex_);
        op = completed_ops_.pop();
        if (!op)
            return 0;
    }

    // Virtual dispatch — bridges both reactor-style services posted into
    // our queue (e.g. posix_signal_op overrides operator()()) and
    // proactor-style io_uring ops (io_uring_op overrides operator()()
    // to forward to its func-pointer).
    // work_finished balances the work_started from post(), matching IOCP.
    (*op)();
    work_finished();
    return 1;
}

inline void
io_uring_scheduler::process_completions()
{
    unsigned head;
    ::io_uring_cqe* cqe;
    unsigned consumed = 0;

    // Collect completed I/O ops locally; splice into completed_ops_
    // after the loop so do_one dispatches them one at a time.
    op_queue local_ops;

    io_uring_for_each_cqe(&ring_, head, cqe)
    {
        void* ud = io_uring_cqe_get_data(cqe);
        if (ud == nullptr)
        {
            // Wakeup eventfd CQE: drain the eventfd byte.
            drain_wakeup_eventfd();
        }
        else if (ud == &cancel_sentinel_)
        {
            // CQE for an ASYNC_CANCEL op — ignore; the actual op's
            // CQE arrives separately and is dispatched via cqe_func.
        }
        else
        {
            auto* iop = static_cast<io_uring_op*>(ud);
            (*iop->cqe_func)(iop, cqe->res, cqe->flags, local_ops);
        }
        ++consumed;
    }

    if (consumed)
        io_uring_cq_advance(&ring_, consumed);

    // do_one holds dispatch_mutex_ only for the pop(), not during the
    // wait. process_completions runs inside do_one after the wait, so
    // the lock is not held here — take it briefly for the splice.
    if (!local_ops.empty())
    {
        lock_type lock(dispatch_mutex_);
        completed_ops_.splice(local_ops);
    }
}

inline void
io_uring_scheduler::submit_cancel_by_user_data(io_uring_op* target) noexcept
{
    lock_type lock(dispatch_mutex_);
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe)
    {
        io_uring_submit(&ring_);
        sqe = io_uring_get_sqe(&ring_);
    }
    if (!sqe)
        return;  // best-effort: op completes on its own if SQ is full

    io_uring_prep_cancel(sqe, target, 0);
    io_uring_sqe_set_data(sqe, &cancel_sentinel_);
}

inline void
io_uring_scheduler::submit_cancel_by_fd(int fd) noexcept
{
    lock_type lock(dispatch_mutex_);
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe)
    {
        io_uring_submit(&ring_);
        sqe = io_uring_get_sqe(&ring_);
    }
    if (!sqe)
        return;  // best-effort: ops complete on their own if SQ is full

    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
    io_uring_sqe_set_data(sqe, &cancel_sentinel_);
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SCHEDULER_HPP
