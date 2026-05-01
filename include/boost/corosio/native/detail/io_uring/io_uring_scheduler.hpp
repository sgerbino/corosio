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

#include <errno.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <liburing.h>

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
    io_uring_submit(&ring_);

    // Wire timer service. on_earliest_changed writes the wakeup eventfd
    // so the run loop recomputes its wait timeout.
    timer_svc_ = &get_timer_service(ctx, *this);
    timer_svc_->set_on_earliest_changed(
        timer_service::callback(this, [](void* p) {
            auto* self = static_cast<io_uring_scheduler*>(p);
            std::uint64_t v = 1;
            [[maybe_unused]] auto r =
                ::write(self->wakeup_eventfd_, &v, sizeof(v));
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
}

// ---- Stub virtuals — bodies arrive in Task 6 ----

inline void io_uring_scheduler::post(std::coroutine_handle<>) const {}
inline void io_uring_scheduler::post(scheduler_op*) const {}
inline bool io_uring_scheduler::running_in_this_thread() const noexcept { return false; }
inline void io_uring_scheduler::stop() { stopped_.store(true, std::memory_order_release); }
inline bool io_uring_scheduler::stopped() const noexcept { return stopped_.load(std::memory_order_acquire); }
inline void io_uring_scheduler::restart() { stopped_.store(false, std::memory_order_release); }
inline std::size_t io_uring_scheduler::run() { return 0; }
inline std::size_t io_uring_scheduler::run_one() { return 0; }
inline std::size_t io_uring_scheduler::wait_one(long) { return 0; }
inline std::size_t io_uring_scheduler::poll() { return 0; }
inline std::size_t io_uring_scheduler::poll_one() { return 0; }
inline void io_uring_scheduler::work_started() noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}
inline void io_uring_scheduler::work_finished() noexcept
{
    if (outstanding_work_.fetch_sub(1, std::memory_order_acq_rel) == 1)
        stop();
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_SCHEDULER_HPP
