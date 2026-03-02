//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_SCHEDULER_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_SCHEDULER_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>

#include <boost/corosio/native/native_scheduler.hpp>
#include <boost/corosio/detail/scheduler_op.hpp>

#include <boost/corosio/native/detail/select/select_op.hpp>
#include <boost/corosio/detail/timer_service.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/native/detail/posix/posix_resolver_service.hpp>
#include <boost/corosio/native/detail/posix/posix_signal_service.hpp>

#include <boost/corosio/detail/except.hpp>
#include <boost/corosio/detail/thread_local_ptr.hpp>

#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace boost::corosio::detail {

namespace select {
struct BOOST_COROSIO_SYMBOL_VISIBLE scheduler_context;
} // namespace select

/** POSIX scheduler using select() for I/O multiplexing.

    This scheduler implements the scheduler interface using the POSIX select()
    call for I/O event notification. It uses a single reactor model
    where one thread runs select() while other threads wait on a condition
    variable for handler work. This design provides:

    - Handler parallelism: N posted handlers can execute on N threads
    - No thundering herd: condition_variable wakes exactly one thread
    - Portability: Works on all POSIX systems

    The design mirrors epoll_scheduler for behavioral consistency:
    - Same single-reactor thread coordination model
    - Same work counting semantics
    - Same timer integration pattern
    - Same deferred I/O model via descriptor_state
    - Same inline budget for speculative completions
    - Same private queue optimization
    - Same signaling state machine

    Known Limitations:
    - FD_SETSIZE (~1024) limits maximum concurrent connections
    - O(n) scanning: rebuilds fd_sets each iteration
    - Level-triggered only (no edge-triggered mode)

    @par Thread Safety
    All public member functions are thread-safe.
*/
class BOOST_COROSIO_DECL select_scheduler final
    : public native_scheduler
    , public capy::execution_context::service
{
public:
    using key_type = scheduler;

    /** Construct the scheduler.

        Creates a self-pipe for reactor interruption.

        @param ctx Reference to the owning execution_context.
        @param concurrency_hint Hint for expected thread count (unused).
    */
    select_scheduler(capy::execution_context& ctx, int concurrency_hint = -1);

    ~select_scheduler() override;

    select_scheduler(select_scheduler const&)            = delete;
    select_scheduler& operator=(select_scheduler const&) = delete;

    void shutdown() override;
    void post(std::coroutine_handle<> h) const override;
    void post(scheduler_op* h) const override;
    bool running_in_this_thread() const noexcept override;
    void stop() override;
    bool stopped() const noexcept override;
    void restart() override;
    std::size_t run() override;
    std::size_t run_one() override;
    std::size_t wait_one(long usec) override;
    std::size_t poll() override;
    std::size_t poll_one() override;

    /** Return the maximum file descriptor value supported.

        Returns FD_SETSIZE - 1, the maximum fd value that can be
        monitored by select(). Operations with fd >= FD_SETSIZE
        will fail with EINVAL.

        @return The maximum supported file descriptor value.
    */
    static constexpr int max_fd() noexcept
    {
        return FD_SETSIZE - 1;
    }

    /** Reset the thread's inline completion budget.

        Called at the start of each posted completion handler to
        grant a fresh budget for speculative inline completions.
    */
    void reset_inline_budget() const noexcept;

    /** Consume one unit of inline budget if available.

        @return True if budget was available and consumed.
    */
    bool try_consume_inline_budget() const noexcept;

    /** Register a descriptor for persistent monitoring.

        The fd is tracked and stays tracked until explicitly
        deregistered. Events are dispatched via descriptor_state which
        tracks pending read/write/connect operations.

        @param fd The file descriptor to register.
        @param desc Pointer to the descriptor_state.
    */
    void register_descriptor(int fd, select_descriptor_state* desc) const;

    /** Deregister a persistently registered descriptor.

        @param fd The file descriptor to deregister.
    */
    void deregister_descriptor(int fd) const;

    /** Start monitoring an fd for specific events.

        Called when an operation is parked in a descriptor_state.
        Adds the fd to the select() fd_sets for the specified events.

        @param fd The file descriptor.
        @param events Bitmask: event_read, event_write.
    */
    void start_op(int fd, int events) const;

    /** Stop monitoring an fd for specific events.

        Called when an operation completes or is cancelled.

        @param fd The file descriptor.
        @param events Bitmask to stop monitoring.
    */
    void finish_op(int fd, int events) const;

    void work_started() noexcept override;
    void work_finished() noexcept override;

    /** Offset a forthcoming work_finished from work_cleanup.

        Called by descriptor_state when all I/O returned EAGAIN and no
        handler will be executed. Must be called from a scheduler thread.
    */
    void compensating_work_started() const noexcept;

    /** Drain work from thread context's private queue to global queue.

        Called by thread_context_guard destructor when a thread exits run().

        @param queue The private queue to drain.
        @param count Item count for wakeup decisions.
    */
    void drain_thread_queue(op_queue& queue, long count) const;

    /** Post completed operations for deferred invocation.

        If called from a thread running this scheduler, operations go to
        the thread's private queue (fast path). Otherwise, operations are
        added to the global queue under mutex and a waiter is signaled.

        @param ops Queue of operations to post.
    */
    void post_deferred_completions(op_queue& ops) const;

    // Event flags for start_op/finish_op
    static constexpr int event_read  = 1;
    static constexpr int event_write = 2;

private:
    struct work_cleanup
    {
        select_scheduler* scheduler;
        std::unique_lock<std::mutex>* lock;
        select::scheduler_context* ctx;
        ~work_cleanup();
    };

    struct task_cleanup
    {
        select_scheduler const* scheduler;
        std::unique_lock<std::mutex>* lock;
        select::scheduler_context* ctx;
        ~task_cleanup();
    };

    std::size_t do_one(
        std::unique_lock<std::mutex>& lock,
        long timeout_us,
        select::scheduler_context* ctx);
    void run_task(
        std::unique_lock<std::mutex>& lock, select::scheduler_context* ctx);
    void wake_one_thread_and_unlock(std::unique_lock<std::mutex>& lock) const;
    void interrupt_reactor() const;
    long calculate_timeout(long requested_timeout_us) const;
    void signal_all(std::unique_lock<std::mutex>& lock) const;
    bool maybe_unlock_and_signal_one(std::unique_lock<std::mutex>& lock) const;
    bool unlock_and_signal_one(std::unique_lock<std::mutex>& lock) const;
    void clear_signal() const;
    void wait_for_signal(std::unique_lock<std::mutex>& lock) const;
    void wait_for_signal_for(std::unique_lock<std::mutex>& lock, long us) const;

    // Self-pipe for interrupting select()
    int pipe_fds_[2]; // [0]=read, [1]=write

    mutable std::mutex mutex_;
    mutable std::condition_variable cond_;
    mutable op_queue completed_ops_;
    mutable std::atomic<long> outstanding_work_;
    bool stopped_;

    // True while a thread is blocked in select(). Used by
    // wake_one_thread_and_unlock and work_finished to know when
    // a self-pipe interrupt is needed instead of a condvar signal.
    mutable std::atomic<bool> task_running_{false};

    // True when the reactor has been told to do a non-blocking poll.
    // Prevents redundant pipe writes and controls the select() timeout.
    mutable bool task_interrupted_ = false;

    // Signaling state: bit 0 = signaled, upper bits = waiter count (+2 each)
    mutable std::size_t state_ = 0;

    // Per-fd state for tracking registered descriptors and monitoring
    struct fd_interest
    {
        select_descriptor_state* desc = nullptr;
        int events                    = 0; // bitmask: event_read | event_write
    };
    mutable std::unordered_map<int, fd_interest> registered_fds_;
    mutable int max_fd_ = -1;

    // Sentinel operation for interleaving reactor runs with handler execution
    struct task_op final : scheduler_op
    {
        void operator()() override {}
        void destroy() override {}
    };
    task_op task_op_;
};

/*
    select Scheduler - Single Reactor Model
    =======================================

    This scheduler mirrors the epoll_scheduler design but uses select() instead
    of epoll for I/O multiplexing. The thread coordination strategy is identical:
    one thread becomes the "reactor" while others wait on a condition variable.

    Thread Model
    ------------
    - ONE thread runs select() at a time (the reactor thread)
    - OTHER threads wait on cond_ (condition variable) for handlers
    - When work is posted, exactly one waiting thread wakes via notify_one()

    Deferred I/O Model
    ------------------
    Matching epoll_scheduler, the reactor does not perform I/O directly:
    1. Reactor sees readiness via select()
    2. Sets ready_events_ atomically on descriptor_state
    3. Enqueues descriptor_state if not already enqueued
    4. Scheduler pops descriptor_state and calls operator()
    5. operator() performs I/O under mutex and queues completions

    Signaling State (state_)
    ------------------------
    Bit 0 = signaled flag, upper bits = waiter count (each waiter adds 2).
    Matches epoll_scheduler for identical thread coordination.

    Self-Pipe Pattern
    -----------------
    To interrupt a blocking select() call, we write a byte to pipe_fds_[1].
    The read end pipe_fds_[0] is always in the read_fds set, so select()
    returns immediately. We drain the pipe to clear the readable state.
*/

namespace select {

struct BOOST_COROSIO_SYMBOL_VISIBLE scheduler_context
{
    select_scheduler const* key;
    scheduler_context* next;
    op_queue private_queue;
    long private_outstanding_work;
    int inline_budget;
    int inline_budget_max;
    bool unassisted;

    scheduler_context(select_scheduler const* k, scheduler_context* n)
        : key(k)
        , next(n)
        , private_outstanding_work(0)
        , inline_budget(0)
        , inline_budget_max(2)
        , unassisted(false)
    {
    }
};

inline thread_local_ptr<scheduler_context> context_stack;

struct thread_context_guard
{
    scheduler_context frame_;

    explicit thread_context_guard(select_scheduler const* ctx) noexcept
        : frame_(ctx, context_stack.get())
    {
        context_stack.set(&frame_);
    }

    ~thread_context_guard() noexcept
    {
        if (!frame_.private_queue.empty())
            frame_.key->drain_thread_queue(
                frame_.private_queue, frame_.private_outstanding_work);
        context_stack.set(frame_.next);
    }
};

inline scheduler_context*
find_context(select_scheduler const* self) noexcept
{
    for (auto* c = context_stack.get(); c != nullptr; c = c->next)
        if (c->key == self)
            return c;
    return nullptr;
}

} // namespace select

inline void
select_scheduler::reset_inline_budget() const noexcept
{
    if (auto* ctx = select::find_context(this))
    {
        if (ctx->unassisted)
        {
            ctx->inline_budget_max = 4;
            ctx->inline_budget     = 4;
            return;
        }
        if (ctx->inline_budget == 0)
            ctx->inline_budget_max = (std::min)(ctx->inline_budget_max * 2, 16);
        else if (ctx->inline_budget < ctx->inline_budget_max)
            ctx->inline_budget_max = 2;
        ctx->inline_budget = ctx->inline_budget_max;
    }
}

inline bool
select_scheduler::try_consume_inline_budget() const noexcept
{
    if (auto* ctx = select::find_context(this))
    {
        if (ctx->inline_budget > 0)
        {
            --ctx->inline_budget;
            return true;
        }
    }
    return false;
}

inline void
select_descriptor_state::operator()()
{
    is_enqueued_.store(false, std::memory_order_relaxed);

    // Take ownership of impl ref set by close_socket() to prevent
    // the owning impl from being freed while we're executing
    auto prevent_impl_destruction = std::move(impl_ref_);

    std::uint32_t ev = ready_events_.exchange(0, std::memory_order_acquire);
    if (ev == 0)
    {
        scheduler_->compensating_work_started();
        return;
    }

    op_queue local_ops;

    int err = 0;
    if (ev & select_event_error)
    {
        socklen_t len = sizeof(err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
            err = errno;
        if (err == 0)
            err = EIO;
    }

    {
        std::lock_guard lock(mutex);
        if (ev & select_event_read)
        {
            if (read_op)
            {
                auto* rd = read_op;
                if (err)
                    rd->complete(err, 0);
                else
                    rd->perform_io();

                if (rd->errn == EAGAIN || rd->errn == EWOULDBLOCK)
                {
                    rd->errn = 0;
                }
                else
                {
                    read_op = nullptr;
                    local_ops.push(rd);
                }
            }
            else
            {
                read_ready = true;
            }
        }
        if (ev & select_event_write)
        {
            bool had_write_op = (connect_op || write_op);
            if (connect_op)
            {
                auto* cn = connect_op;
                if (err)
                    cn->complete(err, 0);
                else
                    cn->perform_io();
                connect_op = nullptr;
                local_ops.push(cn);
            }
            if (write_op)
            {
                auto* wr = write_op;
                if (err)
                    wr->complete(err, 0);
                else
                    wr->perform_io();

                if (wr->errn == EAGAIN || wr->errn == EWOULDBLOCK)
                {
                    wr->errn = 0;
                }
                else
                {
                    write_op = nullptr;
                    local_ops.push(wr);
                }
            }
            if (!had_write_op)
                write_ready = true;
        }
        if (err)
        {
            if (read_op)
            {
                read_op->complete(err, 0);
                local_ops.push(std::exchange(read_op, nullptr));
            }
            if (write_op)
            {
                write_op->complete(err, 0);
                local_ops.push(std::exchange(write_op, nullptr));
            }
            if (connect_op)
            {
                connect_op->complete(err, 0);
                local_ops.push(std::exchange(connect_op, nullptr));
            }
        }
    }

    // Stop monitoring for completed ops
    int finished_events = 0;
    if (!read_op)
        finished_events |= select_scheduler::event_read;
    if (!write_op && !connect_op)
        finished_events |= select_scheduler::event_write;
    if (finished_events)
        scheduler_->finish_op(fd, finished_events);

    // Execute first handler inline — the scheduler's work_cleanup
    // accounts for this as the "consumed" work item
    scheduler_op* first = local_ops.pop();
    if (first)
    {
        scheduler_->post_deferred_completions(local_ops);
        (*first)();
    }
    else
    {
        scheduler_->compensating_work_started();
    }
}

inline select_scheduler::select_scheduler(capy::execution_context& ctx, int)
    : pipe_fds_{-1, -1}
    , outstanding_work_(0)
    , stopped_(false)
    , task_running_{false}
    , task_interrupted_(false)
    , state_(0)
    , max_fd_(-1)
{
    // Create self-pipe for interrupting select()
    if (::pipe(pipe_fds_) < 0)
        detail::throw_system_error(make_err(errno), "pipe");

    // Set both ends to non-blocking and close-on-exec
    for (int i = 0; i < 2; ++i)
    {
        int flags = ::fcntl(pipe_fds_[i], F_GETFL, 0);
        if (flags == -1)
        {
            int errn = errno;
            ::close(pipe_fds_[0]);
            ::close(pipe_fds_[1]);
            detail::throw_system_error(make_err(errn), "fcntl F_GETFL");
        }
        if (::fcntl(pipe_fds_[i], F_SETFL, flags | O_NONBLOCK) == -1)
        {
            int errn = errno;
            ::close(pipe_fds_[0]);
            ::close(pipe_fds_[1]);
            detail::throw_system_error(make_err(errn), "fcntl F_SETFL");
        }
        if (::fcntl(pipe_fds_[i], F_SETFD, FD_CLOEXEC) == -1)
        {
            int errn = errno;
            ::close(pipe_fds_[0]);
            ::close(pipe_fds_[1]);
            detail::throw_system_error(make_err(errn), "fcntl F_SETFD");
        }
    }

    timer_svc_ = &get_timer_service(ctx, *this);
    timer_svc_->set_on_earliest_changed(
        timer_service::callback(this, [](void* p) {
            static_cast<select_scheduler*>(p)->interrupt_reactor();
        }));

    // Initialize resolver service
    get_resolver_service(ctx, *this);

    // Initialize signal service
    get_signal_service(ctx, *this);

    // Push task sentinel to interleave reactor runs with handler execution
    completed_ops_.push(&task_op_);
}

inline select_scheduler::~select_scheduler()
{
    if (pipe_fds_[0] >= 0)
        ::close(pipe_fds_[0]);
    if (pipe_fds_[1] >= 0)
        ::close(pipe_fds_[1]);
}

inline void
select_scheduler::shutdown()
{
    {
        std::unique_lock lock(mutex_);

        while (auto* h = completed_ops_.pop())
        {
            if (h == &task_op_)
                continue;
            lock.unlock();
            h->destroy();
            lock.lock();
        }

        signal_all(lock);
    }

    if (pipe_fds_[1] >= 0)
        interrupt_reactor();
}

inline void
select_scheduler::post(std::coroutine_handle<> h) const
{
    struct post_handler final : scheduler_op
    {
        std::coroutine_handle<> h_;

        explicit post_handler(std::coroutine_handle<> h) : h_(h) {}

        ~post_handler() override = default;

        void operator()() override
        {
            auto h = h_;
            delete this;
            h.resume();
        }

        void destroy() override
        {
            auto h = h_;
            delete this;
            h.destroy();
        }
    };

    auto ph = std::make_unique<post_handler>(h);

    // Fast path: same thread posts to private queue
    if (auto* ctx = select::find_context(this))
    {
        ++ctx->private_outstanding_work;
        ctx->private_queue.push(ph.release());
        return;
    }

    // Slow path: cross-thread post requires mutex
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lock(mutex_);
    completed_ops_.push(ph.release());
    wake_one_thread_and_unlock(lock);
}

inline void
select_scheduler::post(scheduler_op* h) const
{
    // Fast path: same thread posts to private queue
    if (auto* ctx = select::find_context(this))
    {
        ++ctx->private_outstanding_work;
        ctx->private_queue.push(h);
        return;
    }

    // Slow path: cross-thread post requires mutex
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lock(mutex_);
    completed_ops_.push(h);
    wake_one_thread_and_unlock(lock);
}

inline bool
select_scheduler::running_in_this_thread() const noexcept
{
    for (auto* c = select::context_stack.get(); c != nullptr; c = c->next)
        if (c->key == this)
            return true;
    return false;
}

inline void
select_scheduler::stop()
{
    std::unique_lock lock(mutex_);
    if (!stopped_)
    {
        stopped_ = true;
        signal_all(lock);
        interrupt_reactor();
    }
}

inline bool
select_scheduler::stopped() const noexcept
{
    std::unique_lock lock(mutex_);
    return stopped_;
}

inline void
select_scheduler::restart()
{
    std::unique_lock lock(mutex_);
    stopped_ = false;
}

inline std::size_t
select_scheduler::run()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    select::thread_context_guard ctx(this);
    std::unique_lock lock(mutex_);

    std::size_t n = 0;
    for (;;)
    {
        if (!do_one(lock, -1, &ctx.frame_))
            break;
        if (n != (std::numeric_limits<std::size_t>::max)())
            ++n;
        if (!lock.owns_lock())
            lock.lock();
    }
    return n;
}

inline std::size_t
select_scheduler::run_one()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    select::thread_context_guard ctx(this);
    std::unique_lock lock(mutex_);
    return do_one(lock, -1, &ctx.frame_);
}

inline std::size_t
select_scheduler::wait_one(long usec)
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    select::thread_context_guard ctx(this);
    std::unique_lock lock(mutex_);
    return do_one(lock, usec, &ctx.frame_);
}

inline std::size_t
select_scheduler::poll()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    select::thread_context_guard ctx(this);
    std::unique_lock lock(mutex_);

    std::size_t n = 0;
    for (;;)
    {
        if (!do_one(lock, 0, &ctx.frame_))
            break;
        if (n != (std::numeric_limits<std::size_t>::max)())
            ++n;
        if (!lock.owns_lock())
            lock.lock();
    }
    return n;
}

inline std::size_t
select_scheduler::poll_one()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    select::thread_context_guard ctx(this);
    std::unique_lock lock(mutex_);
    return do_one(lock, 0, &ctx.frame_);
}

inline void
select_scheduler::register_descriptor(
    int fd, select_descriptor_state* desc) const
{
    if (fd < 0 || fd >= FD_SETSIZE)
        detail::throw_system_error(make_err(EINVAL), "select: fd out of range");

    std::lock_guard lock(mutex_);
    registered_fds_[fd] = {desc, 0};
    if (fd > max_fd_)
        max_fd_ = fd;

    desc->fd                = fd;
    desc->scheduler_        = this;
    desc->registered_events = 1; // Mark as registered

    std::lock_guard desc_lock(desc->mutex);
    desc->read_ready  = false;
    desc->write_ready = false;
}

inline void
select_scheduler::deregister_descriptor(int fd) const
{
    std::lock_guard lock(mutex_);

    registered_fds_.erase(fd);

    // Recalculate max_fd_ if needed
    if (fd == max_fd_)
    {
        max_fd_ = pipe_fds_[0]; // At minimum, the pipe read end
        for (auto& [registered_fd, fi] : registered_fds_)
        {
            if (registered_fd > max_fd_)
                max_fd_ = registered_fd;
        }
    }
}

inline void
select_scheduler::start_op(int fd, int events) const
{
    {
        std::lock_guard lock(mutex_);
        auto it = registered_fds_.find(fd);
        if (it != registered_fds_.end())
            it->second.events |= events;
    }

    // Wake reactor so it rebuilds fd_sets with the new interest
    interrupt_reactor();
}

inline void
select_scheduler::finish_op(int fd, int events) const
{
    std::lock_guard lock(mutex_);
    auto it = registered_fds_.find(fd);
    if (it != registered_fds_.end())
        it->second.events &= ~events;
}

inline void
select_scheduler::work_started() noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}

inline void
select_scheduler::work_finished() noexcept
{
    if (outstanding_work_.fetch_sub(1, std::memory_order_acq_rel) == 1)
        stop();
}

inline void
select_scheduler::compensating_work_started() const noexcept
{
    auto* ctx = select::find_context(this);
    if (ctx)
        ++ctx->private_outstanding_work;
}

inline void
select_scheduler::drain_thread_queue(op_queue& queue, long count) const
{
    std::unique_lock lock(mutex_);
    completed_ops_.splice(queue);
    if (count > 0)
        maybe_unlock_and_signal_one(lock);
}

inline void
select_scheduler::post_deferred_completions(op_queue& ops) const
{
    if (ops.empty())
        return;

    // Fast path: if on scheduler thread, use private queue
    if (auto* ctx = select::find_context(this))
    {
        ctx->private_queue.splice(ops);
        return;
    }

    // Slow path: add to global queue and wake a thread
    std::unique_lock lock(mutex_);
    completed_ops_.splice(ops);
    wake_one_thread_and_unlock(lock);
}

inline void
select_scheduler::interrupt_reactor() const
{
    char byte               = 1;
    [[maybe_unused]] auto r = ::write(pipe_fds_[1], &byte, 1);
}

inline void
select_scheduler::signal_all(std::unique_lock<std::mutex>&) const
{
    state_ |= 1;
    cond_.notify_all();
}

inline bool
select_scheduler::maybe_unlock_and_signal_one(
    std::unique_lock<std::mutex>& lock) const
{
    state_ |= 1;
    if (state_ > 1)
    {
        lock.unlock();
        cond_.notify_one();
        return true;
    }
    return false;
}

inline bool
select_scheduler::unlock_and_signal_one(
    std::unique_lock<std::mutex>& lock) const
{
    state_ |= 1;
    bool have_waiters = state_ > 1;
    lock.unlock();
    if (have_waiters)
        cond_.notify_one();
    return have_waiters;
}

inline void
select_scheduler::clear_signal() const
{
    state_ &= ~std::size_t(1);
}

inline void
select_scheduler::wait_for_signal(std::unique_lock<std::mutex>& lock) const
{
    while ((state_ & 1) == 0)
    {
        state_ += 2;
        cond_.wait(lock);
        state_ -= 2;
    }
}

inline void
select_scheduler::wait_for_signal_for(
    std::unique_lock<std::mutex>& lock, long timeout_us) const
{
    if ((state_ & 1) == 0)
    {
        state_ += 2;
        cond_.wait_for(lock, std::chrono::microseconds(timeout_us));
        state_ -= 2;
    }
}

inline void
select_scheduler::wake_one_thread_and_unlock(
    std::unique_lock<std::mutex>& lock) const
{
    if (maybe_unlock_and_signal_one(lock))
        return;

    if (task_running_.load(std::memory_order_relaxed) && !task_interrupted_)
    {
        task_interrupted_ = true;
        lock.unlock();
        interrupt_reactor();
    }
    else
    {
        lock.unlock();
    }
}

inline long
select_scheduler::calculate_timeout(long requested_timeout_us) const
{
    if (requested_timeout_us == 0)
        return 0;

    auto nearest = timer_svc_->nearest_expiry();
    if (nearest == timer_service::time_point::max())
        return requested_timeout_us;

    auto now = std::chrono::steady_clock::now();
    if (nearest <= now)
        return 0;

    auto timer_timeout_us =
        std::chrono::duration_cast<std::chrono::microseconds>(nearest - now)
            .count();

    // Clamp to [0, LONG_MAX] to prevent truncation on 32-bit long platforms
    constexpr auto long_max =
        static_cast<long long>((std::numeric_limits<long>::max)());
    auto capped_timer_us =
        (std::min)((std::max)(static_cast<long long>(timer_timeout_us),
                              static_cast<long long>(0)),
                   long_max);

    if (requested_timeout_us < 0)
        return static_cast<long>(capped_timer_us);

    return static_cast<long>(
        (std::min)(static_cast<long long>(requested_timeout_us),
                   capped_timer_us));
}

inline select_scheduler::work_cleanup::~work_cleanup()
{
    if (ctx)
    {
        long produced = ctx->private_outstanding_work;
        if (produced > 1)
            scheduler->outstanding_work_.fetch_add(
                produced - 1, std::memory_order_relaxed);
        else if (produced < 1)
            scheduler->work_finished();
        ctx->private_outstanding_work = 0;

        if (!ctx->private_queue.empty())
        {
            lock->lock();
            scheduler->completed_ops_.splice(ctx->private_queue);
        }
    }
    else
    {
        scheduler->work_finished();
    }
}

inline select_scheduler::task_cleanup::~task_cleanup()
{
    if (!ctx)
        return;

    if (ctx->private_outstanding_work > 0)
    {
        scheduler->outstanding_work_.fetch_add(
            ctx->private_outstanding_work, std::memory_order_relaxed);
        ctx->private_outstanding_work = 0;
    }

    if (!ctx->private_queue.empty())
    {
        if (!lock->owns_lock())
            lock->lock();
        scheduler->completed_ops_.splice(ctx->private_queue);
    }
}

inline void
select_scheduler::run_task(
    std::unique_lock<std::mutex>& lock, select::scheduler_context* ctx)
{
    long effective_timeout_us = task_interrupted_ ? 0 : calculate_timeout(-1);

    // Build fd_sets from registered_fds_
    fd_set read_fds, write_fds, except_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);

    // Always include the interrupt pipe
    FD_SET(pipe_fds_[0], &read_fds);
    int nfds = pipe_fds_[0];

    // Snapshot fd -> desc mappings for post-select processing
    struct fd_snapshot
    {
        int fd;
        select_descriptor_state* desc;
        int events;
    };
    std::vector<fd_snapshot> snapshots;
    snapshots.reserve(registered_fds_.size());

    for (auto& [fd, fi] : registered_fds_)
    {
        if (fi.events == 0)
            continue;

        if (fi.events & event_read)
            FD_SET(fd, &read_fds);
        if (fi.events & event_write)
        {
            FD_SET(fd, &write_fds);
            FD_SET(fd, &except_fds);
        }
        if (fd > nfds)
            nfds = fd;

        snapshots.push_back({fd, fi.desc, fi.events});
    }

    // Convert timeout to timeval
    struct timeval tv;
    struct timeval* tv_ptr = nullptr;
    if (effective_timeout_us >= 0)
    {
        tv.tv_sec  = effective_timeout_us / 1000000;
        tv.tv_usec = effective_timeout_us % 1000000;
        tv_ptr     = &tv;
    }

    if (lock.owns_lock())
        lock.unlock();

    task_cleanup on_exit{this, &lock, ctx};

    int ready = ::select(nfds + 1, &read_fds, &write_fds, &except_fds, tv_ptr);
    int saved_errno = errno;

    // Process timers outside the lock
    timer_svc_->process_expired();

    if (ready < 0 && saved_errno != EINTR)
        detail::throw_system_error(make_err(saved_errno), "select");

    // Drain the interrupt pipe if readable
    if (ready > 0 && FD_ISSET(pipe_fds_[0], &read_fds))
    {
        char buf[256];
        while (::read(pipe_fds_[0], buf, sizeof(buf)) > 0)
        {
        }
    }

    // Process I/O completions using deferred model
    op_queue local_ops;
    if (ready > 0)
    {
        for (auto& snap : snapshots)
        {
            std::uint32_t ev = 0;
            if ((snap.events & event_read) && FD_ISSET(snap.fd, &read_fds))
                ev |= select_event_read;
            if ((snap.events & event_write) &&
                (FD_ISSET(snap.fd, &write_fds) ||
                 FD_ISSET(snap.fd, &except_fds)))
                ev |= select_event_write;
            if (FD_ISSET(snap.fd, &except_fds))
                ev |= select_event_error;

            if (ev)
            {
                snap.desc->add_ready_events(ev);

                // Only enqueue if not already enqueued
                bool expected = false;
                if (snap.desc->is_enqueued_.compare_exchange_strong(
                        expected, true, std::memory_order_release,
                        std::memory_order_relaxed))
                {
                    local_ops.push(snap.desc);
                }
            }
        }
    }

    lock.lock();

    if (!local_ops.empty())
        completed_ops_.splice(local_ops);
}

inline std::size_t
select_scheduler::do_one(
    std::unique_lock<std::mutex>& lock,
    long timeout_us,
    select::scheduler_context* ctx)
{
    for (;;)
    {
        if (stopped_)
            return 0;

        scheduler_op* op = completed_ops_.pop();

        // Handle reactor sentinel - time to poll for I/O
        if (op == &task_op_)
        {
            bool more_handlers = !completed_ops_.empty();

            if (!more_handlers &&
                (outstanding_work_.load(std::memory_order_acquire) == 0 ||
                 timeout_us == 0))
            {
                completed_ops_.push(&task_op_);
                return 0;
            }

            task_interrupted_ = more_handlers || timeout_us == 0;
            task_running_.store(true, std::memory_order_release);

            if (more_handlers)
                unlock_and_signal_one(lock);

            run_task(lock, ctx);

            task_running_.store(false, std::memory_order_relaxed);
            completed_ops_.push(&task_op_);
            continue;
        }

        // Handle operation
        if (op != nullptr)
        {
            bool more = !completed_ops_.empty();

            if (more)
                ctx->unassisted = !unlock_and_signal_one(lock);
            else
            {
                ctx->unassisted = false;
                lock.unlock();
            }

            work_cleanup on_exit{this, &lock, ctx};

            (*op)();
            return 1;
        }

        // No pending work to wait on, or caller requested non-blocking poll
        if (outstanding_work_.load(std::memory_order_acquire) == 0 ||
            timeout_us == 0)
            return 0;

        clear_signal();
        if (timeout_us < 0)
            wait_for_signal(lock);
        else
            wait_for_signal_for(lock, timeout_us);
    }
}

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_SELECT_SELECT_SCHEDULER_HPP
