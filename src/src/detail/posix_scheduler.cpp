//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef _WIN32

#include "src/detail/posix_scheduler.hpp"

#include <boost/capy/core/thread_local_ptr.hpp>

#include <limits>

namespace boost {
namespace corosio {
namespace detail {

namespace {

struct scheduler_context
{
    posix_scheduler const* key;
    scheduler_context* next;
};

capy::thread_local_ptr<scheduler_context> context_stack;

struct thread_context_guard
{
    scheduler_context frame_;

    explicit thread_context_guard(
        posix_scheduler const* ctx) noexcept
        : frame_{ctx, context_stack.get()}
    {
        context_stack.set(&frame_);
    }

    ~thread_context_guard() noexcept
    {
        context_stack.set(frame_.next);
    }
};

} // namespace

posix_scheduler::
posix_scheduler(
    capy::execution_context&,
    int)
    : outstanding_work_(0)
    , stopped_(false)
    , shutdown_(false)
{
}

posix_scheduler::
~posix_scheduler()
{
}

void
posix_scheduler::
shutdown()
{
    std::unique_lock lock(mutex_);
    shutdown_ = true;

    // Drain all outstanding operations without invoking handlers
    while (outstanding_work_.load(std::memory_order_acquire) > 0)
    {
        while (auto* h = completed_ops_.pop())
        {
            outstanding_work_.fetch_sub(1, std::memory_order_relaxed);
            lock.unlock();
            h->destroy();
            lock.lock();
        }

        // If work count still positive but queue empty,
        // wait briefly for more completions
        if (outstanding_work_.load(std::memory_order_acquire) > 0 &&
            completed_ops_.empty())
        {
            lock.unlock();
            std::this_thread::yield();
            lock.lock();
        }
    }
}

void
posix_scheduler::
post(capy::any_coro h) const
{
    struct post_handler
        : capy::execution_context::handler
    {
        capy::any_coro h_;

        explicit
        post_handler(capy::any_coro h)
            : h_(h)
        {
        }

        void operator()() override
        {
            auto h = h_;
            delete this;
            h.resume();
        }

        void destroy() override
        {
            delete this;
        }
    };

    auto* ph = new post_handler(h);
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard lock(mutex_);
        completed_ops_.push(ph);
    }
    wakeup_.notify_one();
}

void
posix_scheduler::
post(capy::execution_context::handler* h) const
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard lock(mutex_);
        completed_ops_.push(h);
    }
    wakeup_.notify_one();
}

void
posix_scheduler::
on_work_started() noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}

void
posix_scheduler::
on_work_finished() noexcept
{
    if (outstanding_work_.fetch_sub(1, std::memory_order_acq_rel) == 1)
        stop();
}

bool
posix_scheduler::
running_in_this_thread() const noexcept
{
    for (auto* c = context_stack.get(); c != nullptr; c = c->next)
        if (c->key == this)
            return true;
    return false;
}

void
posix_scheduler::
stop()
{
    bool expected = false;
    if (stopped_.compare_exchange_strong(expected, true,
            std::memory_order_release, std::memory_order_relaxed))
    {
        std::lock_guard lock(mutex_);
        wakeup_.notify_all();
    }
}

bool
posix_scheduler::
stopped() const noexcept
{
    return stopped_.load(std::memory_order_acquire);
}

void
posix_scheduler::
restart()
{
    stopped_.store(false, std::memory_order_release);
}

std::size_t
posix_scheduler::
run()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);

    std::size_t n = 0;
    while (do_one(-1))
        if (n != (std::numeric_limits<std::size_t>::max)())
            ++n;
    return n;
}

std::size_t
posix_scheduler::
run_one()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);
    return do_one(-1);
}

std::size_t
posix_scheduler::
wait_one(long usec)
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);
    return do_one(usec);
}

std::size_t
posix_scheduler::
poll()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);

    std::size_t n = 0;
    while (do_one(0))
        if (n != (std::numeric_limits<std::size_t>::max)())
            ++n;
    return n;
}

std::size_t
posix_scheduler::
poll_one()
{
    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);
    return do_one(0);
}

// RAII guard - work_finished called even if handler throws
struct work_guard
{
    posix_scheduler* self;
    ~work_guard() { self->on_work_finished(); }
};

std::size_t
posix_scheduler::
do_one(long timeout_us)
{
    std::unique_lock lock(mutex_);

    // Check for available work or wait
    if (timeout_us < 0)
    {
        // Infinite wait
        wakeup_.wait(lock, [this] {
            return stopped_.load(std::memory_order_acquire) ||
                   !completed_ops_.empty();
        });
    }
    else if (timeout_us > 0)
    {
        // Timed wait
        wakeup_.wait_for(lock, std::chrono::microseconds(timeout_us), [this] {
            return stopped_.load(std::memory_order_acquire) ||
                   !completed_ops_.empty();
        });
    }
    // timeout_us == 0: poll, no wait

    if (stopped_.load(std::memory_order_acquire))
        return 0;

    auto* h = completed_ops_.pop();
    if (!h)
        return 0;

    lock.unlock();

    work_guard g{this};
    (*h)();
    return 1;
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif
