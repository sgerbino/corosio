//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "src/detail/config_backend.hpp"

#if defined(BOOST_COROSIO_BACKEND_EPOLL)

#include "src/detail/epoll/scheduler.hpp"
#include "src/detail/epoll/op.hpp"
#include "src/detail/make_err.hpp"

#include <boost/corosio/detail/except.hpp>
#include <boost/capy/core/thread_local_ptr.hpp>

#include <algorithm>
#include <chrono>
#include <limits>

#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

/*
    epoll Scheduler
    ===============

    The scheduler is the heart of the I/O event loop. It multiplexes I/O
    readiness notifications from epoll with a completion queue for operations
    that finished synchronously or were cancelled.

    Event Loop Structure (do_one)
    -----------------------------
    1. Check completion queue first (mutex-protected)
    2. If empty, call epoll_wait with calculated timeout
    3. Process timer expirations
    4. For each ready fd, claim the operation and perform I/O
    5. Push completed operations to completion queue
    6. Pop one and invoke its handler

    The completion queue exists because handlers must run outside the epoll
    processing loop. This allows handlers to safely start new operations
    on the same fd without corrupting iteration state.

    Wakeup Mechanism
    ----------------
    An eventfd allows other threads (or cancel/post calls) to wake the
    event loop from epoll_wait. We distinguish wakeup events from I/O by
    storing nullptr in epoll_event.data.ptr for the eventfd.

    Work Counting
    -------------
    outstanding_work_ tracks pending operations. When it hits zero, run()
    returns. This is how io_context knows there's nothing left to do.
    Each operation increments on start, decrements on completion.

    Timer Integration
    -----------------
    Timers are handled by timer_service. The scheduler adjusts epoll_wait
    timeout to wake in time for the nearest timer expiry. When a new timer
    is scheduled earlier than current, timer_service calls wakeup() to
    re-evaluate the timeout.
*/

namespace boost {
namespace corosio {
namespace detail {

namespace {

struct scheduler_context
{
    epoll_scheduler const* key;
    scheduler_context* next;
};

capy::thread_local_ptr<scheduler_context> context_stack;

struct thread_context_guard
{
    scheduler_context frame_;

    explicit thread_context_guard(
        epoll_scheduler const* ctx) noexcept
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

epoll_scheduler::
epoll_scheduler(
    capy::execution_context& ctx,
    int)
    : epoll_fd_(-1)
    , event_fd_(-1)
    , outstanding_work_(0)
    , stopped_(false)
    , shutdown_(false)
{
    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0)
        detail::throw_system_error(make_err(errno), "epoll_create1");

    event_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event_fd_ < 0)
    {
        int errn = errno;
        ::close(epoll_fd_);
        detail::throw_system_error(make_err(errn), "eventfd");
    }

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.ptr = nullptr;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, event_fd_, &ev) < 0)
    {
        int errn = errno;
        ::close(event_fd_);
        ::close(epoll_fd_);
        detail::throw_system_error(make_err(errn), "epoll_ctl");
    }

    timer_svc_ = &get_timer_service(ctx, *this);
    timer_svc_->set_on_earliest_changed(
        timer_service::callback(
            this,
            [](void* p) { static_cast<epoll_scheduler*>(p)->wakeup(); }));
}

epoll_scheduler::
~epoll_scheduler()
{
    if (event_fd_ >= 0)
        ::close(event_fd_);
    if (epoll_fd_ >= 0)
        ::close(epoll_fd_);
}

void
epoll_scheduler::
shutdown()
{
    std::unique_lock lock(mutex_);
    shutdown_ = true;

    while (auto* h = completed_ops_.pop())
    {
        lock.unlock();
        h->destroy();
        lock.lock();
    }

    outstanding_work_.store(0, std::memory_order_release);
}

void
epoll_scheduler::
post(capy::any_coro h) const
{
    struct post_handler final
        : scheduler_op
    {
        capy::any_coro h_;

        explicit
        post_handler(capy::any_coro h)
            : h_(h)
        {
        }

        ~post_handler() = default;

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
    wakeup();
}

void
epoll_scheduler::
post(scheduler_op* h) const
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard lock(mutex_);
        completed_ops_.push(h);
    }
    wakeup();
}

void
epoll_scheduler::
on_work_started() noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}

void
epoll_scheduler::
on_work_finished() noexcept
{
    if (outstanding_work_.fetch_sub(1, std::memory_order_acq_rel) == 1)
        stop();
}

bool
epoll_scheduler::
running_in_this_thread() const noexcept
{
    for (auto* c = context_stack.get(); c != nullptr; c = c->next)
        if (c->key == this)
            return true;
    return false;
}

void
epoll_scheduler::
stop()
{
    bool expected = false;
    if (stopped_.compare_exchange_strong(expected, true,
            std::memory_order_release, std::memory_order_relaxed))
    {
        wakeup();
    }
}

bool
epoll_scheduler::
stopped() const noexcept
{
    return stopped_.load(std::memory_order_acquire);
}

void
epoll_scheduler::
restart()
{
    stopped_.store(false, std::memory_order_release);
}

std::size_t
epoll_scheduler::
run()
{
    if (stopped_.load(std::memory_order_acquire))
        return 0;

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
epoll_scheduler::
run_one()
{
    if (stopped_.load(std::memory_order_acquire))
        return 0;

    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);
    return do_one(-1);
}

std::size_t
epoll_scheduler::
wait_one(long usec)
{
    if (stopped_.load(std::memory_order_acquire))
        return 0;

    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);
    return do_one(usec);
}

std::size_t
epoll_scheduler::
poll()
{
    if (stopped_.load(std::memory_order_acquire))
        return 0;

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
epoll_scheduler::
poll_one()
{
    if (stopped_.load(std::memory_order_acquire))
        return 0;

    if (outstanding_work_.load(std::memory_order_acquire) == 0)
    {
        stop();
        return 0;
    }

    thread_context_guard ctx(this);
    return do_one(0);
}

void
epoll_scheduler::
register_fd(int fd, epoll_op* op, std::uint32_t events) const
{
    epoll_event ev{};
    ev.events = events;
    ev.data.ptr = op;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0)
        detail::throw_system_error(make_err(errno), "epoll_ctl ADD");
}

void
epoll_scheduler::
modify_fd(int fd, epoll_op* op, std::uint32_t events) const
{
    epoll_event ev{};
    ev.events = events;
    ev.data.ptr = op;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0)
        detail::throw_system_error(make_err(errno), "epoll_ctl MOD");
}

void
epoll_scheduler::
unregister_fd(int fd) const
{
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
}

void
epoll_scheduler::
work_started() const noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}

void
epoll_scheduler::
work_finished() const noexcept
{
    outstanding_work_.fetch_sub(1, std::memory_order_acq_rel);
}

void
epoll_scheduler::
wakeup() const
{
    std::uint64_t val = 1;
    [[maybe_unused]] auto r = ::write(event_fd_, &val, sizeof(val));
}

struct work_guard
{
    epoll_scheduler const* self;
    ~work_guard() { self->work_finished(); }
};

long
epoll_scheduler::
calculate_timeout(long requested_timeout_us) const
{
    if (requested_timeout_us == 0)
        return 0;

    auto nearest = timer_svc_->nearest_expiry();
    if (nearest == timer_service::time_point::max())
        return requested_timeout_us;

    auto now = std::chrono::steady_clock::now();
    if (nearest <= now)
        return 0;

    auto timer_timeout_us = std::chrono::duration_cast<std::chrono::microseconds>(
        nearest - now).count();

    if (requested_timeout_us < 0)
        return static_cast<long>(timer_timeout_us);

    return static_cast<long>((std::min)(
        static_cast<long long>(requested_timeout_us),
        static_cast<long long>(timer_timeout_us)));
}

std::size_t
epoll_scheduler::
do_one(long timeout_us)
{
    for (;;)
    {
        if (stopped_.load(std::memory_order_acquire))
            return 0;

        scheduler_op* h = nullptr;
        {
            std::lock_guard lock(mutex_);
            h = completed_ops_.pop();
        }

        if (h)
        {
            work_guard g{this};
            (*h)();
            return 1;
        }

        if (outstanding_work_.load(std::memory_order_acquire) == 0)
            return 0;

        long effective_timeout_us = calculate_timeout(timeout_us);

        int timeout_ms;
        if (effective_timeout_us < 0)
            timeout_ms = -1;
        else if (effective_timeout_us == 0)
            timeout_ms = 0;
        else
            timeout_ms = static_cast<int>((effective_timeout_us + 999) / 1000);

        epoll_event events[64];
        int nfds = ::epoll_wait(epoll_fd_, events, 64, timeout_ms);

        if (nfds < 0)
        {
            if (errno == EINTR)
            {
                if (timeout_us < 0)
                    continue;
                return 0;
            }
            detail::throw_system_error(make_err(errno), "epoll_wait");
        }

        timer_svc_->process_expired();

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.ptr == nullptr)
            {
                std::uint64_t val;
                [[maybe_unused]] auto r = ::read(event_fd_, &val, sizeof(val));
                continue;
            }

            auto* op = static_cast<epoll_op*>(events[i].data.ptr);

            bool was_registered = op->registered.exchange(false, std::memory_order_acq_rel);
            if (!was_registered)
                continue;

            unregister_fd(op->fd);

            if (events[i].events & (EPOLLERR | EPOLLHUP))
            {
                int errn = 0;
                socklen_t len = sizeof(errn);
                if (::getsockopt(op->fd, SOL_SOCKET, SO_ERROR, &errn, &len) < 0)
                    errn = errno;
                if (errn == 0)
                    errn = EIO;
                op->complete(errn, 0);
            }
            else
            {
                op->perform_io();
            }

            {
                std::lock_guard lock(mutex_);
                completed_ops_.push(op);
            }
        }

        if (stopped_.load(std::memory_order_acquire))
            return 0;

        {
            std::lock_guard lock(mutex_);
            h = completed_ops_.pop();
        }

        if (h)
        {
            work_guard g{this};
            (*h)();
            return 1;
        }

        if (timeout_us >= 0)
            return 0;
    }
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif
