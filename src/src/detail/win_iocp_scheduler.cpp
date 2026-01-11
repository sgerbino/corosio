//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "src/detail/win_iocp_scheduler.hpp"
#include "src/detail/win_overlapped_op.hpp"

#include <boost/corosio/detail/except.hpp>
#include <boost/capy/thread_local_ptr.hpp>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <WinSock2.h>
#include <Windows.h>

namespace boost {
namespace corosio {
namespace detail {

namespace {

inline
system::error_code
last_error() noexcept
{
    return system::error_code(
        static_cast<int>(GetLastError()),
        system::system_category());
}

struct scheduler_context
{
    win_iocp_scheduler const* key;
    scheduler_context* next;
};

capy::thread_local_ptr<scheduler_context> context_stack;

struct thread_context_guard
{
    scheduler_context frame_;

    explicit thread_context_guard(
        win_iocp_scheduler const* ctx) noexcept
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

win_iocp_scheduler::
win_iocp_scheduler(
    capy::execution_context&,
    unsigned)
    : iocp_(nullptr)
{
    iocp_ = ::CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,
        nullptr,
        0,
        0);

    if (iocp_ == nullptr)
        detail::throw_system_error(last_error());
}

win_iocp_scheduler::
~win_iocp_scheduler()
{
    if (iocp_ != nullptr)
        ::CloseHandle(iocp_);
}

void
win_iocp_scheduler::
shutdown()
{
    ::PostQueuedCompletionStatus(
        iocp_,
        0,
        shutdown_key,
        nullptr);

    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;

    while (::GetQueuedCompletionStatus(
        iocp_,
        &bytes,
        &key,
        &overlapped,
        0))
    {
        if (overlapped != nullptr)
        {
            if (key == handler_key)
            {
                pending_.fetch_sub(1, std::memory_order_relaxed);
                auto* work = reinterpret_cast<capy::execution_context::handler*>(overlapped);
                work->destroy();
            }
            else if (key == socket_key)
            {
                pending_.fetch_sub(1, std::memory_order_relaxed);
                auto* op = static_cast<overlapped_op*>(overlapped);
                op->destroy();
            }
        }
    }
}

void
win_iocp_scheduler::
post(capy::coro h) const
{
    struct coro_work : capy::execution_context::handler
    {
        capy::coro h_;

        explicit coro_work(capy::coro h)
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

    post(new coro_work(h));
}

void
win_iocp_scheduler::
post(capy::execution_context::handler* h) const
{
    pending_.fetch_add(1, std::memory_order_relaxed);

    BOOL result = ::PostQueuedCompletionStatus(
        iocp_,
        0,
        handler_key,
        reinterpret_cast<LPOVERLAPPED>(h));

    if (!result)
    {
        pending_.fetch_sub(1, std::memory_order_relaxed);
        h->destroy();
    }
}

void
win_iocp_scheduler::
on_work_started() noexcept
{
    outstanding_work_.fetch_add(1, std::memory_order_relaxed);
}

void
win_iocp_scheduler::
on_work_finished() noexcept
{
    outstanding_work_.fetch_sub(1, std::memory_order_relaxed);
}

bool
win_iocp_scheduler::
running_in_this_thread() const noexcept
{
    for (auto* c = context_stack.get(); c != nullptr; c = c->next)
        if (c->key == this)
            return true;
    return false;
}

void
win_iocp_scheduler::
stop()
{
    stopped_.store(true, std::memory_order_release);
    ::PostQueuedCompletionStatus(
        iocp_,
        0,
        shutdown_key,
        nullptr);
}

bool
win_iocp_scheduler::
stopped() const noexcept
{
    return stopped_.load(std::memory_order_acquire);
}

void
win_iocp_scheduler::
restart()
{
    stopped_.store(false, std::memory_order_release);
}

std::size_t
win_iocp_scheduler::
run()
{
    system::error_code ec;
    std::size_t total = 0;

    while (!stopped())
    {
        if (pending_.load(std::memory_order_relaxed) == 0)
            break;

        std::size_t n = do_run(INFINITE, static_cast<std::size_t>(-1), ec);
        if (ec)
            detail::throw_system_error(ec);
        if (n == 0)
            break;
        total += n;
    }

    return total;
}

std::size_t
win_iocp_scheduler::
run_one()
{
    if (pending_.load(std::memory_order_relaxed) == 0)
        return 0;
    system::error_code ec;
    std::size_t n = do_run(INFINITE, 1, ec);
    if (ec)
        detail::throw_system_error(ec);
    return n;
}

std::size_t
win_iocp_scheduler::
run_one(long usec)
{
    unsigned long timeout_ms = static_cast<unsigned long>((usec + 999) / 1000);
    system::error_code ec;
    std::size_t n = do_run(timeout_ms, 1, ec);
    if (ec)
        detail::throw_system_error(ec);
    return n;
}

std::size_t
win_iocp_scheduler::
wait_one(long usec)
{
    unsigned long timeout_ms = static_cast<unsigned long>((usec + 999) / 1000);
    system::error_code ec;
    std::size_t n = do_wait(timeout_ms, ec);
    if (ec)
        detail::throw_system_error(ec);
    return n;
}

std::size_t
win_iocp_scheduler::
run_for(std::chrono::steady_clock::duration rel_time)
{
    auto end_time = std::chrono::steady_clock::now() + rel_time;
    return run_until(end_time);
}

std::size_t
win_iocp_scheduler::
run_until(std::chrono::steady_clock::time_point abs_time)
{
    system::error_code ec;
    std::size_t total = 0;

    while (!stopped())
    {
        if (pending_.load(std::memory_order_relaxed) == 0)
            break;

        auto now = std::chrono::steady_clock::now();
        if (now >= abs_time)
            break;

        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            abs_time - now);
        unsigned long timeout = static_cast<unsigned long>(remaining.count());
        if (timeout == 0)
            timeout = 1;

        std::size_t n = do_run(timeout, static_cast<std::size_t>(-1), ec);
        total += n;

        if (ec)
            detail::throw_system_error(ec);
        if (n == 0)
            break;
    }

    return total;
}

std::size_t
win_iocp_scheduler::
poll()
{
    system::error_code ec;
    std::size_t n = do_run(0, static_cast<std::size_t>(-1), ec);
    if (ec)
        detail::throw_system_error(ec);
    return n;
}

std::size_t
win_iocp_scheduler::
poll_one()
{
    system::error_code ec;
    std::size_t n = do_run(0, 1, ec);
    if (ec)
        detail::throw_system_error(ec);
    return n;
}

void
win_iocp_scheduler::
work_started() const noexcept
{
    pending_.fetch_add(1, std::memory_order_relaxed);
}

void
win_iocp_scheduler::
work_finished() const noexcept
{
    pending_.fetch_sub(1, std::memory_order_relaxed);
}

std::size_t
win_iocp_scheduler::
do_run(unsigned long timeout, std::size_t max_handlers,
    system::error_code& ec)
{
    thread_context_guard guard(this);
    ec.clear();
    std::size_t count = 0;
    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;

    while (count < max_handlers && !stopped())
    {
        unsigned long actual_timeout = timeout;
        if (count > 0 && timeout != 0)
        {
            if (pending_.load(std::memory_order_relaxed) == 0)
                break;
        }

        BOOL result = ::GetQueuedCompletionStatus(
            iocp_,
            &bytes,
            &key,
            &overlapped,
            actual_timeout);

        if (!result)
        {
            DWORD err = ::GetLastError();
            if (err == WAIT_TIMEOUT)
                break;
            if (overlapped == nullptr)
            {
                ec.assign(static_cast<int>(err), system::system_category());
                break;
            }
        }

        if (key == shutdown_key)
        {
            if (stopped())
            {
                ::PostQueuedCompletionStatus(
                    iocp_,
                    0,
                    shutdown_key,
                    nullptr);
                break;
            }
            continue;
        }

        if (overlapped != nullptr)
        {
            if (key == handler_key)
            {
                pending_.fetch_sub(1, std::memory_order_relaxed);
                (*reinterpret_cast<capy::execution_context::handler*>(overlapped))();
                ++count;
            }
            else if (key == socket_key)
            {
                pending_.fetch_sub(1, std::memory_order_relaxed);
                auto* op = static_cast<overlapped_op*>(overlapped);
                DWORD err = result ? 0 : ::GetLastError();
                op->complete(bytes, err);
                (*op)();
                ++count;
            }
        }
    }

    return count;
}

std::size_t
win_iocp_scheduler::
do_wait(unsigned long timeout, system::error_code& ec)
{
    ec.clear();
    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;

    if (stopped())
        return 0;

    BOOL result = ::GetQueuedCompletionStatus(
        iocp_,
        &bytes,
        &key,
        &overlapped,
        timeout);

    if (!result)
    {
        DWORD err = ::GetLastError();
        if (err == WAIT_TIMEOUT)
            return 0;
        if (overlapped == nullptr)
        {
            ec.assign(static_cast<int>(err), system::system_category());
            return 0;
        }
    }

    if (key == shutdown_key)
    {
        if (stopped())
        {
            ::PostQueuedCompletionStatus(
                iocp_,
                0,
                shutdown_key,
                nullptr);
        }
        return 0;
    }

    if (overlapped != nullptr && (key == handler_key || key == socket_key))
    {
        ::PostQueuedCompletionStatus(
            iocp_,
            bytes,
            key,
            overlapped);
        return 1;
    }

    return 0;
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // _WIN32
