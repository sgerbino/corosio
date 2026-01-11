//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "src/detail/win_iocp_scheduler.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <boost/corosio/detail/except.hpp>

#include <Windows.h>

extern "C" __declspec(dllimport) unsigned long __stdcall GetLastError();

namespace boost {
namespace corosio {
namespace detail {

namespace {

// Completion key used to identify work items
constexpr ULONG_PTR work_key = 1;

// Completion key used to signal shutdown
constexpr ULONG_PTR shutdown_key = 0;

inline system::error_code
last_error() noexcept
{
    return system::error_code(
        static_cast<int>(GetLastError()),
        system::system_category());
}

// Stack frame for tracking nested scheduler contexts
struct scheduler_context
{
    win_iocp_scheduler const* key;
    scheduler_context* next;
};

// Thread-local head of the context stack
capy::thread_local_ptr<scheduler_context> context_stack;

// RAII guard that pushes/pops a frame
struct thread_context_guard
{
    scheduler_context frame_;

    explicit thread_context_guard(win_iocp_scheduler const* ctx) noexcept
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
    capy::execution_context&)
    : iocp_(CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,
        nullptr,
        0,
        0))
{
    if (iocp_ == nullptr)
        detail::throw_system_error(last_error(), "CreateIoCompletionPort failed");
}

win_iocp_scheduler::
~win_iocp_scheduler()
{
    if (iocp_ != nullptr)
    {
        CloseHandle(iocp_);
    }
}

void
win_iocp_scheduler::
shutdown()
{
    // Post a shutdown signal to wake any blocked threads
    ::PostQueuedCompletionStatus(
        iocp_,
        0,
        shutdown_key,
        nullptr);

    // Drain and destroy all pending work items
    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;

    while (::GetQueuedCompletionStatus(
        iocp_,
        &bytes,
        &key,
        &overlapped,
        0)) // Non-blocking
    {
        if (key == work_key && overlapped != nullptr)
        {
            auto* work = reinterpret_cast<capy::executor_work*>(overlapped);
            work->destroy();
        }
        // Ignore shutdown signals during drain
    }
}

void
win_iocp_scheduler::
post(capy::coro h) const
{
    struct coro_work : capy::executor_work
    {
        capy::coro h_;

        explicit coro_work(capy::coro h)
            : h_(h)
        {
        }

        void operator()() override
        {
            // delete before dispatch to enable work recycling
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
post(capy::executor_work* w) const
{
    // Post the work item to the IOCP
    // We use the OVERLAPPED* field to carry the work pointer
    BOOL result = ::PostQueuedCompletionStatus(
        iocp_,
        0,
        work_key,
        reinterpret_cast<LPOVERLAPPED>(w));

    if (!result)
    {
        // If posting fails, destroy the work item
        w->destroy();

        // Claude: do we throw ::GetLastError?
    }
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
    // Post a shutdown signal to wake any blocked threads
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
                break; // Timeout is not an error
            if (overlapped == nullptr)
            {
                // Real error
                ec.assign(static_cast<int>(err), system::system_category());
                break;
            }
            // Completion with error - still process it
        }

        if (key == shutdown_key)
        {
            // Shutdown signal received - re-post for other threads
            ::PostQueuedCompletionStatus(
                iocp_,
                0,
                shutdown_key,
                nullptr);
            break;
        }

        if (key == work_key && overlapped != nullptr)
        {
            (*reinterpret_cast<capy::executor_work*>(overlapped))();
            ++count;
        }

        // After first handler, switch to non-blocking for poll behavior
        if (timeout == 0)
            continue;
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
            return 0; // Timeout is not an error
        if (overlapped == nullptr)
        {
            ec.assign(static_cast<int>(err), system::system_category());
            return 0;
        }
    }

    if (key == shutdown_key)
    {
        // Re-post for other threads
        ::PostQueuedCompletionStatus(
            iocp_,
            0,
            shutdown_key,
            nullptr);
        return 0;
    }

    // Put the completion back for later execution
    if (key == work_key && overlapped != nullptr)
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

std::size_t
win_iocp_scheduler::
run(system::error_code& ec)
{
    std::size_t total = 0;

    while (!stopped())
    {
        std::size_t n = do_run(INFINITE, static_cast<std::size_t>(-1), ec);
        if (ec)
            break;
        if (n == 0)
            break;
        total += n;
    }

    return total;
}

std::size_t
win_iocp_scheduler::
run_one(system::error_code& ec)
{
    return do_run(INFINITE, 1, ec);
}

std::size_t
win_iocp_scheduler::
run_one(long usec, system::error_code& ec)
{
    // Convert microseconds to milliseconds (round up)
    unsigned long timeout_ms = static_cast<unsigned long>((usec + 999) / 1000);
    return do_run(timeout_ms, 1, ec);
}

std::size_t
win_iocp_scheduler::
wait_one(long usec, system::error_code& ec)
{
    // Convert microseconds to milliseconds (round up)
    unsigned long timeout_ms = static_cast<unsigned long>((usec + 999) / 1000);
    return do_wait(timeout_ms, ec);
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
        auto now = std::chrono::steady_clock::now();
        if (now >= abs_time)
            break;

        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            abs_time - now);
        unsigned long timeout = static_cast<unsigned long>(remaining.count());
        if (timeout == 0)
            timeout = 1; // Minimum 1ms to avoid pure poll

        std::size_t n = do_run(timeout, static_cast<std::size_t>(-1), ec);
        total += n;

        if (n == 0 || ec)
            break;
    }

    return total;
}

std::size_t
win_iocp_scheduler::
poll(system::error_code& ec)
{
    return do_run(0, static_cast<std::size_t>(-1), ec);
}

std::size_t
win_iocp_scheduler::
poll_one(system::error_code& ec)
{
    return do_run(0, 1, ec);
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // _WIN32
