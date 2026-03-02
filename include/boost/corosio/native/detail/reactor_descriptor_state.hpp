//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_DESCRIPTOR_STATE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_DESCRIPTOR_STATE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/scheduler_op.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>

/*
    Reactor Descriptor State
    ========================

    Shared base for per-descriptor state across the reactor backends
    (epoll, kqueue, select). Each backend derives a final struct that
    overrides operator()() with backend-specific deferred I/O dispatch.

    The template is parameterized on:
      - Op: the base operation type (e.g. reactor_op<epoll_backend>)
      - Scheduler: the backend scheduler (e.g. epoll_scheduler)

    Only pointers to these types are stored, so forward declarations
    suffice at the point of template instantiation.
*/

namespace boost::corosio::detail {

/** Per-descriptor state shared across reactor backends.

    Tracks pending operations, readiness flags, and cancellation state
    for a single file descriptor. The fd is registered once with the
    backend reactor and stays registered until closed.

    @par Thread Safety
    The mutex protects operation pointers and ready flags during I/O.
    ready_events_ and is_enqueued_ are atomic for lock-free reactor access.

    @tparam Op Base operation type for this backend.
    @tparam Scheduler Backend scheduler type.
*/
template<typename Op, typename Scheduler>
struct reactor_descriptor_state : scheduler_op
{
    std::mutex mutex;

    // Protected by mutex
    Op* read_op    = nullptr;
    Op* write_op   = nullptr;
    Op* connect_op = nullptr;

    // Caches edge events that arrived before an op was registered
    bool read_ready  = false;
    bool write_ready = false;

    // Deferred cancellation: set by cancel() when the target op is not
    // parked (e.g. completing inline via speculative I/O). Checked when
    // the next op parks; if set, the op is immediately self-cancelled.
    // This matches IOCP semantics where CancelIoEx always succeeds.
    bool read_cancel_pending    = false;
    bool write_cancel_pending   = false;
    bool connect_cancel_pending = false;

    // Set during registration only (no mutex needed)
    std::uint32_t registered_events = 0;
    int fd                          = -1;

    // For deferred I/O - set by reactor, read by scheduler
    std::atomic<std::uint32_t> ready_events_{0};
    std::atomic<bool> is_enqueued_{false};
    Scheduler const* scheduler_ = nullptr;

    // Prevents impl destruction while this descriptor_state is queued.
    // Set by close_socket() when is_enqueued_ is true, cleared by operator().
    std::shared_ptr<void> impl_ref_;

    /// Lock the mutex and null all three op pointers.
    void init_ops() noexcept
    {
        std::lock_guard lock(mutex);
        read_op    = nullptr;
        write_op   = nullptr;
        connect_op = nullptr;
    }

    /// Add ready events atomically.
    /// Release pairs with the consumer's acquire exchange on
    /// ready_events_ so the consumer sees all flags.
    void add_ready_events(std::uint32_t ev) noexcept
    {
        ready_events_.fetch_or(ev, std::memory_order_release);
    }

    /// Destroy without invoking.
    /// Called during scheduler::shutdown() drain. Clear impl_ref_ to break
    /// the self-referential cycle set by close_socket().
    void destroy() override
    {
        impl_ref_.reset();
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_DESCRIPTOR_STATE_HPP
