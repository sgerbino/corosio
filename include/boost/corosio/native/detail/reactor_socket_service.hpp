//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/intrusive.hpp>
#include <boost/corosio/io/io_object.hpp>
#include <boost/capy/ex/execution_context.hpp>

#include <memory>
#include <mutex>
#include <unordered_map>

/*
    Reactor Socket Service (CRTP)
    =============================

    Shared service boilerplate for socket services across epoll,
    kqueue, and select backends. Provides the state class,
    construct/destroy/shutdown/close lifecycle, and scheduler
    delegation (post, work_started, work_finished).

    Derived classes provide:
      - Impl type (the concrete socket, e.g. epoll_socket)
      - Scheduler type
      - open_socket() — platform-specific fd creation

    Customization points (default no-op):
      - on_pre_shutdown(Impl*) — kqueue clears SO_LINGER
      - on_pre_destroy(Impl*) — kqueue clears SO_LINGER
*/

namespace boost::corosio::detail {

/** Shared state for reactor socket services.

    @tparam Impl The concrete socket type.
    @tparam Scheduler The concrete scheduler type.
*/
template<typename Impl, typename Scheduler>
class reactor_socket_state
{
public:
    explicit reactor_socket_state(Scheduler& sched) noexcept : sched_(sched) {}

    Scheduler& sched_;
    std::mutex mutex_;
    intrusive_list<Impl> socket_list_;
    std::unordered_map<Impl*, std::shared_ptr<Impl>> socket_ptrs_;
};

/** CRTP base providing shared socket service operations.

    @tparam Derived The concrete socket service type.
    @tparam Impl The concrete socket type.
    @tparam Scheduler The concrete scheduler type.
*/
template<typename Derived, typename Impl, typename Scheduler>
class reactor_socket_service
{
    friend Derived;

    Derived& self() noexcept
    {
        return static_cast<Derived&>(*this);
    }

    Derived const& self() const noexcept
    {
        return static_cast<Derived const&>(*this);
    }

    using state_type = reactor_socket_state<Impl, Scheduler>;

    explicit reactor_socket_service(capy::execution_context& ctx)
        : state_(std::make_unique<state_type>(ctx.use_service<Scheduler>()))
    {
    }

    ~reactor_socket_service() = default;

    /// Return a reference to the scheduler.
    Scheduler& do_scheduler() const noexcept
    {
        return state_->sched_;
    }

    /** Shut down the service, closing all sockets.

        Calls `self().on_pre_shutdown(impl)` before closing each socket.
        Does not clear the shared_ptr map — the scheduler drains queued
        ops after service shutdown, and ~state_ releases ptrs during
        service destruction.
    */
    void do_shutdown()
    {
        std::lock_guard lock(state_->mutex_);

        while (auto* impl = state_->socket_list_.pop_front())
        {
            self().on_pre_shutdown(impl);
            impl->close_socket();
        }
    }

    /// Construct a new socket implementation.
    io_object::implementation* do_construct()
    {
        auto impl = std::make_shared<Impl>(self());
        auto* raw = impl.get();

        {
            std::lock_guard lock(state_->mutex_);
            state_->socket_list_.push_back(raw);
            state_->socket_ptrs_.emplace(raw, std::move(impl));
        }

        return raw;
    }

    /** Destroy a socket implementation.

        Calls `self().on_pre_destroy(impl)` before closing.
    */
    void do_destroy(io_object::implementation* impl)
    {
        auto* typed = static_cast<Impl*>(impl);
        self().on_pre_destroy(typed);
        typed->close_socket();
        std::lock_guard lock(state_->mutex_);
        state_->socket_list_.remove(typed);
        state_->socket_ptrs_.erase(typed);
    }

    /// Close a socket without removing from the service map.
    void do_close(io_object::handle& h)
    {
        static_cast<Impl*>(h.get())->close_socket();
    }

    /// Post an operation to the scheduler.
    template<typename Op>
    void do_post(Op* op)
    {
        state_->sched_.post(op);
    }

    /// Notify the scheduler that work has started.
    void do_work_started() noexcept
    {
        state_->sched_.work_started();
    }

    /// Notify the scheduler that work has finished.
    void do_work_finished() noexcept
    {
        state_->sched_.work_finished();
    }

    // Default no-op hooks for CRTP customization
    void on_pre_shutdown(Impl*) noexcept {}
    void on_pre_destroy(Impl*) noexcept {}

    std::unique_ptr<state_type> state_;
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_SERVICE_HPP
