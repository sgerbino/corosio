//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_ACCEPTOR_SERVICE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_ACCEPTOR_SERVICE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/detail/intrusive.hpp>
#include <boost/corosio/detail/socket_service.hpp>
#include <boost/corosio/io/io_object.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/native/detail/endpoint_convert.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/capy/ex/execution_context.hpp>

#include <memory>
#include <mutex>
#include <unordered_map>

#include <netinet/in.h>
#include <sys/socket.h>

/*
    Reactor Acceptor Service (CRTP)
    ===============================

    Shared service boilerplate for acceptor services across epoll,
    kqueue, and select backends. Provides the state class,
    construct/destroy/shutdown/close lifecycle, scheduler delegation,
    bind/listen, and socket_service lookup.

    Derived classes provide:
      - Impl type (the concrete acceptor, e.g. epoll_acceptor)
      - Scheduler type
      - SocketService type (for peer socket creation during accept)
      - open_acceptor_socket() — platform-specific fd creation
*/

namespace boost::corosio::detail {

/** Shared state for reactor acceptor services.

    @tparam Impl The concrete acceptor type.
    @tparam Scheduler The concrete scheduler type.
*/
template<typename Impl, typename Scheduler>
class reactor_acceptor_state
{
public:
    explicit reactor_acceptor_state(Scheduler& sched) noexcept : sched_(sched)
    {
    }

    Scheduler& sched_;
    std::mutex mutex_;
    intrusive_list<Impl> acceptor_list_;
    std::unordered_map<Impl*, std::shared_ptr<Impl>> acceptor_ptrs_;
};

/** CRTP base providing shared acceptor service operations.

    @tparam Derived The concrete acceptor service type.
    @tparam Impl The concrete acceptor type.
    @tparam Scheduler The concrete scheduler type.
    @tparam SocketService The concrete socket service type.
*/
template<
    typename Derived,
    typename Impl,
    typename Scheduler,
    typename SocketService>
class reactor_acceptor_service
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

    using state_type = reactor_acceptor_state<Impl, Scheduler>;

    explicit reactor_acceptor_service(capy::execution_context& ctx)
        : ctx_(ctx)
        , state_(std::make_unique<state_type>(ctx.use_service<Scheduler>()))
    {
    }

    ~reactor_acceptor_service() = default;

    /// Return a reference to the scheduler.
    Scheduler& do_scheduler() const noexcept
    {
        return state_->sched_;
    }

    /** Shut down the service, closing all acceptors.

        Does not clear the shared_ptr map — same rationale as
        socket services.
    */
    void do_shutdown()
    {
        std::lock_guard lock(state_->mutex_);

        while (auto* impl = state_->acceptor_list_.pop_front())
            impl->close_socket();
    }

    /// Construct a new acceptor implementation.
    io_object::implementation* do_construct()
    {
        auto impl = std::make_shared<Impl>(self());
        auto* raw = impl.get();

        std::lock_guard lock(state_->mutex_);
        state_->acceptor_list_.push_back(raw);
        state_->acceptor_ptrs_.emplace(raw, std::move(impl));

        return raw;
    }

    /// Destroy an acceptor implementation.
    void do_destroy(io_object::implementation* impl)
    {
        auto* typed = static_cast<Impl*>(impl);
        typed->close_socket();
        std::lock_guard lock(state_->mutex_);
        state_->acceptor_list_.remove(typed);
        state_->acceptor_ptrs_.erase(typed);
    }

    /// Close an acceptor without removing from the service map.
    void do_close(io_object::handle& h)
    {
        static_cast<Impl*>(h.get())->close_socket();
    }

    /** Bind an acceptor to a local endpoint.

        Calls `::bind()` and caches the resolved local endpoint
        (including ephemeral port).
    */
    std::error_code
    do_bind_acceptor(tcp_acceptor::implementation& impl, endpoint ep)
    {
        auto* typed = static_cast<Impl*>(&impl);
        int fd      = typed->fd_;

        sockaddr_storage storage{};
        socklen_t addrlen = detail::to_sockaddr(ep, storage);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&storage), addrlen) < 0)
            return make_err(errno);

        sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(
                fd, reinterpret_cast<sockaddr*>(&local), &local_len) == 0)
            typed->set_local_endpoint(detail::from_sockaddr(local));

        return {};
    }

    /** Start listening and register with the reactor.

        Calls `::listen()` then registers the descriptor with the
        scheduler for event monitoring.
    */
    std::error_code
    do_listen_acceptor(tcp_acceptor::implementation& impl, int backlog)
    {
        auto* typed = static_cast<Impl*>(&impl);
        int fd      = typed->fd_;

        if (::listen(fd, backlog) < 0)
            return make_err(errno);

        do_scheduler().register_descriptor(fd, &typed->desc_state_);

        return {};
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

    /** Look up the socket service for creating peer sockets.

        @return Pointer to the socket service, or nullptr if not found.
    */
    SocketService* do_socket_service() const noexcept
    {
        auto* svc = ctx_.find_service<detail::socket_service>();
        return svc ? dynamic_cast<SocketService*>(svc) : nullptr;
    }

    capy::execution_context& ctx_;
    std::unique_ptr<state_type> state_;
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_ACCEPTOR_SERVICE_HPP
