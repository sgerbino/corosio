//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_ACCEPTOR_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_ACCEPTOR_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE || \
    BOOST_COROSIO_HAS_SELECT

#include <boost/corosio/endpoint.hpp>

#include <atomic>
#include <mutex>
#include <utility>

#include <errno.h>
#include <unistd.h>

/*
    Reactor Acceptor (CRTP)
    ========================

    Shared cancel_single_op and close_socket logic for acceptor
    implementations across epoll, kqueue, and select backends.

    Derived classes provide:
      svc_             — service ref (post, work_started, work_finished)
      fd_              — file descriptor
      desc_state_      — descriptor state (mutex, op pointers, flags)
      acc_             — accept operation slot
      local_endpoint_  — cached local endpoint
      weak_from_this() — from enable_shared_from_this
      on_pre_close_fd()— backend-specific cleanup before ::close()
*/

namespace boost::corosio::detail {

/** CRTP base providing shared acceptor operations.

    @tparam Derived The concrete acceptor type.
*/
template<typename Derived>
class reactor_acceptor
{
    friend Derived;

    reactor_acceptor() = default;

    Derived& self() noexcept
    {
        return static_cast<Derived&>(*this);
    }

protected:
    /** Cancel a single pending acceptor operation.

        @param op The operation to cancel.
    */
    template<typename Op>
    void do_cancel_single_op(Op& op) noexcept
    {
        auto& s  = self();
        auto ptr = s.weak_from_this().lock();
        if (!ptr)
            return;

        op.request_cancel();

        using op_ptr   = decltype(s.desc_state_.read_op);
        op_ptr claimed = nullptr;
        {
            std::lock_guard lock(s.desc_state_.mutex);
            if (s.desc_state_.read_op == &op)
                claimed = std::exchange(s.desc_state_.read_op, nullptr);
        }
        if (claimed)
        {
            op.impl_ptr = ptr;
            s.svc_.post(&op);
            s.svc_.work_finished();
        }
    }

    /** Close the acceptor, cancelling the pending operation.

        Calls Derived::on_pre_close_fd() for backend-specific
        cleanup before closing the file descriptor.
    */
    void do_close_socket() noexcept
    {
        auto& s  = self();
        auto ptr = s.weak_from_this().lock();
        if (ptr)
        {
            s.acc_.request_cancel();

            using op_ptr   = decltype(s.desc_state_.read_op);
            op_ptr claimed = nullptr;
            {
                std::lock_guard lock(s.desc_state_.mutex);
                claimed = std::exchange(s.desc_state_.read_op, nullptr);
                s.desc_state_.read_ready  = false;
                s.desc_state_.write_ready = false;
            }

            if (claimed)
            {
                s.acc_.impl_ptr = ptr;
                s.svc_.post(&s.acc_);
                s.svc_.work_finished();
            }

            if (s.desc_state_.is_enqueued_.load(std::memory_order_acquire))
                s.desc_state_.impl_ref_ = ptr;
        }

        if (s.fd_ >= 0)
        {
            s.on_pre_close_fd();
            ::close(s.fd_);
            s.fd_ = -1;
        }

        s.desc_state_.fd                = -1;
        s.desc_state_.registered_events = 0;

        s.local_endpoint_ = endpoint{};
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_ACCEPTOR_HPP
