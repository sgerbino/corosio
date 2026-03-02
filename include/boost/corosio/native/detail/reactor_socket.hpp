//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_HPP

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
    Reactor Socket (CRTP)
    ======================

    Shared register_op, cancel, cancel_single_op, and close_socket
    logic for socket implementations across epoll, kqueue, and
    select backends.

    Derived classes provide:
      svc_             — service ref (post, work_started, work_finished)
      fd_              — file descriptor
      desc_state_      — descriptor state (mutex, op pointers, flags)
      conn_, rd_, wr_  — operation slots
      local_endpoint_  — cached local endpoint
      remote_endpoint_ — cached remote endpoint
      weak_from_this() — from enable_shared_from_this
      on_pre_close_fd()— backend-specific cleanup before ::close()
*/

namespace boost::corosio::detail {

/** CRTP base providing shared socket operations.

    @tparam Derived The concrete socket type.
*/
template<typename Derived>
class reactor_socket
{
    friend Derived;

    reactor_socket() = default;

    Derived& self() noexcept
    {
        return static_cast<Derived&>(*this);
    }

protected:
    // Default no-ops; select shadows these to call start_op()
    void on_register_read() noexcept {}
    void on_register_write() noexcept {}

    /** Register an op with the reactor under the descriptor mutex.

        Retries cached readiness before parking, checks pending
        cancellation, and posts immediately if I/O completed or
        cancel was requested.

        @param op The operation to register.
        @param desc_slot Descriptor state slot for this op direction.
        @param ready_flag Cached readiness flag.
        @param cancel_flag Pending cancel flag.
    */
    template<typename ConcreteOp, typename BaseOp>
    void do_register_op(
        ConcreteOp& op,
        BaseOp*& desc_slot,
        bool& ready_flag,
        bool& cancel_flag) noexcept
    {
        auto& s = self();
        s.svc_.work_started();

        std::lock_guard lock(s.desc_state_.mutex);
        bool io_done = false;
        if (ready_flag)
        {
            ready_flag = false;
            op.perform_io();
            io_done = (op.errn != EAGAIN && op.errn != EWOULDBLOCK);
            if (!io_done)
                op.errn = 0;
        }

        if (cancel_flag)
        {
            cancel_flag = false;
            op.cancelled.store(true, std::memory_order_relaxed);
        }

        if (io_done || op.cancelled.load(std::memory_order_acquire))
        {
            s.svc_.post(&op);
            s.svc_.work_finished();
        }
        else
        {
            desc_slot = &op;
        }
    }

    /** Cancel all pending operations on this socket. */
    void do_cancel() noexcept
    {
        auto& s  = self();
        auto ptr = s.weak_from_this().lock();
        if (!ptr)
            return;

        s.conn_.request_cancel();
        s.rd_.request_cancel();
        s.wr_.request_cancel();

        using op_ptr        = decltype(s.desc_state_.read_op);
        op_ptr conn_claimed = nullptr;
        op_ptr rd_claimed   = nullptr;
        op_ptr wr_claimed   = nullptr;
        {
            std::lock_guard lock(s.desc_state_.mutex);
            if (s.desc_state_.connect_op == &s.conn_)
                conn_claimed = std::exchange(s.desc_state_.connect_op, nullptr);
            else
                s.desc_state_.connect_cancel_pending = true;
            if (s.desc_state_.read_op == &s.rd_)
                rd_claimed = std::exchange(s.desc_state_.read_op, nullptr);
            else
                s.desc_state_.read_cancel_pending = true;
            if (s.desc_state_.write_op == &s.wr_)
                wr_claimed = std::exchange(s.desc_state_.write_op, nullptr);
            else
                s.desc_state_.write_cancel_pending = true;
        }

        if (conn_claimed)
        {
            s.conn_.impl_ptr = ptr;
            s.svc_.post(&s.conn_);
            s.svc_.work_finished();
        }
        if (rd_claimed)
        {
            s.rd_.impl_ptr = ptr;
            s.svc_.post(&s.rd_);
            s.svc_.work_finished();
        }
        if (wr_claimed)
        {
            s.wr_.impl_ptr = ptr;
            s.svc_.post(&s.wr_);
            s.svc_.work_finished();
        }
    }

    /** Cancel a single pending operation.

        @param op The specific operation to cancel.
    */
    template<typename Op>
    void do_cancel_single_op(Op& op) noexcept
    {
        auto& s  = self();
        auto ptr = s.weak_from_this().lock();
        if (!ptr)
            return;

        op.request_cancel();

        using op_ptr        = decltype(s.desc_state_.read_op);
        op_ptr* desc_op_ptr = nullptr;
        if (&op == &s.conn_)
            desc_op_ptr = &s.desc_state_.connect_op;
        else if (&op == &s.rd_)
            desc_op_ptr = &s.desc_state_.read_op;
        else if (&op == &s.wr_)
            desc_op_ptr = &s.desc_state_.write_op;

        if (desc_op_ptr)
        {
            op_ptr claimed = nullptr;
            {
                std::lock_guard lock(s.desc_state_.mutex);
                if (*desc_op_ptr == &op)
                    claimed = std::exchange(*desc_op_ptr, nullptr);
                else if (&op == &s.conn_)
                    s.desc_state_.connect_cancel_pending = true;
                else if (&op == &s.rd_)
                    s.desc_state_.read_cancel_pending = true;
                else if (&op == &s.wr_)
                    s.desc_state_.write_cancel_pending = true;
            }
            if (claimed)
            {
                op.impl_ptr = ptr;
                s.svc_.post(&op);
                s.svc_.work_finished();
            }
        }
    }

    /** Close the socket, cancelling all pending operations.

        Calls Derived::on_pre_close_fd() for backend-specific
        cleanup before closing the file descriptor.
    */
    void do_close_socket() noexcept
    {
        auto& s  = self();
        auto ptr = s.weak_from_this().lock();
        if (ptr)
        {
            s.conn_.request_cancel();
            s.rd_.request_cancel();
            s.wr_.request_cancel();

            using op_ptr        = decltype(s.desc_state_.read_op);
            op_ptr conn_claimed = nullptr;
            op_ptr rd_claimed   = nullptr;
            op_ptr wr_claimed   = nullptr;
            {
                std::lock_guard lock(s.desc_state_.mutex);
                conn_claimed = std::exchange(s.desc_state_.connect_op, nullptr);
                rd_claimed   = std::exchange(s.desc_state_.read_op, nullptr);
                wr_claimed   = std::exchange(s.desc_state_.write_op, nullptr);
                s.desc_state_.read_ready             = false;
                s.desc_state_.write_ready            = false;
                s.desc_state_.read_cancel_pending    = false;
                s.desc_state_.write_cancel_pending   = false;
                s.desc_state_.connect_cancel_pending = false;
            }

            if (conn_claimed)
            {
                s.conn_.impl_ptr = ptr;
                s.svc_.post(&s.conn_);
                s.svc_.work_finished();
            }
            if (rd_claimed)
            {
                s.rd_.impl_ptr = ptr;
                s.svc_.post(&s.rd_);
                s.svc_.work_finished();
            }
            if (wr_claimed)
            {
                s.wr_.impl_ptr = ptr;
                s.svc_.post(&s.wr_);
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

        s.local_endpoint_  = endpoint{};
        s.remote_endpoint_ = endpoint{};
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_EPOLL || BOOST_COROSIO_HAS_KQUEUE ||
       // BOOST_COROSIO_HAS_SELECT

#endif // BOOST_COROSIO_NATIVE_DETAIL_REACTOR_SOCKET_HPP
