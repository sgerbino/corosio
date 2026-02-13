//
// Copyright (c) 2025 Vinnie Falco (vinnie.falco@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_IO_OBJECT_HPP
#define BOOST_COROSIO_IO_OBJECT_HPP

#include <boost/corosio/detail/config.hpp>
#include <boost/capy/ex/execution_context.hpp>

#include <memory>
#include <utility>

namespace boost::corosio {

/** Base class for platform I/O objects.

    Provides common infrastructure for I/O objects that wrap kernel
    resources (sockets, timers, signal handlers, acceptors). Derived
    classes dispatch operations through a platform-specific vtable
    (IOCP, epoll, kqueue, io_uring).

    @par Semantics
    Only concrete platform I/O types should inherit from `io_object`.
    Test mocks, decorators, and stream adapters must not inherit from
    this class. Use concepts or templates for generic I/O algorithms.

    @par Thread Safety
    Distinct objects: Safe.
    Shared objects: Unsafe. All operations on a single I/O object
    must be serialized.

    @note Intended as a protected base class. The handle `h_` is
        accessible to derived classes.

    @see io_stream, tcp_socket, tcp_acceptor
*/
class BOOST_COROSIO_DECL io_object
{
public:
    /** Polymorphic base for platform-specific implementations.

        Each backend (epoll, select, kqueue, IOCP) provides concrete
        types that derive from this through intermediate interfaces
        (socket_impl, acceptor_impl, timer_impl, etc.).
    */
    struct implementation
    {
        virtual ~implementation() = default;
    };

    class handle;

    /** Service interface for closing I/O objects.

        Platform backends implement this to release kernel resources
        (file descriptors, IOCP handles) and remove the implementation
        from service tracking structures.
    */
    struct io_service
    {
        virtual ~io_service() = default;

        /// Close the I/O object, releasing kernel resources.
        virtual void close(handle&) = 0;
    };

    /** Ownership wrapper for I/O object implementations.

        Holds a `shared_ptr<implementation>` as the master reference.
        In-flight operations extend the implementation's lifetime
        via `shared_from_this()`.
    */
    class handle
    {
        io_service* svc_ = nullptr;
        std::shared_ptr<implementation> impl_;

    public:
        /// Close the I/O object if this handle still owns one.
        ~handle()
        {
            if (impl_ && svc_)
                svc_->close(*this);
        }

        /// Construct an empty handle.
        handle() = default;

        /// Construct a handle with a service and implementation.
        handle(
            io_service& svc,
            std::shared_ptr<implementation> impl) noexcept
            : svc_(&svc)
            , impl_(std::move(impl))
        {
        }

        /// Construct a handle without a service (timers, signals, resolver).
        explicit
        handle(
            std::shared_ptr<implementation> impl) noexcept
            : impl_(std::move(impl))
        {
        }

        /// Move construct from another handle.
        handle(handle&& other) noexcept
            : svc_(std::exchange(other.svc_, nullptr))
            , impl_(std::move(other.impl_))
        {
        }

        /// Move assign from another handle.
        handle& operator=(handle&& other) noexcept
        {
            svc_ = std::exchange(other.svc_, nullptr);
            impl_ = std::move(other.impl_);
            return *this;
        }

        handle(handle const&) = delete;
        handle& operator=(handle const&) = delete;

        /// Return true if the handle holds an implementation.
        explicit operator bool() const noexcept
        {
            return impl_ != nullptr;
        }

        /// Return the platform implementation.
        implementation* get() const noexcept
        {
            return impl_.get();
        }

        /// Return the associated I/O service.
        io_service& service() const noexcept
        {
            return *svc_;
        }

        /// Release the implementation and clear the service.
        void reset() noexcept
        {
            impl_.reset();
            svc_ = nullptr;
        }
    };

    /// Return the execution context.
    capy::execution_context&
    context() const noexcept
    {
        return *ctx_;
    }

protected:
    virtual ~io_object() = default;

    /// Construct an I/O object bound to the given context.
    explicit
    io_object(
        capy::execution_context& ctx) noexcept
        : ctx_(&ctx)
    {
    }

    io_object(io_object&&) noexcept = default;
    io_object& operator=(io_object&&) noexcept = default;
    io_object(io_object const&) = delete;
    io_object& operator=(io_object const&) = delete;

    capy::execution_context* ctx_ = nullptr;
    handle h_;
};

} // namespace boost::corosio

#endif
