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

#include "src/detail/epoll/resolver_service.hpp"
#include "src/detail/epoll/scheduler.hpp"
#include "src/detail/endpoint_convert.hpp"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <thread>
#include <vector>

namespace boost {
namespace corosio {
namespace detail {

namespace {

// Convert resolve_flags to addrinfo ai_flags
int
flags_to_hints(resolve_flags flags)
{
    int hints = 0;

    if ((flags & resolve_flags::passive) != resolve_flags::none)
        hints |= AI_PASSIVE;
    if ((flags & resolve_flags::numeric_host) != resolve_flags::none)
        hints |= AI_NUMERICHOST;
    if ((flags & resolve_flags::numeric_service) != resolve_flags::none)
        hints |= AI_NUMERICSERV;
    if ((flags & resolve_flags::address_configured) != resolve_flags::none)
        hints |= AI_ADDRCONFIG;
    if ((flags & resolve_flags::v4_mapped) != resolve_flags::none)
        hints |= AI_V4MAPPED;
    if ((flags & resolve_flags::all_matching) != resolve_flags::none)
        hints |= AI_ALL;

    return hints;
}

// Convert addrinfo results to resolver_results
resolver_results
convert_results(
    struct addrinfo* ai,
    std::string_view host,
    std::string_view service)
{
    std::vector<resolver_entry> entries;

    for (auto* p = ai; p != nullptr; p = p->ai_next)
    {
        if (p->ai_family == AF_INET)
        {
            auto* addr = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            auto ep = from_sockaddr_in(*addr);
            entries.emplace_back(ep, host, service);
        }
        else if (p->ai_family == AF_INET6)
        {
            auto* addr = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            auto ep = from_sockaddr_in6(*addr);
            entries.emplace_back(ep, host, service);
        }
    }

    return resolver_results(std::move(entries));
}

// Convert getaddrinfo error codes to system::error_code
system::error_code
make_gai_error(int gai_err)
{
    // Map GAI errors to appropriate generic error codes
    switch (gai_err)
    {
    case EAI_AGAIN:
        // Temporary failure - try again later
        return system::error_code(
            static_cast<int>(std::errc::resource_unavailable_try_again),
            system::generic_category());

    case EAI_BADFLAGS:
        // Invalid flags
        return system::error_code(
            static_cast<int>(std::errc::invalid_argument),
            system::generic_category());

    case EAI_FAIL:
        // Non-recoverable failure
        return system::error_code(
            static_cast<int>(std::errc::io_error),
            system::generic_category());

    case EAI_FAMILY:
        // Address family not supported
        return system::error_code(
            static_cast<int>(std::errc::address_family_not_supported),
            system::generic_category());

    case EAI_MEMORY:
        // Memory allocation failure
        return system::error_code(
            static_cast<int>(std::errc::not_enough_memory),
            system::generic_category());

    case EAI_NONAME:
        // Host or service not found
        return system::error_code(
            static_cast<int>(std::errc::no_such_device_or_address),
            system::generic_category());

    case EAI_SERVICE:
        // Service not supported for socket type
        return system::error_code(
            static_cast<int>(std::errc::invalid_argument),
            system::generic_category());

    case EAI_SOCKTYPE:
        // Socket type not supported
        return system::error_code(
            static_cast<int>(std::errc::not_supported),
            system::generic_category());

    case EAI_SYSTEM:
        // System error - use errno
        return system::error_code(errno, system::generic_category());

    default:
        // Unknown error
        return system::error_code(
            static_cast<int>(std::errc::io_error),
            system::generic_category());
    }
}

} // namespace

//------------------------------------------------------------------------------
// epoll_resolve_op
//------------------------------------------------------------------------------

void
epoll_resolve_op::
reset() noexcept
{
    host.clear();
    service.clear();
    flags = resolve_flags::none;
    stored_results = resolver_results{};
    gai_error = 0;
    cancelled.store(false, std::memory_order_relaxed);
    stop_cb.reset();
    ec_out = nullptr;
    out = nullptr;
}

void
epoll_resolve_op::
operator()()
{
    stop_cb.reset();  // Disconnect stop callback

    if (ec_out)
    {
        if (cancelled.load(std::memory_order_acquire))
            *ec_out = capy::error::canceled;
        else if (gai_error != 0)
            *ec_out = make_gai_error(gai_error);
    }

    if (out && !cancelled.load(std::memory_order_acquire) && gai_error == 0)
        *out = std::move(stored_results);

    d.dispatch(h).resume();
}

void
epoll_resolve_op::
destroy()
{
    stop_cb.reset();
}

void
epoll_resolve_op::
request_cancel() noexcept
{
    cancelled.store(true, std::memory_order_release);
}

void
epoll_resolve_op::
start(std::stop_token token)
{
    cancelled.store(false, std::memory_order_release);
    stop_cb.reset();

    if (token.stop_possible())
        stop_cb.emplace(token, canceller{this});
}

//------------------------------------------------------------------------------
// epoll_resolver_impl
//------------------------------------------------------------------------------

void
epoll_resolver_impl::
release()
{
    cancel();
    svc_.destroy_impl(*this);
}

void
epoll_resolver_impl::
resolve(
    std::coroutine_handle<> h,
    capy::executor_ref d,
    std::string_view host,
    std::string_view service,
    resolve_flags flags,
    std::stop_token token,
    system::error_code* ec,
    resolver_results* out)
{
    auto& op = op_;
    op.reset();
    op.h = h;
    op.d = d;
    op.ec_out = ec;
    op.out = out;
    op.impl = this;
    op.host = host;
    op.service = service;
    op.flags = flags;
    op.start(token);

    svc_.work_started();

    auto self = shared_from_this();
    std::thread worker([this, self = std::move(self)]() {
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = flags_to_hints(op_.flags);

        struct addrinfo* ai = nullptr;
        int result = ::getaddrinfo(
            op_.host.empty() ? nullptr : op_.host.c_str(),
            op_.service.empty() ? nullptr : op_.service.c_str(),
            &hints, &ai);

        if (!op_.cancelled.load(std::memory_order_acquire))
        {
            if (result == 0 && ai)
            {
                op_.stored_results = convert_results(ai, op_.host, op_.service);
                op_.gai_error = 0;
            }
            else
            {
                op_.gai_error = result;
            }
        }

        if (ai)
            ::freeaddrinfo(ai);

        svc_.work_finished();
        svc_.post(&op_);
    });
    worker.detach();
}

void
epoll_resolver_impl::
cancel() noexcept
{
    op_.request_cancel();
}

//------------------------------------------------------------------------------
// epoll_resolver_service
//------------------------------------------------------------------------------

epoll_resolver_service::
epoll_resolver_service(capy::execution_context& ctx)
    : sched_(ctx.use_service<epoll_scheduler>())
{
}

epoll_resolver_service::
~epoll_resolver_service()
{
}

void
epoll_resolver_service::
shutdown()
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Cancel and release all resolvers
    for (auto* impl = resolver_list_.pop_front(); impl != nullptr;
         impl = resolver_list_.pop_front())
    {
        impl->cancel();
    }

    // Clear the map which releases shared_ptrs
    resolver_ptrs_.clear();
}

epoll_resolver_impl&
epoll_resolver_service::
create_impl()
{
    auto ptr = std::make_shared<epoll_resolver_impl>(*this);
    auto* impl = ptr.get();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        resolver_list_.push_back(impl);
        resolver_ptrs_[impl] = std::move(ptr);
    }

    return *impl;
}

void
epoll_resolver_service::
destroy_impl(epoll_resolver_impl& impl)
{
    std::lock_guard<std::mutex> lock(mutex_);
    resolver_list_.remove(&impl);
    resolver_ptrs_.erase(&impl);
}

void
epoll_resolver_service::
post(scheduler_op* op)
{
    sched_.post(op);
}

void
epoll_resolver_service::
work_started() noexcept
{
    sched_.work_started();
}

void
epoll_resolver_service::
work_finished() noexcept
{
    sched_.work_finished();
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // BOOST_COROSIO_BACKEND_EPOLL
