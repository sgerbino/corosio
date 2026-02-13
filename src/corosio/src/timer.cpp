//
// Copyright (c) 2025 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/timer.hpp>

#include <boost/corosio/detail/except.hpp>

#include <memory>

namespace boost::corosio {

namespace detail {

// Defined in timer_service.cpp
extern std::shared_ptr<io_object::implementation>
    timer_service_create(capy::execution_context&);
extern std::size_t timer_service_update_expiry(timer::timer_impl&);
extern std::size_t timer_service_cancel(timer::timer_impl&) noexcept;
extern std::size_t timer_service_cancel_one(timer::timer_impl&) noexcept;

} // namespace detail

timer::
~timer()
{
}

timer::
timer(capy::execution_context& ctx)
    : io_object(ctx)
{
    h_ = io_object::handle(detail::timer_service_create(ctx));
}

timer::
timer(capy::execution_context& ctx, time_point t)
    : timer(ctx)
{
    expires_at(t);
}

timer::
timer(timer&& other) noexcept
    : io_object(other.context())
{
    h_ = std::move(other.h_);
}

timer&
timer::
operator=(timer&& other)
{
    if (this != &other)
    {
        if (ctx_ != other.ctx_)
            detail::throw_logic_error(
                "cannot move timer across execution contexts");
        h_ = std::move(other.h_);
    }
    return *this;
}

std::size_t
timer::
do_cancel()
{
    return detail::timer_service_cancel(get());
}

std::size_t
timer::
do_cancel_one()
{
    return detail::timer_service_cancel_one(get());
}

std::size_t
timer::
do_update_expiry()
{
    return detail::timer_service_update_expiry(get());
}

} // namespace boost::corosio
