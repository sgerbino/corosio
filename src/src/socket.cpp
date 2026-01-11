//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/socket.hpp>
#include "src/detail/win_iocp_sockets.hpp"

#include <cassert>

namespace boost {
namespace corosio {

socket::
~socket()
{
    close();
}

socket::
socket(
    capy::execution_context& ctx)
    : ctx_(&ctx)
    , impl_(nullptr)
{
}

void
socket::
open()
{
    if (impl_)
        return; // Already open

    impl_ = &ctx_->use_service<detail::win_iocp_sockets>().create_impl();
}

void
socket::
close()
{
    if (!impl_)
        return; // Already closed

    impl_->release();
    impl_ = nullptr;
}

void
socket::
cancel()
{
    assert(impl_ != nullptr);
    impl_->cancel();
}

void
socket::
do_read_some(
    capy::coro h,
    capy::any_dispatcher d,
    std::stop_token token,
    std::error_code* ec)
{
    assert(impl_ != nullptr);
    impl_->rd.h = h;
    impl_->rd.d = d;
    impl_->rd.ec_out = ec;
    impl_->rd.start(token);
    //reactor_->submit(&impl_->rd);
}

} // namespace corosio
} // namespace boost
