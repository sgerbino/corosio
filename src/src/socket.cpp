//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/socket.hpp>
#include "src/win_iocp_sockets.hpp"

namespace boost {
namespace corosio {

socket::
~socket()
{
    auto& svc = impl_.svc_;
    svc.unregister_socket(&impl_);
    delete &impl_;
}

socket::
socket(
    capy::execution_context& ctx)
    : impl_([&ctx]() -> socket_impl& {
        auto& svc = ctx.use_service<win_iocp_sockets>();
        auto* impl = new socket_impl(svc);
        svc.register_socket(impl);
        return *impl;
    }())
{
}

void
socket::
cancel() const
{
    impl_.cancel();
}

void
socket::
do_read_some(
    capy::coro h,
    capy::any_dispatcher d,
    std::stop_token token,
    std::error_code* ec)
{
    impl_.rd.h = h;
    impl_.rd.d = d;
    impl_.rd.ec_out = ec;
    impl_.rd.start(token);
    //reactor_->submit(&impl_.rd);
}

} // namespace corosio
} // namespace boost
