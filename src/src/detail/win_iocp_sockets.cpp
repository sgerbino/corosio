//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "src/detail/win_iocp_sockets.hpp"

#ifdef _WIN32

#include "src/detail/win_iocp_scheduler.hpp"

namespace boost {
namespace corosio {
namespace detail {

//------------------------------------------------------------------------------
// socket_impl

void
socket_impl::
release()
{
    svc_.destroy_impl(*this);
}

//------------------------------------------------------------------------------
// win_iocp_sockets

win_iocp_sockets::
win_iocp_sockets(
    capy::execution_context& ctx)
    : iocp_(ctx.use_service<win_iocp_scheduler>().native_handle())
{
}

win_iocp_sockets::
~win_iocp_sockets()
{
}

void
win_iocp_sockets::
shutdown()
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Destroy all socket implementations
    for (auto* impl = list_.pop_front(); impl != nullptr;
         impl = list_.pop_front())
    {
        delete impl;
    }
}

socket_impl&
win_iocp_sockets::
create_impl()
{
    auto* impl = new socket_impl(*this);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        list_.push_back(impl);
    }

    // TODO: Associate socket handle with IOCP via CreateIoCompletionPort
    // when socket_impl gains a native handle member

    return *impl;
}

void
win_iocp_sockets::
destroy_impl(socket_impl& impl)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        list_.remove(&impl);
    }

    delete &impl;

    // Future: recycle impl instead of deleting
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // _WIN32
