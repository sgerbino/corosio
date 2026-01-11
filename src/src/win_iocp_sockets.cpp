//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "src/win_iocp_sockets.hpp"

#ifdef _WIN32

#include "src/win_iocp_scheduler.hpp"

namespace boost {
namespace corosio {

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
    // Cancel all pending operations on registered sockets
    for (auto* impl = sockets_.pop_front(); impl != nullptr;
         impl = sockets_.pop_front())
    {
        impl->cancel();
    }
}

void
win_iocp_sockets::
register_socket(socket_impl* impl)
{
    sockets_.push_back(impl);

    // TODO: Associate socket handle with IOCP via CreateIoCompletionPort
    // when socket_impl gains a native handle member
}

void
win_iocp_sockets::
unregister_socket(socket_impl* impl)
{
    sockets_.remove(impl);
}

} // namespace corosio
} // namespace boost

#endif // _WIN32
