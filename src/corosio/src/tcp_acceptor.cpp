//
// Copyright (c) 2025 Vinnie Falco (vinnie.falco@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IOCP
#include "src/detail/iocp/sockets.hpp"
#else
// POSIX backends use the abstract acceptor_service interface
#include "src/detail/socket_service.hpp"
#endif

#include <boost/corosio/detail/except.hpp>

namespace boost::corosio {

tcp_acceptor::
~tcp_acceptor()
{
    close();
}

tcp_acceptor::
tcp_acceptor(
    capy::execution_context& ctx)
    : io_object(ctx)
{
}

std::error_code
tcp_acceptor::
listen(endpoint ep, int backlog)
{
    if (h_)
        close();

    std::error_code ec;

#if BOOST_COROSIO_HAS_IOCP
    auto& svc = ctx_->use_service<detail::win_sockets>();
    auto sp = svc.create_acceptor_impl();
    h_ = io_object::handle(svc, std::move(sp));
    ec = svc.open_acceptor(get(), ep, backlog);
#else
    auto* svc = ctx_->find_service<detail::acceptor_service>();
    if (!svc)
        return make_error_code(std::errc::operation_not_supported);
    auto sp = svc->create_acceptor_impl();
    h_ = io_object::handle(*svc, std::move(sp));
    ec = svc->open_acceptor(get(), ep, backlog);
#endif
    if (ec)
        h_.service().close(h_);
    return ec;
}

void
tcp_acceptor::
close()
{
    if (!h_)
        return;

    h_.service().close(h_);
}

void
tcp_acceptor::
cancel()
{
    if (!h_)
        return;
#if BOOST_COROSIO_HAS_IOCP
    static_cast<detail::win_acceptor_impl*>(h_.get())->get_internal()->cancel();
#else
    get().cancel();
#endif
}

endpoint
tcp_acceptor::
local_endpoint() const noexcept
{
    if (!h_)
        return endpoint{};
    return get().local_endpoint();
}

} // namespace boost::corosio
