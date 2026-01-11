//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include "src/detail/win_wsa_init.hpp"

#ifdef _WIN32

#include <boost/corosio/detail/except.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <Windows.h>

namespace boost {
namespace corosio {
namespace detail {

long win_wsa_init::count_ = 0;

win_wsa_init::win_wsa_init()
{
    if (::InterlockedIncrement(&count_) == 1)
    {
        WSADATA wsaData;
        int result = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0)
        {
            ::InterlockedDecrement(&count_);
            throw_system_error(
                system::error_code(result, system::system_category()));
        }
    }
}

win_wsa_init::~win_wsa_init()
{
    if (::InterlockedDecrement(&count_) == 0)
        ::WSACleanup();
}

} // namespace detail
} // namespace corosio
} // namespace boost

#endif // _WIN32
