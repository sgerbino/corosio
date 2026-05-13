//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/host_name.hpp>
#include <boost/corosio/detail/platform.hpp>

#include <stdexcept>
#include <string>

#if BOOST_COROSIO_POSIX
#include <cerrno>
#include <cstring>
#include <limits.h>
#include <unistd.h>
#elif BOOST_COROSIO_HAS_IOCP
#include <windows.h>
#endif

namespace boost::corosio {

#if BOOST_COROSIO_POSIX

std::string
host_name()
{
    // Prefer the runtime limit; fall back to HOST_NAME_MAX, then 256.
    long sz = ::sysconf(_SC_HOST_NAME_MAX);
    if (sz <= 0)
    {
#ifdef HOST_NAME_MAX
        sz = HOST_NAME_MAX;
#else
        sz = 256;
#endif
    }

    // +1 for guaranteed NUL terminator slot we can inspect.
    std::string buf(static_cast<std::size_t>(sz) + 1, '\0');

    if (::gethostname(buf.data(), buf.size()) != 0)
    {
        int e = errno;
        throw std::runtime_error(
            std::string("gethostname failed: ") + std::strerror(e));
    }

    // POSIX does not guarantee NUL termination if the name was
    // truncated. The final byte must still be NUL or the result is
    // unsafe to return.
    if (buf.back() != '\0')
        throw std::runtime_error("gethostname: hostname truncated");

    buf.resize(std::strlen(buf.c_str()));
    return buf;
}

#elif BOOST_COROSIO_HAS_IOCP

std::string
host_name()
{
    // First call: discover the required wide-char count (including
    // the trailing NUL). This call is expected to fail with
    // ERROR_MORE_DATA; any other failure is fatal.
    DWORD size = 0;
    BOOL ok = ::GetComputerNameExW(
        ComputerNameDnsHostname, nullptr, &size);
    DWORD err = ::GetLastError();
    if (ok)
    {
        throw std::runtime_error(
            "GetComputerNameExW (size query) unexpectedly succeeded");
    }
    if (err != ERROR_MORE_DATA)
    {
        throw std::runtime_error(
            "GetComputerNameExW (size query) failed: error " +
            std::to_string(err));
    }

    // `size` includes the trailing NUL on entry. After a successful
    // call, GetComputerNameExW updates `size` to the count without
    // the NUL, so resize(size) below trims exactly to the hostname.
    std::wstring wide(size, L'\0');
    if (!::GetComputerNameExW(
            ComputerNameDnsHostname, wide.data(), &size))
    {
        throw std::runtime_error(
            "GetComputerNameExW failed: error " +
            std::to_string(::GetLastError()));
    }
    wide.resize(size); // size is now the count without the NUL

    // UTF-16 -> UTF-8. First call sizes the destination buffer.
    int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
    {
        throw std::runtime_error(
            "WideCharToMultiByte (size query) failed: error " +
            std::to_string(::GetLastError()));
    }

    std::string out(static_cast<std::size_t>(needed), '\0');
    int written = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        out.data(), needed, nullptr, nullptr);
    if (written != needed)
    {
        throw std::runtime_error(
            "WideCharToMultiByte failed: error " +
            std::to_string(::GetLastError()));
    }
    return out;
}

#endif

} // namespace boost::corosio
