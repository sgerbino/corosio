//
// Copyright (c) 2026 Michael Vandeberg
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_TEST_TEMP_PATH_HPP
#define BOOST_COROSIO_TEST_TEMP_PATH_HPP

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace boost::corosio::test {

/** RAII temp directory holding a path for a Unix-domain socket.

    Creates a unique empty directory under
    `std::filesystem::temp_directory_path()` and exposes a path under
    it suitable for binding `local_stream_socket` /
    `local_datagram_socket`. The destructor removes the directory
    (and the bound socket file inside it) recursively, so tests that
    throw mid-execution still clean up.

    Naming entropy comes from a process-wide atomic counter mixed with
    a one-time `random_device` seed; that's enough to avoid collisions
    between parallel test runs without requiring cryptographic
    randomness. The constructor retries on collision and throws if it
    cannot create a directory in a reasonable number of attempts.

    Platform note: the helper exists so tests don't need to call
    `mkdtemp` / `unlink` / `rmdir` directly. On Windows, the path is
    a filesystem AF_UNIX path (Windows 10 1803+).
*/
class temp_socket_dir
{
public:
    temp_socket_dir()
    {
        namespace fs = std::filesystem;
        auto const base = fs::temp_directory_path();

        // 64 bits of mixed entropy: a random seed established once
        // at static init, XORed with a monotonic counter.
        static std::uint64_t const seed = [] {
            std::random_device rd;
            return (static_cast<std::uint64_t>(rd()) << 32) |
                   static_cast<std::uint64_t>(rd());
        }();
        static std::atomic<std::uint64_t> counter{0};

        std::error_code ec;
        for (int tries = 0; tries < 32; ++tries)
        {
            auto const n   = counter.fetch_add(1, std::memory_order_relaxed);
            auto const tag = seed ^ n;

            char buf[32];
            std::snprintf(
                buf, sizeof(buf), "corosio_test_%016llx",
                static_cast<unsigned long long>(tag));

            auto candidate = base / buf;
            if (fs::create_directory(candidate, ec))
            {
                dir_ = std::move(candidate);
                return;
            }
        }
        throw std::runtime_error(
            "temp_socket_dir: could not create temp directory");
    }

    ~temp_socket_dir() noexcept
    {
        if (dir_.empty())
            return;

#if defined(_WIN32)
        // A bound AF_UNIX socket leaves a special socket file on disk.
        // std::filesystem::remove_all() stats each entry via
        // symlink_status(), which (on libstdc++) opens the file with
        // CreateFileW -- and opening an AF_UNIX socket file hangs in
        // ZwCreateFile, deadlocking test teardown (observed as the
        // MinGW coverage-build timeout). FindFirstFileW reads directory
        // entries without opening the files, and DeleteFileW removes
        // the socket file's directory entry without that hanging open.
        std::wstring spec = dir_.wstring() + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE h = ::FindFirstFileW(spec.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                std::wstring name = fd.cFileName;
                if (name == L"." || name == L"..")
                    continue;
                std::wstring full = dir_.wstring() + L"\\" + name;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    ::RemoveDirectoryW(full.c_str());
                else
                    ::DeleteFileW(full.c_str());
            } while (::FindNextFileW(h, &fd));
            ::FindClose(h);
        }
        ::RemoveDirectoryW(dir_.wstring().c_str());
#else
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
#endif
    }

    temp_socket_dir(temp_socket_dir const&)            = delete;
    temp_socket_dir& operator=(temp_socket_dir const&) = delete;

    /// Path suitable for binding a local socket.
    std::string path() const
    {
        return (dir_ / "sock").string();
    }

private:
    std::filesystem::path dir_;
};

} // namespace boost::corosio::test

#endif // BOOST_COROSIO_TEST_TEMP_PATH_HPP
