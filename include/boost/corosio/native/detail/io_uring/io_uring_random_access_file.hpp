//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_RANDOM_ACCESS_FILE_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_RANDOM_ACCESS_FILE_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

#include <boost/corosio/detail/random_access_file_service.hpp>
#include <boost/corosio/detail/intrusive.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_file_ops.hpp>
#include <boost/corosio/native/detail/io_uring/io_uring_scheduler.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/corosio/random_access_file.hpp>

#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <system_error>
#include <unordered_map>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace boost::corosio::detail {

class io_uring_random_access_file_service;

/** Native io_uring random-access-file implementation.

    Async `read_some_at` / `write_some_at` submit `IORING_OP_READV`
    / `IORING_OP_WRITEV` with the caller-supplied offset. Metadata
    operations (open, size, resize, sync, close) are synchronous
    syscalls.
*/
class BOOST_COROSIO_DECL io_uring_random_access_file final
    : public random_access_file::implementation
    , public std::enable_shared_from_this<io_uring_random_access_file>
    , public intrusive_list<io_uring_random_access_file>::node
{
    friend class io_uring_random_access_file_service;

    int                  fd_    = -1;
    io_uring_scheduler*  sched_ = nullptr;

public:
    explicit io_uring_random_access_file(io_uring_scheduler& sched) noexcept
        : sched_(&sched)
    {}

    ~io_uring_random_access_file() override
    {
        close_file();
    }

    // -- random_access_file::implementation (defined in Task 7) --

    std::coroutine_handle<> read_some_at(
        std::uint64_t,
        std::coroutine_handle<>,
        capy::executor_ref,
        buffer_param,
        std::stop_token,
        std::error_code*,
        std::size_t*) override;

    std::coroutine_handle<> write_some_at(
        std::uint64_t,
        std::coroutine_handle<>,
        capy::executor_ref,
        buffer_param,
        std::stop_token,
        std::error_code*,
        std::size_t*) override;

    native_handle_type native_handle() const noexcept override
    {
        return fd_;
    }

    void cancel() noexcept override
    {
        if (fd_ >= 0)
            sched_->submit_cancel_by_fd(fd_);
    }

    std::uint64_t size() const override
    {
        struct stat st;
        if (::fstat(fd_, &st) < 0)
            throw_system_error(
                make_err(errno), "random_access_file::size");
        return static_cast<std::uint64_t>(st.st_size);
    }

    void resize(std::uint64_t new_size) override
    {
        if (new_size > static_cast<std::uint64_t>(
                (std::numeric_limits<off_t>::max)()))
            throw_system_error(
                make_err(EOVERFLOW), "random_access_file::resize");
        if (::ftruncate(fd_, static_cast<off_t>(new_size)) < 0)
            throw_system_error(
                make_err(errno), "random_access_file::resize");
    }

    void sync_data() override
    {
#if BOOST_COROSIO_HAS_POSIX_SYNCHRONIZED_IO
        if (::fdatasync(fd_) < 0)
#else
        if (::fsync(fd_) < 0)
#endif
            throw_system_error(
                make_err(errno), "random_access_file::sync_data");
    }

    void sync_all() override
    {
        if (::fsync(fd_) < 0)
            throw_system_error(
                make_err(errno), "random_access_file::sync_all");
    }

    native_handle_type release() override
    {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    void assign(native_handle_type handle) override
    {
        close_file();
        fd_ = handle;
    }

    // -- Internal --

    std::error_code open_file(
        std::filesystem::path const& path, file_base::flags mode)
    {
        close_file();

        int oflags = 0;
        unsigned access = static_cast<unsigned>(mode) & 3u;
        if (access == static_cast<unsigned>(file_base::read_write))
            oflags |= O_RDWR;
        else if (access == static_cast<unsigned>(file_base::write_only))
            oflags |= O_WRONLY;
        else
            oflags |= O_RDONLY;

        if ((mode & file_base::create) != file_base::flags(0))
            oflags |= O_CREAT;
        if ((mode & file_base::exclusive) != file_base::flags(0))
            oflags |= O_EXCL;
        if ((mode & file_base::truncate) != file_base::flags(0))
            oflags |= O_TRUNC;
        if ((mode & file_base::sync_all_on_write) != file_base::flags(0))
            oflags |= O_SYNC;

        oflags |= O_CLOEXEC;

        int fd = ::open(path.c_str(), oflags, 0666);
        if (fd < 0)
            return make_err(errno);

        fd_ = fd;
        return {};
    }

    void close_file() noexcept
    {
        if (fd_ >= 0)
        {
            sched_->cancel_and_flush(fd_);
            ::close(fd_);
            fd_ = -1;
        }
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_RANDOM_ACCESS_FILE_HPP
