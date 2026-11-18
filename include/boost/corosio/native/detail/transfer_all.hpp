//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_TRANSFER_ALL_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_TRANSFER_ALL_HPP

#include <boost/corosio/detail/platform.hpp>
#include <boost/corosio/detail/buffer_param.hpp>
#include <boost/capy/buffers.hpp>

#include <cstddef>

#if BOOST_COROSIO_POSIX
#include <sys/uio.h>
#elif BOOST_COROSIO_HAS_IOCP
#include <boost/corosio/native/detail/iocp/win_windows.hpp>
#endif

namespace boost::corosio::detail {

#if BOOST_COROSIO_POSIX

inline constexpr std::size_t
max_buf_len(iovec const*) noexcept
{
    return static_cast<std::size_t>(-1);
}

inline void
set_buf(iovec& b, void* p, std::size_t n) noexcept
{
    b.iov_base = p;
    b.iov_len  = n;
}

inline std::size_t
buf_len(iovec const& b) noexcept
{
    return b.iov_len;
}

inline void
consume_buf(iovec& b, std::size_t n) noexcept
{
    b.iov_base = static_cast<char*>(b.iov_base) + n;
    b.iov_len -= n;
}

#elif BOOST_COROSIO_HAS_IOCP

inline constexpr std::size_t
max_buf_len(WSABUF const*) noexcept
{
    return 0x7fffffff;
}

inline void
set_buf(WSABUF& b, void* p, std::size_t n) noexcept
{
    b.buf = static_cast<char*>(p);
    b.len = static_cast<ULONG>(n);
}

inline std::size_t
buf_len(WSABUF const& b) noexcept
{
    return b.len;
}

inline void
consume_buf(WSABUF& b, std::size_t n) noexcept
{
    b.buf += n;
    b.len -= static_cast<ULONG>(n);
}

#endif

/** Progress of an operation that transfers a whole buffer sequence.

    The op keeps the caller's `buffer_param` so it can refill its
    array of OS buffers when the sequence holds more buffers than one
    array. That is safe only because the awaitable that owns the
    sequence stays suspended until the op completes.

    @tparam Buf The OS buffer descriptor, `iovec` or `WSABUF`.
*/
template<class Buf>
struct transfer_all_state
{
    /// The whole sequence, for refills past the first array.
    buffer_param src;

    /// The last fill stopped short of the sequence's end.
    bool more = false;

    /// Keep transferring until the buffers are exhausted.
    bool active = false;

    /// A read reached end of stream.
    bool hit_eof = false;

    /// Every requested byte moved.
    bool all_done = false;

    /// Bytes moved so far.
    std::size_t transferred = 0;

    /// Return to the state of an op that transfers only once.
    void reset() noexcept
    {
        *this = transfer_all_state{};
    }

    /** Start transferring all of @a param.

        @param array_full `true` if the op's first fill used its whole
            array, so buffers may remain past it.
    */
    void begin(buffer_param param, bool array_full) noexcept
    {
        reset();
        active = true;
        src    = param;
        more   = array_full;
    }

    /** Fill @a bufs from the sequence, past the bytes already moved.

        @return The number of entries written.
    */
    template<class Count>
    Count fill(Buf* bufs, Count max) noexcept
    {
        constexpr std::size_t limit = 64;
        capy::mutable_buffer mb[limit];
        std::size_t const cap     = static_cast<std::size_t>(max) < limit
            ? static_cast<std::size_t>(max)
            : limit;
        std::size_t const n       = src.copy_to(mb, cap, transferred);
        std::size_t const max_len = max_buf_len(bufs);
        more                      = (n == cap);
        for (std::size_t i = 0; i < n; ++i)
        {
            if (mb[i].size() > max_len)
            {
                // Bytes must move in order, so the tail of a buffer
                // one descriptor can't cover waits for the next fill.
                set_buf(bufs[i], mb[i].data(), max_len);
                more = true;
                return static_cast<Count>(i + 1);
            }
            set_buf(bufs[i], mb[i].data(), mb[i].size());
        }
        return static_cast<Count>(n);
    }

    /** Record @a n bytes moved and drop them from @a bufs.

        @return `true` if bytes remain to transfer.
    */
    template<class Count>
    bool advance(Buf* bufs, Count& count, Count max, std::size_t n) noexcept
    {
        transferred += n;
        Count i = 0;
        while (i < count && n >= buf_len(bufs[i]))
            n -= buf_len(bufs[i++]);
        if (i < count)
        {
            consume_buf(bufs[i], n);
            for (Count j = i; j < count; ++j)
                bufs[j - i] = bufs[j];
            count -= i;
            return true;
        }
        count = more ? fill(bufs, max) : Count(0);
        if (count == 0)
            all_done = true;
        return count != 0;
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_NATIVE_DETAIL_TRANSFER_ALL_HPP
