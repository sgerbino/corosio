//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_OP_HPP
#define BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_OP_HPP

#include <boost/corosio/detail/platform.hpp>

#if BOOST_COROSIO_HAS_IO_URING

#include <boost/corosio/detail/config.hpp>
#include <boost/corosio/detail/continuation_op.hpp>
#include <boost/corosio/detail/scheduler_op.hpp>
#include <boost/corosio/native/detail/make_err.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/executor_ref.hpp>

#include <atomic>
#include <coroutine>
#include <cstddef>
#include <memory>
#include <optional>
#include <stop_token>
#include <system_error>

#include <liburing.h>

namespace boost::corosio::detail {

/** Base class for io_uring operations.

    Holds per-operation state common to every uring op: coroutine
    handle, executor for handler dispatch, output pointers, the
    stop_token wiring for cancellation, and a function pointer
    used by the scheduler to dispatch a CQE arrival.

    Concrete op types (uring_read_op, uring_write_op, etc.) set
    `cqe_func_` at construction so the run loop's completion path
    has zero virtual indirection.
*/
struct io_uring_op : scheduler_op
{
    /// CQE-side dispatcher type. Called once per completion event.
    using cqe_func_type = void (*)(io_uring_op*, int res, unsigned flags) noexcept;

    /// Stop-callback handler: requests cancellation of this op.
    struct canceller
    {
        io_uring_op* op;
        void operator()() const noexcept { op->request_cancel(); }
    };

    explicit io_uring_op(func_type post_func, cqe_func_type cqe_func) noexcept
        : scheduler_op(post_func)
        , cqe_func_(cqe_func)
    {}

    std::coroutine_handle<>                      h;
    detail::continuation_op                      cont_op;
    capy::executor_ref                           ex;
    std::error_code*                             ec_out    = nullptr;
    std::size_t*                                 bytes_out = nullptr;

    int                                          res       = 0;
    unsigned                                     cqe_flags = 0;
    bool                                         is_read_      = false;
    bool                                         empty_buffer_ = false;

    std::atomic<bool>                            cancelled{false};
    std::optional<std::stop_callback<canceller>> stop_cb;
    cqe_func_type                                cqe_func_;

    /// Keeps the owning impl alive while the op is in flight (kernel
    /// owns user buffers until completion).
    std::shared_ptr<void>                        impl_ptr;

    void request_cancel() noexcept
    {
        cancelled.store(true, std::memory_order_release);
    }

    /// Arm the stop-token callback. Must be called before the SQE submits.
    void start(std::stop_token const& token)
    {
        cancelled.store(false, std::memory_order_release);
        stop_cb.reset();
        if (token.stop_possible())
            stop_cb.emplace(token, canceller{this});
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_OP_HPP
