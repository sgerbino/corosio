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

#include <boost/corosio/detail/continuation_op.hpp>
#include <boost/corosio/detail/scheduler_op.hpp>
#include <boost/capy/ex/executor_ref.hpp>

// Forward declare to avoid circular include with io_uring_scheduler.hpp.
namespace boost::corosio::detail { class io_uring_scheduler; }

#include <atomic>
#include <coroutine>
#include <cstddef>
#include <memory>
#include <optional>
#include <stop_token>

#include <liburing.h>

namespace boost::corosio::detail {

/** Base class for io_uring operations.

    Holds per-operation state common to every uring op: coroutine
    handle, executor for handler dispatch, output pointers, the
    stop_token wiring for cancellation, and a function pointer
    used by the scheduler to dispatch a CQE arrival.

    Concrete op types (uring_read_op, uring_write_op, etc.) set
    `cqe_func` at construction so the run loop's completion path
    has zero virtual indirection.
*/
struct io_uring_op : scheduler_op
{
    /// CQE-side dispatcher type. Called once per completion event.
    /// Pushes self into `local` rather than dispatching inline so
    /// process_completions can splice the batch into completed_ops_
    /// atomically and do_one dispatches one handler at a time.
    using cqe_func_type =
        void (*)(io_uring_op*, int res, unsigned flags, op_queue& local) noexcept;

    /// Stop-callback handler: requests cancellation of this op.
    struct canceller
    {
        io_uring_op* op;
        void operator()() const noexcept { op->request_cancel(); }
    };

    explicit io_uring_op(func_type post_func, cqe_func_type cqe_fn) noexcept
        : scheduler_op(post_func)
        , cqe_func(cqe_fn)
    {}

    std::coroutine_handle<>                      h;
    detail::continuation_op                      cont_op;
    capy::executor_ref                           ex;
    std::error_code*                             ec_out    = nullptr;
    std::size_t*                                 bytes_out = nullptr;

    int                                          res       = 0;
    unsigned                                     cqe_flags = 0;
    bool                                         is_read      = false;
    bool                                         empty_buffer = false;

    std::atomic<bool>                            cancelled{false};
    std::optional<std::stop_callback<canceller>> stop_cb;
    cqe_func_type                                cqe_func;

    /// Keeps the owning impl alive while the op is in flight (kernel
    /// owns user buffers until completion).
    std::shared_ptr<void>                        impl_ptr;

    /// Scheduler reference for submitting cancel SQEs on stop_token.
    io_uring_scheduler*                          sched_ = nullptr;

    void request_cancel() noexcept;


    /// Bridge virtual dispatch to func-pointer dispatch. Lets the run
    /// loop dispatch any scheduler_op via `(*op)()` — both reactor-style
    /// services posted into the queue and proactor-style io_uring ops.
    /// Pass `this` (non-null) so handlers take the normal completion path,
    /// not the destroy path (which is signalled by owner == nullptr).
    void operator()() override { complete(this, 0, 0); }

    /// Arm the stop-token callback. Must be called before the SQE submits.
    void start(std::stop_token const& token)
    {
        cancelled.store(false, std::memory_order_relaxed);
        stop_cb.reset();
        if (token.stop_possible())
            stop_cb.emplace(token, canceller{this});
    }
};

} // namespace boost::corosio::detail

#endif // BOOST_COROSIO_HAS_IO_URING

#endif // BOOST_COROSIO_NATIVE_DETAIL_IO_URING_IO_URING_OP_HPP
