//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_DETAIL_READY_QUEUE_HPP
#define BOOST_COROSIO_DETAIL_READY_QUEUE_HPP

#include <boost/corosio/detail/scheduler_op.hpp>
#include <boost/capy/ex/ready_queue.hpp>

namespace boost::corosio::detail {

/** A unified intrusive FIFO of scheduler_ops and continuations.

    Carries both completion handlers (`scheduler_op`, dispatched via
    `(*op)()`) and posted coroutine resumptions in one ordered queue,
    with no per-entry allocation.

    @par Thread Safety
    Not thread-safe; external synchronization required (the schedulers
    hold their dispatch mutex while touching it).
*/
using ready_queue = capy::ready_queue<scheduler_op>;

} // namespace boost::corosio::detail

#endif
