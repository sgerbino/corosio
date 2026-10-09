//
// Copyright (c) 2026 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#include <boost/corosio/tcp_server.hpp>
#include <boost/corosio/detail/except.hpp>
#include <condition_variable>
#include <mutex>
#include <utility>

namespace boost::corosio {

tcp_server::worker_base::worker_base()  = default;
tcp_server::worker_base::~worker_base() = default;

struct tcp_server::impl
{
    std::mutex join_mutex;
    std::condition_variable join_cv;
    capy::execution_context& ctx;
    std::vector<tcp_acceptor> ports;
    std::stop_source stop;

    explicit impl(capy::execution_context& c) noexcept : ctx(c) {}
};

tcp_server::state*
tcp_server::make_state(capy::execution_context& ctx, capy::any_executor const& ex)
{
    auto* i = new impl(ctx);
    try
    {
        return new state(i, ex);
    }
    catch (...)
    {
        delete i;
        throw;
    }
}

void
tcp_server::release(state* s) noexcept
{
    if (s->refs.fetch_sub(1, std::memory_order_acq_rel) == 1)
    {
        delete s->impl_;
        delete s;
    }
}

void
tcp_server::discard() noexcept
{
    if (!st_)
        return;
    stop();
    {
        std::lock_guard<std::mutex> lock(st_->mutex);
        st_->discarded = true;
    }
    release(std::exchange(st_, nullptr));
}

tcp_server::~tcp_server()
{
    discard();
}

tcp_server::tcp_server(tcp_server&& o) noexcept
    : st_(std::exchange(o.st_, nullptr))
{
}

tcp_server&
tcp_server::operator=(tcp_server&& o) noexcept
{
    if (this != &o)
    {
        discard();
        st_ = std::exchange(o.st_, nullptr);
    }
    return *this;
}

// Accept loop: wait for idle worker, accept connection, dispatch
capy::task<void>
tcp_server::do_accept(state_ref st, tcp_acceptor& acc)
{
    // Analyzer can't trace value through coroutine await_transform
    // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
    auto env = co_await capy::this_coro::environment;
    while (!env->stop_token.stop_requested())
    {
        // Wait for an idle worker before blocking on accept
        auto& w   = co_await pop_awaitable{*st};
        auto [ec] = co_await acc.accept(w.socket());
        if (ec)
        {
            co_await push_awaitable{*st, w};
            continue;
        }
        w.run(launcher{*st, w});
    }

    // Closed here rather than by the departing server: the loop is the
    // listener's only user, so the close cannot race its operations.
    bool discarded = false;
    {
        std::lock_guard<std::mutex> lock(st->mutex);
        discarded = st->discarded;
    }
    if (discarded)
        acc.close();
}

std::error_code
tcp_server::bind(endpoint ep)
{
    try
    {
        st_->impl_->ports.emplace_back(st_->impl_->ctx, ep);
        return {};
    }
    catch (std::system_error const& e)
    {
        return e.code();
    }
}

endpoint
tcp_server::local_endpoint(std::size_t index) const noexcept
{
    if (!st_ || index >= st_->impl_->ports.size())
        return endpoint{};
    return st_->impl_->ports[index].local_endpoint();
}

void
tcp_server::start()
{
    // Idempotent - only start if not already running
    if (st_->running)
        return;

    auto& im = *st_->impl_;
    {
        // Previous session must be fully stopped before restart
        std::lock_guard lock(im.join_mutex);
        if (st_->active_accepts != 0)
            detail::throw_logic_error(
                "tcp_server::start: previous session not joined");
        st_->active_accepts = im.ports.size();
    }

    st_->running = true;
    im.stop      = {}; // Fresh stop source
    auto token   = im.stop.get_token();

    // Launch with completion handler that decrements counter
    for (auto& t : im.ports)
        capy::run_async(st_->ex, token, [st = state_ref(st_)]() {
            auto& im = *st->impl_;
            std::lock_guard lock(im.join_mutex);
            if (--st->active_accepts == 0)
                im.join_cv.notify_all();
        })(do_accept(state_ref(st_), t));
}

void
tcp_server::stop()
{
    // Idempotent - only stop if running
    if (!st_ || !st_->running)
        return;
    st_->running = false;

    // Stop accept loops
    st_->impl_->stop.request_stop();

    // Launch cancellation coroutine on server executor
    capy::run_async(st_->ex, std::stop_token{})(do_stop(state_ref(st_)));
}

void
tcp_server::join()
{
    auto& im = *st_->impl_;
    std::unique_lock lock(im.join_mutex);
    im.join_cv.wait(lock, [this] { return st_->active_accepts == 0; });
}

capy::task<>
tcp_server::do_stop(state_ref st)
{
    // Requested outside the lock: a stop callback may return its worker,
    // which takes the lock.
    std::vector<std::stop_source> active;
    {
        std::lock_guard<std::mutex> lock(st->mutex);
        for (auto* w = st->active_head; w; w = w->next_)
            active.push_back(w->stop_);
    }
    for (auto& s : active)
        s.request_stop();
    co_return;
}

} // namespace boost::corosio
