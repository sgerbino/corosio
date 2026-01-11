//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

// Test that header file is self-contained.
#include <boost/corosio/io_context.hpp>

#include <boost/capy/executor.hpp>

#include <thread>
#include <chrono>

#include "test_suite.hpp"

namespace boost {
namespace corosio {

static_assert(capy::is_execution_context<io_context>);

// Coroutine that increments a counter when resumed
struct counter_coro
{
    struct promise_type
    {
        int* counter_ = nullptr;

        counter_coro get_return_object()
        {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_always initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }

        void return_void()
        {
            if (counter_)
                ++(*counter_);
        }

        void unhandled_exception() { std::terminate(); }
    };

    std::coroutine_handle<promise_type> h;

    operator capy::coro() const { return h; }
};

inline counter_coro make_coro(int& counter)
{
    auto c = []() -> counter_coro { co_return; }();
    c.h.promise().counter_ = &counter;
    return c;
}

// Coroutine that checks running_in_this_thread when resumed
struct check_coro
{
    struct promise_type
    {
        bool* result_ = nullptr;
        io_context::executor_type* ex_ = nullptr;

        check_coro get_return_object()
        {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_always initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }

        void return_void()
        {
            if (result_ && ex_)
                *result_ = ex_->running_in_this_thread();
        }

        void unhandled_exception() { std::terminate(); }
    };

    std::coroutine_handle<promise_type> h;

    operator capy::coro() const { return h; }
};

inline check_coro make_check_coro(bool& result, io_context::executor_type& ex)
{
    auto c = []() -> check_coro { co_return; }();
    c.h.promise().result_ = &result;
    c.h.promise().ex_ = &ex;
    return c;
}

struct io_context_test
{
    void
    testConstruction()
    {
        // Default construction
        {
            io_context ioc;
            BOOST_TEST(!ioc.stopped());
        }

        // Construction with concurrency hint
        {
            io_context ioc(1);
            BOOST_TEST(!ioc.stopped());
        }
    }

    void
    testGetExecutor()
    {
        io_context ioc;
        auto ex = ioc.get_executor();

        // Executor should be valid
        io_context::executor_type ex2 = ioc.get_executor();
        BOOST_TEST(ex == ex2);
    }

    void
    testRun()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // Post some work
        ex.post(make_coro(counter));
        ex.post(make_coro(counter));
        ex.post(make_coro(counter));

        // Run should execute all work
        std::size_t n = ioc.run();
        BOOST_TEST(n == 3);
        BOOST_TEST(counter == 3);
    }

    void
    testRunOne()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        ex.post(make_coro(counter));
        ex.post(make_coro(counter));

        // run_one should execute exactly one
        std::size_t n = ioc.run_one();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);

        // run_one again
        n = ioc.run_one();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 2);

        // No more work - would block, so use poll_one instead
    }

    void
    testPoll()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // Poll with no work should return 0 and stop the context
        std::size_t n = ioc.poll();
        BOOST_TEST(n == 0);
        BOOST_TEST(ioc.stopped());

        // Add work
        ex.post(make_coro(counter));
        ex.post(make_coro(counter));

        // Must restart after stop before poll will process handlers
        ioc.restart();

        // Poll should execute all ready work
        n = ioc.poll();
        BOOST_TEST(n == 2);
        BOOST_TEST(counter == 2);
    }

    void
    testPollOne()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // poll_one with no work should return 0 and stop the context
        std::size_t n = ioc.poll_one();
        BOOST_TEST(n == 0);
        BOOST_TEST(ioc.stopped());

        ex.post(make_coro(counter));
        ex.post(make_coro(counter));

        // Must restart after stop before poll_one will process handlers
        ioc.restart();

        // poll_one should execute exactly one
        n = ioc.poll_one();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);

        n = ioc.poll_one();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 2);

        // No more work - stops again
        n = ioc.poll_one();
        BOOST_TEST(n == 0);
        BOOST_TEST(ioc.stopped());
    }

    void
    testStopAndRestart()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        BOOST_TEST(!ioc.stopped());

        // Stop the context
        ioc.stop();
        BOOST_TEST(ioc.stopped());

        // Post work after stop
        ex.post(make_coro(counter));

        // Run should return immediately when stopped
        std::size_t n = ioc.run();
        BOOST_TEST(n == 0);
        BOOST_TEST(counter == 0);

        // Restart
        ioc.restart();
        BOOST_TEST(!ioc.stopped());

        // Now run should work
        n = ioc.run();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);
    }

    void
    testRunOneFor()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // run_one_for with no work - returns immediately (no outstanding work)
        std::size_t n = ioc.run_one_for(std::chrono::milliseconds(10));
        BOOST_TEST(n == 0);

        // With work posted
        ex.post(make_coro(counter));

        n = ioc.run_one_for(std::chrono::milliseconds(100));
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);
    }

    void
    testRunOneUntil()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // run_one_until with no work - should return after deadline
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
        std::size_t n = ioc.run_one_until(deadline);
        BOOST_TEST(n == 0);

        // Post work and run_one_until
        ex.post(make_coro(counter));

        deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        n = ioc.run_one_until(deadline);
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);
    }

    void
    testRunFor()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // run_for with no work - should return immediately
        auto start = std::chrono::steady_clock::now();
        std::size_t n = ioc.run_for(std::chrono::milliseconds(20));
        auto elapsed = std::chrono::steady_clock::now() - start;

        BOOST_TEST(n == 0);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        BOOST_TEST(ms < 15); // Should return immediately when no work

        // run_for with work
        ex.post(make_coro(counter));
        n = ioc.run_for(std::chrono::milliseconds(100));
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);
    }

    void
    testExecutorRunningInThisThread()
    {
        io_context ioc;
        auto ex = ioc.get_executor();

        // Not running yet - should return false
        BOOST_TEST(ex.running_in_this_thread() == false);

        // Post work that checks running_in_this_thread
        bool during = false;
        ex.post(make_check_coro(during, ex));
        ioc.run();

        BOOST_TEST(during == true);
    }

    void
    run()
    {
        testConstruction();
        testGetExecutor();
        testRun();
        testRunOne();
        testPoll();
        testPollOne();
        testStopAndRestart();
        testRunOneFor();
        testRunOneUntil();
        testRunFor();
        testExecutorRunningInThisThread();
    }
};

TEST_SUITE(io_context_test, "boost.corosio.io_context");

} // namespace corosio
} // namespace boost
