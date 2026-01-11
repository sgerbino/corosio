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

// Simple work item for testing
struct test_work : capy::executor_work
{
    int& counter;

    explicit test_work(int& c) : counter(c) {}

    void operator()() override
    {
        ++counter;
        delete this;
    }

    void destroy() override
    {
        delete this;
    }
};

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
        ex.post(new test_work(counter));
        ex.post(new test_work(counter));
        ex.post(new test_work(counter));

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

        ex.post(new test_work(counter));
        ex.post(new test_work(counter));

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

        // Poll with no work should return 0
        std::size_t n = ioc.poll();
        BOOST_TEST(n == 0);

        // Add work
        ex.post(new test_work(counter));
        ex.post(new test_work(counter));

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

        // poll_one with no work should return 0
        std::size_t n = ioc.poll_one();
        BOOST_TEST(n == 0);

        ex.post(new test_work(counter));
        ex.post(new test_work(counter));

        // poll_one should execute exactly one
        n = ioc.poll_one();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);

        n = ioc.poll_one();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 2);

        // No more work
        n = ioc.poll_one();
        BOOST_TEST(n == 0);
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
        ex.post(new test_work(counter));

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
    testRunOneWithTimeout()
    {
        io_context ioc;
        int counter = 0;

        // run_one with timeout and no work - should return after timeout
        auto start = std::chrono::steady_clock::now();
        std::size_t n = ioc.run_one(10000); // 10ms timeout
        auto elapsed = std::chrono::steady_clock::now() - start;

        BOOST_TEST(n == 0);
        // Should have waited at least some time (allow for timing variance)
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        BOOST_TEST(ms >= 5); // At least 5ms

        // With work posted
        auto ex = ioc.get_executor();
        ex.post(new test_work(counter));

        n = ioc.run_one(100000); // 100ms timeout
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);
    }

    void
    testWaitOne()
    {
        io_context ioc;
        auto ex = ioc.get_executor();
        int counter = 0;

        // wait_one with no work - should timeout
        std::size_t n = ioc.wait_one(10000); // 10ms
        BOOST_TEST(n == 0);

        // Post work
        ex.post(new test_work(counter));

        // wait_one should indicate work available but not execute
        n = ioc.wait_one(100000); // 100ms
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 0); // Not executed yet

        // Now run to actually execute
        n = ioc.run();
        BOOST_TEST(n == 1);
        BOOST_TEST(counter == 1);
    }

    void
    testRunFor()
    {
        io_context ioc;

        // run_for with no work
        auto start = std::chrono::steady_clock::now();
        std::size_t n = ioc.run_for(std::chrono::milliseconds(20));
        auto elapsed = std::chrono::steady_clock::now() - start;

        BOOST_TEST(n == 0);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        BOOST_TEST(ms >= 15); // Should have waited close to 20ms
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
        struct check_work : capy::executor_work
        {
            bool& result;
            io_context::executor_type ex;

            check_work(bool& r, io_context::executor_type e)
                : result(r), ex(e) {}

            void operator()() override
            {
                result = ex.running_in_this_thread();
                delete this;
            }

            void destroy() override { delete this; }
        };

        ex.post(new check_work(during, ex));
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
        testRunOneWithTimeout();
        testWaitOne();
        testRunFor();
        testExecutorRunningInThisThread();
    }
};

TEST_SUITE(io_context_test, "boost.corosio.io_context");

} // namespace corosio
} // namespace boost
