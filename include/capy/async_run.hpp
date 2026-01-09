//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef CAPY_ASYNC_RUN_HPP
#define CAPY_ASYNC_RUN_HPP

#include <capy/config.hpp>
#include <capy/affine.hpp>
#include <capy/executor.hpp>
#include <capy/task.hpp>
#include <capy/detail/frame_pool.hpp>

#include <exception>
#include <optional>
#include <utility>

namespace capy {

/** Default completion handler for async_run.

    Discards the result on success, rethrows on exception.
*/
struct default_handler
{
    // Success with result (non-void tasks)
    template<typename T>
    void operator()(T&&) const noexcept
    {
    }

    // Success with no result (void tasks)
    void operator()() const noexcept
    {
    }

    // Error
    void operator()(std::exception_ptr ep) const
    {
        if(ep)
            std::rethrow_exception(ep);
    }
};

namespace detail {

// Helper base for result storage and return_void/return_value
template<typename T, typename Derived>
struct root_task_result
{
    std::optional<T> result_;

    template<typename U>
    void return_value(U&& value)
    {
        result_ = std::forward<U>(value);
    }
};

template<typename Derived>
struct root_task_result<void, Derived>
{
    void return_void()
    {
    }
};

template<executor Executor, typename T, typename Handler>
struct root_task
{
    struct starter : executor_work
    {
        coro h_;

        void operator()() override
        {
            h_.resume();
        }

        void destroy() override
        {
            // Not meant to be destroyed externally; owned by promise_type
        }
    };

    struct promise_type
        : capy::detail::frame_pool::promise_allocator
        , root_task_result<T, promise_type>
    {
        Executor ex_;
        Handler handler_;
        starter starter_;
        std::exception_ptr ep_;

        template<typename E, typename H, typename... Args>
        promise_type(E&&, H&& h, Args&&...)
            : handler_(std::forward<H>(h))
        {
        }

        root_task get_return_object()
        {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        std::suspend_always initial_suspend() noexcept
        {
            return {};
        }

        auto final_suspend() noexcept
        {
            struct awaiter
            {
                promise_type* p_;

                bool await_ready() const noexcept
                {
                    return false;
                }

                coro await_suspend(coro h) const noexcept
                {
                    // Save before destroy
                    auto handler = std::move(p_->handler_);
                    auto ep = p_->ep_;
                    
                    // For non-void, we need to get the result before destroy
                    if constexpr (!std::is_void_v<T>)
                    {
                        auto result = std::move(p_->result_);
                        h.destroy();
                        if(ep)
                            handler(ep);
                        else if(result)
                            handler(std::move(*result));
                    }
                    else
                    {
                        h.destroy();
                        if(ep)
                            handler(ep);
                        else
                            handler();
                    }
                    return std::noop_coroutine();
                }

                void await_resume() const noexcept
                {
                }
            };
            return awaiter{this};
        }

        // return_void() or return_value() inherited from root_task_result

        void unhandled_exception()
        {
            ep_ = std::current_exception();
        }

        template<class Awaitable>
        struct transform_awaiter
        {
            std::decay_t<Awaitable> a_;
            promise_type* p_;

            bool await_ready()
            {
                return a_.await_ready();
            }

            auto await_resume()
            {
                return a_.await_resume();
            }

            template<class Promise>
            auto await_suspend(std::coroutine_handle<Promise> h)
            {
                return a_.await_suspend(h, p_->ex_);
            }
        };

        template<class Awaitable>
        auto await_transform(Awaitable&& a)
        {
            return transform_awaiter<Awaitable>{std::forward<Awaitable>(a), this};
        }
    };

    std::coroutine_handle<promise_type> h_;

    void release()
    {
        h_ = nullptr;
    }

    ~root_task()
    {
        if(h_)
            h_.destroy();
    }
};

template<executor Executor, typename T, typename Handler>
root_task<Executor, T, Handler>
wrapper(Executor, Handler handler, task<T> t)
{
    if constexpr (std::is_void_v<T>)
        co_await std::move(t);
    else
        co_return co_await std::move(t);
}

} // namespace detail

/** Starts a task for execution on an executor.

    This function initiates execution of a task by posting it to the
    specified executor's work queue. The task will begin running when
    the executor processes the posted work item.

    @param ex The executor on which to run the task.
    @param t The task to execute.
    @param handler Completion handler called with T on success or
                   std::exception_ptr on error. Defaults to default_handler
                   which discards results and rethrows exceptions.

    @par Example
    @code
    io_context ioc;
    
    // Fire and forget (default handler)
    async_run(ioc.get_executor(), my_coroutine());
    
    // With completion handler
    async_run(ioc.get_executor(), compute_value(), overload{
        [](int result) { std::cout << "Got: " << result << "\n"; },
        [](std::exception_ptr ep) { }
    });
    
    ioc.run();
    @endcode

    @note The executor and handler are captured by value to ensure they
    remain valid for the duration of the task's execution.
*/
template<executor Executor, typename T, typename Handler = default_handler>
void async_run(Executor ex, task<T> t, Handler handler = {})
{
    auto root = detail::wrapper<Executor, T, Handler>(ex, std::move(handler), std::move(t));
    root.h_.promise().ex_ = std::move(ex);
    root.h_.promise().starter_.h_ = root.h_;
    root.h_.promise().ex_.post(&root.h_.promise().starter_);
    root.release();
}

} // namespace capy

#endif
