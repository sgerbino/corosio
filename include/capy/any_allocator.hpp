//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef CAPY_ANY_ALLOCATOR_HPP
#define CAPY_ANY_ALLOCATOR_HPP

#include <capy/frame_allocator.hpp>

#include <cstddef>

namespace capy {

/** A type-erased frame allocator.

    This class wraps any type satisfying the `frame_allocator` concept,
    storing only a pointer to the allocator and a pointer to a static
    operations table. This enables polymorphic frame allocation without
    virtual functions or heap allocation for the wrapper itself.

    The wrapped allocator must outlive the `any_allocator` instance.

    @see frame_allocator
*/
class any_allocator
{
    struct ops
    {
        void* (*allocate)(void* alloc, std::size_t n);
        void (*deallocate)(void* alloc, void* p, std::size_t n);
    };

    template<frame_allocator A>
    static ops const&
    ops_for() noexcept
    {
        static constexpr ops o = {
            [](void* alloc, std::size_t n) -> void* {
                return static_cast<A*>(alloc)->allocate(n);
            },
            [](void* alloc, void* p, std::size_t n) {
                static_cast<A*>(alloc)->deallocate(p, n);
            }
        };
        return o;
    }

    void* alloc_;
    ops const* ops_;

public:
    /** Construct from a frame allocator.

        @param alloc The allocator to wrap. Must outlive this instance.
    */
    template<frame_allocator A>
    any_allocator(A& alloc) noexcept
        : alloc_(&alloc)
        , ops_(&ops_for<A>())
    {
    }

    /** Allocate memory for a coroutine frame.

        @param n The number of bytes to allocate.

        @return A pointer to the allocated memory.
    */
    void*
    allocate(std::size_t n)
    {
        return ops_->allocate(alloc_, n);
    }

    /** Deallocate memory for a coroutine frame.

        @param p Pointer to the memory to deallocate.
        @param n The number of bytes to deallocate.
    */
    void
    deallocate(void* p, std::size_t n)
    {
        ops_->deallocate(alloc_, p, n);
    }
};

static_assert(frame_allocator<any_allocator>);

} // namespace capy

#endif
