//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef CAPY_FRAME_ALLOCATOR_HPP
#define CAPY_FRAME_ALLOCATOR_HPP

#include <capy/config.hpp>

#include <concepts>
#include <cstddef>
#include <new>

namespace capy {

/** Abstract base class for frame allocators.

    This class provides a polymorphic interface for coroutine frame
    allocation. Concrete allocators derive from this base and implement
    the virtual allocate/deallocate methods.

    @see frame_allocator
    @see default_frame_allocator
*/
class frame_allocator_base
{
public:
    virtual ~frame_allocator_base() = default;

    /** Allocate memory for a coroutine frame.

        @param n The number of bytes to allocate.

        @return A pointer to the allocated memory.
    */
    virtual void* allocate(std::size_t n) = 0;

    /** Deallocate memory for a coroutine frame.

        @param p Pointer to the memory to deallocate.
        @param n The number of bytes to deallocate.
    */
    virtual void deallocate(void* p, std::size_t n) = 0;
};

/** A concept for types that can allocate and deallocate memory for coroutine frames.

    Frame allocators are used to manage memory for coroutine frames, enabling
    custom allocation strategies such as pooling to reduce allocation overhead.

    Types satisfying this concept must derive from `frame_allocator_base`.

    @tparam A The type to check for frame allocator conformance.

    @see frame_allocator_base
*/
template<class A>
concept frame_allocator = std::derived_from<A, frame_allocator_base>;

/** A concept for types that provide access to a frame allocator.

    Types satisfying this concept can be used as the first or second parameter
    to coroutine functions to enable custom frame allocation. The promise type
    will call `get_frame_allocator()` to obtain the allocator for the coroutine
    frame.

    Given:
    @li `t` a reference to type `T`

    The following expression must be valid:
    @li `t.get_frame_allocator()` - Returns a reference to a type satisfying
        `frame_allocator`

    @tparam T The type to check for frame allocator access.
*/
template<class T>
concept has_frame_allocator = requires(T& t) {
    { t.get_frame_allocator() } -> frame_allocator;
};

/** A frame allocator that passes through to global new/delete.

    This allocator provides no pooling or recycling—each allocation
    goes directly to `::operator new` and each deallocation goes to
    `::operator delete`. It serves as a baseline for comparison and
    as a fallback when pooling is not desired.

    @see frame_allocator_base
*/
struct default_frame_allocator : frame_allocator_base
{
    void* allocate(std::size_t n) override
    {
        return ::operator new(n);
    }

    void deallocate(void* p, std::size_t) override
    {
        ::operator delete(p);
    }
};

static_assert(frame_allocator<default_frame_allocator>);

} // namespace capy

#endif
