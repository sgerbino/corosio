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

/** Mixin base for promise types to support custom frame allocation.

    Derive your promise_type from this class to enable custom coroutine
    frame allocation via a thread-local allocator pointer.

    The allocation strategy:
    @li If a thread-local allocator is set, use it for allocation
    @li Otherwise, fall back to global `::operator new`/`::operator delete`

    A header is prepended to each allocation to store the allocator
    pointer, enabling correct deallocation regardless of which allocator
    was active at allocation time.

    @par Usage
    @code
    // Before creating a coroutine:
    frame_allocating_base::set_frame_allocator(my_allocator);
    auto t = my_coroutine();  // Frame allocated with my_allocator

    // Clear when done (optional)
    frame_allocating_base::clear_frame_allocator();
    @endcode

    @see frame_allocator_base
*/
struct frame_allocating_base
{
private:
    static constexpr std::size_t header_magic = 0xCAFEBABEDEADBEEF;

    struct alignas(alignof(std::max_align_t)) header
    {
        std::size_t magic;
        frame_allocator_base* alloc;
    };

    static frame_allocator_base*&
    current_allocator() noexcept
    {
        static thread_local frame_allocator_base* alloc = nullptr;
        return alloc;
    }

public:
    /** Set the thread-local frame allocator.

        The allocator will be used for subsequent coroutine frame
        allocations on this thread until changed or cleared.

        @param alloc The allocator to use. Must outlive all coroutines
                     allocated with it.
    */
    static void
    set_frame_allocator(frame_allocator_base& alloc) noexcept
    {
        current_allocator() = &alloc;
    }

    /** Clear the thread-local frame allocator.

        Subsequent allocations will use global `::operator new`.
    */
    static void
    clear_frame_allocator() noexcept
    {
        current_allocator() = nullptr;
    }

    /** Get the current thread-local frame allocator.

        @return Pointer to current allocator, or nullptr if none set.
    */
    static frame_allocator_base*
    get_frame_allocator() noexcept
    {
        return current_allocator();
    }

    static void*
    operator new(std::size_t size)
    {
        std::size_t total = size + sizeof(header);
        auto* alloc = current_allocator();

        void* raw;
        if(alloc)
            raw = alloc->allocate(total);
        else
            raw = ::operator new(total);

        auto* h = static_cast<header*>(raw);
        h->magic = header_magic;
        h->alloc = alloc;
        return h + 1;
    }

    /** Deallocate a coroutine frame.

        Uses the allocator pointer stored in the header at allocation
        time, not the current thread-local. This is correct because:
        @li The coroutine may be destroyed on a different thread
        @li The thread-local may have changed since allocation
        @li Guarantees matching allocator for alloc/dealloc pair
    */
    static void
    operator delete(void* ptr, std::size_t size)
    {
        auto* h = static_cast<header*>(ptr) - 1;

        // Verify header integrity
        if(h->magic != header_magic)
            std::terminate();

        std::size_t total = size + sizeof(header);

        // Use stored allocator, not thread-local
        if(h->alloc)
            h->alloc->deallocate(h, total);
        else
            ::operator delete(h, total);
    }
};

} // namespace capy

#endif
