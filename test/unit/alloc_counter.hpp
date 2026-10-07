//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

#ifndef BOOST_COROSIO_TEST_ALLOC_COUNTER_HPP
#define BOOST_COROSIO_TEST_ALLOC_COUNTER_HPP

/* Shared global operator new/delete counting interposer.

   The replaceable global allocation functions are process-wide and
   may be defined exactly once; continuation_post.cpp owns that one
   definition (guarded against TSan, which replaces them itself).
   Every other test that needs to assert an allocation count --
   zero_alloc.cpp included -- counts against these same extern
   counters instead of layering on a second interposer, which would
   be a link error.
*/

#include <atomic>

// TSan's runtime already replaces global operator new/delete, so a
// counting replacement cannot link under -fsanitize=thread (and the
// counts would reflect the sanitizer's allocator anyway).
#if defined(__SANITIZE_THREAD__)
#define COROSIO_TEST_HAS_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define COROSIO_TEST_HAS_TSAN 1
#endif
#endif

namespace boost::corosio {

#ifndef COROSIO_TEST_HAS_TSAN
/// True while allocations should be tallied into alloc_count.
extern std::atomic<bool> alloc_armed;
/// Running count of operator new calls while alloc_armed is set.
extern std::atomic<long long> alloc_count;
#endif

} // namespace boost::corosio

#endif
