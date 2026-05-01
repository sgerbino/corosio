#
# Copyright (c) 2026 Steve Gerbino
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/cppalliance/corosio
#

# Find liburing via pkg-config and expose an imported target liburing::liburing.
# Sets: liburing_FOUND, liburing_VERSION

find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(_liburing QUIET liburing)

    if(_liburing_FOUND)
        set(liburing_VERSION "${_liburing_VERSION}")

        add_library(liburing::liburing INTERFACE IMPORTED)
        target_include_directories(liburing::liburing INTERFACE ${_liburing_INCLUDE_DIRS})
        target_link_libraries(liburing::liburing INTERFACE ${_liburing_LINK_LIBRARIES})
        target_compile_options(liburing::liburing INTERFACE ${_liburing_CFLAGS_OTHER})

        set(liburing_FOUND TRUE)
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(liburing
    REQUIRED_VARS liburing_FOUND
    VERSION_VAR   liburing_VERSION)
