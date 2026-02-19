include(CMakeFindDependencyMacro)
find_dependency(boost_capy)
find_dependency(Threads)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(WolfSSL QUIET)
find_package(OpenSSL QUIET)

include("${CMAKE_CURRENT_LIST_DIR}/boost_corosio-targets.cmake")
