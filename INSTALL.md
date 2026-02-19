# Installing Boost.Corosio

Corosio can be consumed by external CMake projects in two ways. In both
cases, Capy is fetched automatically when not already available.

## Install and find_package

Build, install to a prefix, then consume with `find_package` from any
project.

```bash
git clone https://github.com/cppalliance/corosio.git
cd corosio
cmake -B _build -DCMAKE_BUILD_TYPE=Release
cmake --build _build
cmake --install _build --prefix /path/to/prefix
```

In your project:

```cmake
cmake_minimum_required(VERSION 3.20)
project(myapp CXX)

find_package(boost_corosio REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE Boost::corosio)
```

Configure with the install prefix:

```bash
cmake -B _build -DCMAKE_PREFIX_PATH=/path/to/prefix
cmake --build _build
```

### SSL Backends

WolfSSL and OpenSSL backends are built automatically when the libraries
are found on the system. After installation, link to `Boost::corosio_wolfssl`
or `Boost::corosio_openssl`:

```cmake
find_package(boost_corosio REQUIRED)
target_link_libraries(myapp PRIVATE Boost::corosio_wolfssl)
```

## FetchContent

Pull Corosio (and transitively Capy) directly into your CMake build.

```cmake
cmake_minimum_required(VERSION 3.20)
project(myapp CXX)

include(FetchContent)
FetchContent_Declare(
    corosio
    GIT_REPOSITORY https://github.com/cppalliance/corosio.git
    GIT_TAG develop
    GIT_SHALLOW TRUE)

set(BOOST_COROSIO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_PERF OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(corosio)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE Boost::corosio)
```

### Using a Local Capy Checkout

Override the Capy fetch with a local directory:

```bash
cmake -B _build -DFETCHCONTENT_SOURCE_DIR_CAPY=/path/to/capy
```

## CMake Targets

| Target | Description |
|---|---|
| `Boost::corosio` | Core networking library |
| `Boost::corosio_wolfssl` | WolfSSL TLS backend (when WolfSSL is found) |
| `Boost::corosio_openssl` | OpenSSL TLS backend (when OpenSSL is found) |
| `Boost::capy` | Capy (transitive dependency, always available) |

## Requirements

- CMake 3.20 or later
- C++20 compiler (GCC 12+, Clang 17+, MSVC 14.34+)
- Ninja (recommended) or other CMake generator
