| Branch | Docs | GitHub Actions | Drone | Codecov |
|:---|:---|:---|:---|:---|
| [`master`](https://github.com/cppalliance/corosio/tree/master) | [![Documentation](https://img.shields.io/badge/docs-master-brightgreen.svg)](https://master.corosio.cpp.al/) | [![CI](https://github.com/cppalliance/corosio/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cppalliance/corosio/actions/workflows/ci.yml?query=branch%3Amaster) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/corosio/status.svg?ref=refs/heads/master)](https://drone.cpp.al/cppalliance/corosio/branches) | [![codecov](https://codecov.io/gh/cppalliance/corosio/branch/master/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/corosio/tree/master) |
| [`develop`](https://github.com/cppalliance/corosio/tree/develop) | [![Documentation](https://img.shields.io/badge/docs-develop-brightgreen.svg)](https://develop.corosio.cpp.al/) | [![CI](https://github.com/cppalliance/corosio/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/cppalliance/corosio/actions/workflows/ci.yml?query=branch%3Adevelop) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/corosio/status.svg?ref=refs/heads/develop)](https://drone.cpp.al/cppalliance/corosio/branches) | [![codecov](https://codecov.io/gh/cppalliance/corosio/branch/develop/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/corosio/tree/develop) |

# Boost.Corosio

Boost.Corosio is a coroutine-only I/O library for C++20 that provides asynchronous networking primitives with automatic executor affinity propagation. Every operation returns an awaitable that integrates with the _IoAwaitable_ protocol, ensuring your coroutines resume on the correct executor without manual dispatch.

## Quick Start

Clone and build with CMake (Capy is fetched automatically):

```bash
git clone https://github.com/cppalliance/corosio.git
cd corosio
cmake -B _build -DCMAKE_BUILD_TYPE=Release
cmake --build _build
```

## Requirements

- CMake 3.20 or later
- C++20 compiler (GCC 12+, Clang 17+, MSVC 14.34+)
- Ninja (recommended) or other CMake generator

## Installation

See [INSTALL.md](INSTALL.md) for detailed instructions on consuming
Corosio via `find_package` or `FetchContent`.

## License

Distributed under the Boost Software License, Version 1.0.
(See accompanying file [LICENSE_1_0.txt](LICENSE_1_0.txt) or copy at
https://www.boost.org/LICENSE_1_0.txt)
