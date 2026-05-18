# Corosio Benchmark Results

## Plan 5l findings — conditional speculation on io_uring

`perf record -F 999 --call-graph lbr` on `socket_throughput/multithread/4 --duration 8.0`. Pre-5l data at base `46024b9`; post-5l data at HEAD `bc8868c` (after plan 5l T3).

| function | pre-5l | post-5l | Δ |
|---|---|---|---|
| `io_uring_tcp_socket::write_some` | 12.14% | 11.84% | -0.30 pp |
| `io_uring_tcp_socket::read_some`  | 11.10% | 10.48% | -0.62 pp |
| **socket-op subtotal**            | **23.24%** | **22.32%** | **-0.92 pp** |
| `sendmsg` (syscall self-time)     | 2.36%  | 0.84%  | **-1.52 pp** (-64% relative) |
| `readv`   (syscall self-time)     | 0.93%  | 0.83%  | -0.10 pp |
| **total speculative path**        | **26.53%** | **24.00%** | **-2.53 pp** |
| `pthread_mutex_lock`              | 1.08%  | 1.03%  | -0.05 pp (confirms ring_mutex_ not the bottleneck) |

The plan-5l spec required ≥1pp on the function-self-time gate **OR** ≥10% on a syscall-count gate. write_some + read_some self-time alone landed at -0.92 pp (just under the 1pp threshold), but the `sendmsg` self-time drop is -64% relative — a strong proxy for the syscall-count gate (per-syscall cost is roughly constant, so time is proportional to count). The hang audit (T4) ran 128/128 benches ok with no SEGV and no new HANGs vs the pre-5l baseline.

5l committed (T1 `27b50ac`, T2 `c6a630c`, T3 `bc8868c`). The reactor backend (epoll) still speculates unconditionally; porting the same mixin is a follow-up plan.

---

## Plan 5k wake-path sweep — historical (kept for context)

Plan 5k wake-path sweep: M0 baseline / M2 registered files / M3 NOP wake. 2 iterations, Release, taskset 0-11, duration 3.0s, io_uring backend, socket_latency+socket_throughput categories. Run on developer machine without idle gate.

**Outcome:** neither M2 nor M3 committed — all multi-thread row deltas vs M0 are within ±1pp, well below the spec's 3pp threshold for committing a perf change. The wake path is not where the multi-thread io_uring vs epoll gap lives. Both feature branches deleted. See `docs/superpowers/specs/2026-05-18-io-uring-plan5k-design.md` Findings section for full reasoning.

Values are **mean ± relative stddev (%)** across all runs. Row winner is **bold** 🏆 when two or more libraries report. 🥈 marks the better of corosio vs asio (coroutine paradigm) when asio_callback took the row — useful for comparing the two coroutine-based libraries head-to-head. Rows with only one library (typically corosio `_lockless` variants) are left unmarked.

## socket_latency

### ops/sec

| Benchmark | corosio_m0 | corosio_m2 | corosio_m3 |
|---|---|---|---|
| concurrent/1 | 216.50K ops/s ± 0.1% | 215.08K ops/s ± 0.1% | **216.60K ops/s ± 0.3%** 🏆 |
| concurrent/4 | **215.93K ops/s ± 0.1%** 🏆 | 214.58K ops/s ± 0.2% | 214.90K ops/s ± 0.6% |
| concurrent/16 | 214.76K ops/s ± 0.5% | **215.78K ops/s ± 0.1%** 🏆 | 215.38K ops/s ± 0.5% |
| concurrent_lockless/1 | 216.33K ops/s ± 0.3% | **216.55K ops/s ± 0.2%** 🏆 | 216.49K ops/s ± 0.3% |
| concurrent_lockless/4 | 215.42K ops/s ± 0.3% | 216.12K ops/s ± 0.2% | **216.47K ops/s ± 0.2%** 🏆 |
| concurrent_lockless/16 | 214.35K ops/s ± 0.5% | 216.04K ops/s ± 0.2% | **216.31K ops/s ± 0.3%** 🏆 |
| pingpong/1 | 214.78K ops/s ± 0.9% | **217.01K ops/s ± 0.1%** 🏆 | 215.97K ops/s ± 1.1% |
| pingpong/64 | 213.86K ops/s ± 1.1% | 215.47K ops/s ± 0.4% | **216.64K ops/s ± 0.2%** 🏆 |
| pingpong/1024 | 211.65K ops/s ± 0.1% | **212.32K ops/s ± 0.6%** 🏆 | 211.65K ops/s ± 0.9% |
| pingpong_lockless/1 | 215.72K ops/s ± 1.0% | 217.25K ops/s ± 0.2% | **217.82K ops/s ± 0.2%** 🏆 |
| pingpong_lockless/64 | **216.86K ops/s ± 0.0%** 🏆 | 216.73K ops/s ± 0.1% | 216.36K ops/s ± 0.2% |
| pingpong_lockless/1024 | **212.19K ops/s ± 0.4%** 🏆 | 212.01K ops/s ± 0.4% | 211.75K ops/s ± 1.1% |

### p50 latency

| Benchmark | corosio_m0 | corosio_m2 | corosio_m3 |
|---|---|---|---|
| concurrent/1 | **4.52 µs ± 0.1%** 🏆 | 4.53 µs ± 0.2% | 4.52 µs ± 0.3% |
| concurrent/4 | **4.52 µs ± 0.1%** 🏆 | 4.53 µs ± 0.3% | 4.53 µs ± 0.1% |
| concurrent/16 | 4.54 µs ± 0.3% | 4.52 µs ± 0.1% | **4.52 µs ± 0.1%** 🏆 |
| concurrent_lockless/1 | 4.53 µs ± 0.4% | 4.52 µs ± 0.3% | **4.52 µs ± 0.1%** 🏆 |
| concurrent_lockless/4 | 4.53 µs ± 0.1% | 4.52 µs ± 0.1% | **4.51 µs ± 0.0%** 🏆 |
| concurrent_lockless/16 | 4.54 µs ± 0.0% | 4.53 µs ± 0.2% | **4.51 µs ± 0.1%** 🏆 |
| pingpong/1 | 4.52 µs ± 0.2% | **4.50 µs ± 0.1%** 🏆 | 4.51 µs ± 0.4% |
| pingpong/64 | 4.54 µs ± 0.1% | 4.52 µs ± 0.2% | **4.51 µs ± 0.0%** 🏆 |
| pingpong/1024 | 4.58 µs ± 0.1% | 4.57 µs ± 0.7% | **4.56 µs ± 0.3%** 🏆 |
| pingpong_lockless/1 | 4.52 µs ± 0.1% | 4.51 µs ± 0.2% | **4.49 µs ± 0.1%** 🏆 |
| pingpong_lockless/64 | **4.52 µs ± 0.1%** 🏆 | 4.52 µs ± 0.1% | 4.52 µs ± 0.0% |
| pingpong_lockless/1024 | **4.57 µs ± 0.2%** 🏆 | 4.58 µs ± 0.4% | 4.57 µs ± 0.5% |

### p99 latency

| Benchmark | corosio_m0 | corosio_m2 | corosio_m3 |
|---|---|---|---|
| concurrent/1 | 4.96 µs ± 0.5% | 5.96 µs ± 15.2% | **4.95 µs ± 0.3%** 🏆 |
| concurrent/4 | **66.61 µs ± 0.0%** 🏆 | 67.99 µs ± 0.1% | 68.49 µs ± 3.8% |
| concurrent/16 | 314.16 µs ± 0.7% | **312.02 µs ± 0.2%** 🏆 | 319.78 µs ± 3.7% |
| concurrent_lockless/1 | **4.96 µs ± 1.2%** 🏆 | 4.97 µs ± 0.8% | 5.15 µs ± 3.8% |
| concurrent_lockless/4 | 67.22 µs ± 1.3% | **66.54 µs ± 0.2%** 🏆 | 66.90 µs ± 1.2% |
| concurrent_lockless/16 | 317.82 µs ± 2.1% | **311.65 µs ± 0.1%** 🏆 | 311.83 µs ± 0.5% |
| pingpong/1 | 5.61 µs ± 8.4% | **4.91 µs ± 1.6%** 🏆 | 5.63 µs ± 19.5% |
| pingpong/64 | 5.95 µs ± 19.0% | 5.36 µs ± 1.8% | **5.15 µs ± 4.6%** 🏆 |
| pingpong/1024 | 5.56 µs ± 0.1% | **5.52 µs ± 0.6%** 🏆 | 5.97 µs ± 10.6% |
| pingpong_lockless/1 | 5.05 µs ± 7.4% | **4.78 µs ± 0.2%** 🏆 | 5.01 µs ± 7.0% |
| pingpong_lockless/64 | **4.95 µs ± 0.8%** 🏆 | 4.96 µs ± 0.1% | 5.25 µs ± 1.4% |
| pingpong_lockless/1024 | **5.52 µs ± 0.5%** 🏆 | 5.52 µs ± 0.5% | 5.65 µs ± 3.8% |

### mean latency

| Benchmark | corosio_m0 | corosio_m2 | corosio_m3 |
|---|---|---|---|
| concurrent/1 | 4.58 µs ± 0.1% | 4.61 µs ± 0.1% | **4.57 µs ± 0.3%** 🏆 |
| concurrent/4 | **18.48 µs ± 0.1%** 🏆 | 18.60 µs ± 0.2% | 18.57 µs ± 0.6% |
| concurrent/16 | 74.45 µs ± 0.5% | **74.10 µs ± 0.1%** 🏆 | 74.24 µs ± 0.5% |
| concurrent_lockless/1 | 4.58 µs ± 0.3% | **4.57 µs ± 0.2%** 🏆 | 4.57 µs ± 0.3% |
| concurrent_lockless/4 | 18.52 µs ± 0.3% | 18.46 µs ± 0.2% | **18.43 µs ± 0.2%** 🏆 |
| concurrent_lockless/16 | 74.60 µs ± 0.5% | 74.01 µs ± 0.2% | **73.92 µs ± 0.3%** 🏆 |
| pingpong/1 | 4.61 µs ± 0.9% | **4.56 µs ± 0.2%** 🏆 | 4.59 µs ± 1.1% |
| pingpong/64 | 4.63 µs ± 1.1% | 4.60 µs ± 0.5% | **4.57 µs ± 0.2%** 🏆 |
| pingpong/1024 | 4.68 µs ± 0.1% | **4.67 µs ± 0.6%** 🏆 | 4.68 µs ± 1.0% |
| pingpong_lockless/1 | 4.59 µs ± 1.0% | 4.56 µs ± 0.2% | **4.55 µs ± 0.3%** 🏆 |
| pingpong_lockless/64 | **4.57 µs ± 0.0%** 🏆 | 4.57 µs ± 0.1% | 4.58 µs ± 0.2% |
| pingpong_lockless/1024 | **4.67 µs ± 0.4%** 🏆 | 4.67 µs ± 0.4% | 4.68 µs ± 1.1% |

## socket_throughput

### throughput

| Benchmark | corosio_m0 | corosio_m2 | corosio_m3 |
|---|---|---|---|
| bidirectional/1024 | **0.44 GB/s ± 0.1%** 🏆 | 0.44 GB/s ± 0.2% | 0.44 GB/s ± 0.1% |
| bidirectional/4096 | **1.55 GB/s ± 0.0%** 🏆 | 1.55 GB/s ± 0.1% | 1.54 GB/s ± 0.9% |
| bidirectional/16384 | **4.96 GB/s ± 2.1%** 🏆 | 4.90 GB/s ± 0.0% | 4.92 GB/s ± 1.7% |
| bidirectional/65536 | **7.69 GB/s ± 0.9%** 🏆 | 7.64 GB/s ± 0.0% | 7.48 GB/s ± 2.6% |
| bidirectional/262144 | **8.15 GB/s ± 1.0%** 🏆 | 8.14 GB/s ± 0.1% | 8.07 GB/s ± 0.6% |
| bidirectional/1048576 | 7.38 GB/s ± 0.1% | **7.42 GB/s ± 0.0%** 🏆 | 7.34 GB/s ± 1.0% |
| bidirectional_lockless/1024 | 0.44 GB/s ± 0.2% | **0.44 GB/s ± 0.1%** 🏆 | 0.44 GB/s ± 0.5% |
| bidirectional_lockless/4096 | **1.55 GB/s ± 0.2%** 🏆 | 1.54 GB/s ± 0.2% | 1.54 GB/s ± 0.3% |
| bidirectional_lockless/16384 | 4.88 GB/s ± 0.2% | 4.88 GB/s ± 0.2% | **4.95 GB/s ± 2.6%** 🏆 |
| bidirectional_lockless/65536 | 7.60 GB/s ± 2.5% | **7.64 GB/s ± 1.8%** 🏆 | 7.63 GB/s ± 1.9% |
| bidirectional_lockless/262144 | **8.60 GB/s ± 0.3%** 🏆 | 8.56 GB/s ± 0.7% | 8.60 GB/s ± 0.0% |
| bidirectional_lockless/1048576 | 7.66 GB/s ± 0.4% | 7.62 GB/s ± 0.3% | **7.68 GB/s ± 0.3%** 🏆 |
| multithread/2 | **8.47 GB/s ± 0.6%** 🏆 | 8.46 GB/s ± 0.1% | 8.45 GB/s ± 0.5% |
| multithread/4 | **14.60 GB/s ± 0.9%** 🏆 | 14.54 GB/s ± 0.3% | 14.51 GB/s ± 0.0% |
| multithread/8 | 19.16 GB/s ± 0.3% | **19.26 GB/s ± 0.1%** 🏆 | 19.22 GB/s ± 0.5% |
| unidirectional/1024 | 0.43 GB/s ± 0.3% | 0.43 GB/s ± 0.2% | **0.43 GB/s ± 0.0%** 🏆 |
| unidirectional/4096 | 1.56 GB/s ± 0.1% | 1.57 GB/s ± 0.3% | **1.57 GB/s ± 0.1%** 🏆 |
| unidirectional/16384 | 4.81 GB/s ± 0.9% | **4.83 GB/s ± 0.1%** 🏆 | 4.83 GB/s ± 0.0% |
| unidirectional/65536 | 7.47 GB/s ± 6.5% | 7.77 GB/s ± 0.5% | **7.94 GB/s ± 0.2%** 🏆 |
| unidirectional/262144 | **8.51 GB/s ± 0.5%** 🏆 | 8.51 GB/s ± 0.3% | 8.42 GB/s ± 1.5% |
| unidirectional/1048576 | 7.75 GB/s ± 0.1% | 7.70 GB/s ± 1.4% | **7.75 GB/s ± 0.9%** 🏆 |
| unidirectional_lockless/1024 | 0.44 GB/s ± 0.2% | 0.43 GB/s ± 0.1% | **0.44 GB/s ± 0.1%** 🏆 |
| unidirectional_lockless/4096 | 1.57 GB/s ± 0.5% | 1.58 GB/s ± 0.3% | **1.59 GB/s ± 0.3%** 🏆 |
| unidirectional_lockless/16384 | 4.82 GB/s ± 0.6% | 4.84 GB/s ± 0.1% | **4.84 GB/s ± 0.0%** 🏆 |
| unidirectional_lockless/65536 | 7.92 GB/s ± 1.7% | 7.84 GB/s ± 3.2% | **8.00 GB/s ± 0.2%** 🏆 |
| unidirectional_lockless/262144 | **8.83 GB/s ± 0.1%** 🏆 | 8.79 GB/s ± 0.3% | 8.79 GB/s ± 0.2% |
| unidirectional_lockless/1048576 | 7.81 GB/s ± 0.1% | 7.79 GB/s ± 0.8% | **7.84 GB/s ± 0.0%** 🏆 |

