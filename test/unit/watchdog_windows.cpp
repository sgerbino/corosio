//
// Copyright (c) 2026 Steve Gerbino
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/corosio
//

// Diagnostic watchdog for hunting the Windows coverage-build hang.
//
// Background: the gcc + gcov coverage CI times out (1500s) in exactly
// the suites that exercise AF_UNIX sockets on IOCP
// (local_stream_socket.iocp, native.local_stream_socket.iocp,
// wait.iocp). It does not reproduce on a normal local build. We have
// been unable to capture *where* the process is stuck.
//
// This TU arms a process-wide watchdog thread at static-init time when
// the environment variable COROSIO_WATCHDOG_SECS is set to a positive
// integer. Each ctest invocation runs a single suite in its own
// process, so a process-wide timeout is effectively per-suite. When
// the timeout elapses (i.e. the suite is hung), the watchdog walks and
// prints the call stack of every thread in the process, then aborts so
// CTest records the failure with the stacks in the captured output.
//
// MinGW emits DWARF debug info, which dbghelp cannot symbolize inline.
// We therefore print, for each frame, the owning module and its RVA:
//   <module>+0x<rva>
// Resolve offline by adding the module's preferred ImageBase (the
// MinGW x64 default for the test exe is 0x140000000), e.g.:
//   addr2line -f -C -i -e boost_corosio_tests.exe 0x$((0x140000000 + rva))
// SymFromAddr is also attempted best-effort (resolves public/system
// symbols such as the ntdll/KERNELBASE frames).
//
// This file compiles to nothing on non-Windows targets.

#if defined(_WIN32)

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

// clang-format off
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
// clang-format on

namespace {

// Identify the owning module of a runtime address and the address's
// offset within it (RVA). Resolve offline with addr2line by adding the
// module's preferred ImageBase (0x140000000 for the MinGW x64 exe).
void
describe_addr(DWORD64 addr, char* mod_out, std::size_t mod_cap, DWORD64* rva_out)
{
    *rva_out = 0;
    std::snprintf(mod_out, mod_cap, "?");

    HMODULE hmod = nullptr;
    if (!::GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(addr), &hmod) ||
        hmod == nullptr)
        return;

    char path[MAX_PATH];
    if (::GetModuleFileNameA(hmod, path, MAX_PATH))
    {
        // Keep only the file name.
        char const* base = std::strrchr(path, '\\');
        std::snprintf(mod_out, mod_cap, "%s", base ? base + 1 : path);
    }

    *rva_out = addr - reinterpret_cast<DWORD64>(hmod);
}

void
dump_thread(HANDLE proc, HANDLE thread, DWORD tid)
{
    if (::SuspendThread(thread) == DWORD(-1))
        return;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!::GetThreadContext(thread, &ctx))
    {
        ::ResumeThread(thread);
        return;
    }

    STACKFRAME64 frame{};
    DWORD machine;
#if defined(_M_X64) || defined(__x86_64__)
    machine              = IMAGE_FILE_MACHINE_AMD64;
    frame.AddrPC.Offset    = ctx.Rip;
    frame.AddrFrame.Offset = ctx.Rbp;
    frame.AddrStack.Offset = ctx.Rsp;
#else
    machine              = IMAGE_FILE_MACHINE_I386;
    frame.AddrPC.Offset    = ctx.Eip;
    frame.AddrFrame.Offset = ctx.Ebp;
    frame.AddrStack.Offset = ctx.Esp;
#endif
    frame.AddrPC.Mode    = AddrModeFlat;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Mode = AddrModeFlat;

    std::fprintf(stderr, "  --- thread %lu ---\n", static_cast<unsigned long>(tid));

    alignas(SYMBOL_INFO) char sym_buf[sizeof(SYMBOL_INFO) + 512];
    auto* sym         = reinterpret_cast<SYMBOL_INFO*>(sym_buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = 511;

    for (int i = 0; i < 64; ++i)
    {
        if (!::StackWalk64(
                machine, proc, thread, &frame, &ctx, nullptr,
                ::SymFunctionTableAccess64, ::SymGetModuleBase64, nullptr))
            break;
        DWORD64 const pc = frame.AddrPC.Offset;
        if (pc == 0)
            break;

        char mod[64];
        DWORD64 rva = 0;
        describe_addr(pc, mod, sizeof(mod), &rva);

        char const* name = "";
        DWORD64 disp     = 0;
        if (::SymFromAddr(proc, pc, &disp, sym))
            name = sym->Name;

        std::fprintf(
            stderr, "    #%-2d %s+0x%llx  %s\n", i, mod,
            static_cast<unsigned long long>(rva), name);
    }

    ::ResumeThread(thread);
}

void
fire()
{
    HANDLE proc = ::GetCurrentProcess();
    ::SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    ::SymInitialize(proc, nullptr, TRUE);

    std::fprintf(
        stderr,
        "\n==================== COROSIO WATCHDOG FIRED ====================\n"
        "process appears hung; dumping all thread stacks then aborting.\n"
        "frames show <module>+0x<rva>; resolve exe frames offline with:\n"
        "  addr2line -f -C -i -e boost_corosio_tests.exe "
        "$((0x140000000 + rva))\n");
    std::fflush(stderr);

    DWORD const self_pid = ::GetCurrentProcessId();
    DWORD const self_tid = ::GetCurrentThreadId();

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (::Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != self_pid)
                    continue;
                if (te.th32ThreadID == self_tid)
                    continue;
                HANDLE th = ::OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                        THREAD_QUERY_INFORMATION,
                    FALSE, te.th32ThreadID);
                if (th)
                {
                    dump_thread(proc, th, te.th32ThreadID);
                    ::CloseHandle(th);
                }
            } while (::Thread32Next(snap, &te));
        }
        ::CloseHandle(snap);
    }

    std::fprintf(
        stderr,
        "==================== END WATCHDOG DUMP ====================\n\n");
    std::fflush(stderr);

    // _exit with a distinctive code; abort() can deadlock if the hang
    // holds a CRT lock, and we want CTest to see a clean failure.
    ::TerminateProcess(::GetCurrentProcess(), 99);
}

struct watchdog_arm
{
    watchdog_arm()
    {
        char secs[32];
        DWORD got = ::GetEnvironmentVariableA(
            "COROSIO_WATCHDOG_SECS", secs, sizeof(secs));
        if (got == 0 || got >= sizeof(secs))
            return;
        long n = std::strtol(secs, nullptr, 10);
        if (n <= 0)
            return;

        std::thread([n] {
            std::this_thread::sleep_for(std::chrono::seconds(n));
            fire();
        }).detach();
    }
};

watchdog_arm const g_watchdog_arm;

} // namespace

#endif // _WIN32
