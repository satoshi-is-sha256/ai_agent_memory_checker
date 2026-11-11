// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VIRTUALALLOCINJECTIONMONITOR_H
#define VIRTUALALLOCINJECTIONMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef LPVOID(WINAPI *pfnVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef HANDLE(WINAPI *pfnCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CVirtualallocInjectionMonitor {
public:
    static pfnVirtualAllocEx Original_VirtualAllocEx;
    static pfnCreateRemoteThread Original_CreateRemoteThread;

    static LPVOID WINAPI Hooked_VirtualAllocEx(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    ) {
        if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
            std::ostringstream ss;
            ss << "[INJECTION-AUDIT] Remote Memory Allocation (VirtualAllocEx) Detected!\r\n";
            ss << "  -> Target Process Handle: 0x" << std::hex << (uintptr_t)hProcess << std::dec << "\r\n";
            ss << "  -> Allocated Size: " << dwSize << " bytes\r\n";
            ss << "  -> Protection Flags: 0x" << std::hex << flProtect << std::dec << "\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("RemoteMemoryAlloc", ss.str(), ThreatCorrelator::ThreatLevel::High);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    }

    static HANDLE WINAPI Hooked_CreateRemoteThread(
        HANDLE hProcess,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId
    ) {
        std::ostringstream ss;
        ss << "[INJECTION-AUDIT] Remote Thread Creation (CreateRemoteThread) Intercepted!\r\n";
        ss << "  -> Target Process Handle: 0x" << std::hex << (uintptr_t)hProcess << std::dec << "\r\n";
        ss << "  -> Start Address: 0x" << std::hex << (uintptr_t)lpStartAddress << std::dec << "\r\n";
        ss << "  -> Creation Flags: 0x" << std::hex << dwCreationFlags << std::dec << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("RemoteThreadInjection", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }

    static void InitializeProcessInjectionHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            hKernel32 = LoadLibraryW(L"kernel32.dll");
        }
        if (!hKernel32) return;

        Original_VirtualAllocEx = (pfnVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
        Original_CreateRemoteThread = (pfnCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_VirtualAllocEx) {
            DetourAttach(&(PVOID&)Original_VirtualAllocEx, Hooked_VirtualAllocEx);
        }
        if (Original_CreateRemoteThread) {
            DetourAttach(&(PVOID&)Original_CreateRemoteThread, Hooked_CreateRemoteThread);
        }

        DetourTransactionCommit();
    }

    static void UninitializeProcessInjectionHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_VirtualAllocEx) {
            DetourDetach(&(PVOID&)Original_VirtualAllocEx, Hooked_VirtualAllocEx);
        }
        if (Original_CreateRemoteThread) {
            DetourDetach(&(PVOID&)Original_CreateRemoteThread, Hooked_CreateRemoteThread);
        }

        DetourTransactionCommit();
    }
};

#endif
