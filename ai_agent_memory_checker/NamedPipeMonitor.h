// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAMEDPIPEMONITOR_H
#define NAMEDPIPEMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef HANDLE(WINAPI *pfnCreateNamedPipeW)(
    LPCWSTR lpName,
    DWORD dwOpenMode,
    DWORD dwPipeMode,
    DWORD nMaxInstances,
    DWORD nOutBufferSize,
    DWORD nInBufferSize,
    DWORD nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );

typedef BOOL(WINAPI *pfnConnectNamedPipe)(
    HANDLE hNamedPipe,
    LPOVERLAPPED lpOverlapped
    );

class CNamedPipeMonitor {
public:
    static pfnCreateNamedPipeW Original_CreateNamedPipeW;
    static pfnConnectNamedPipe Original_ConnectNamedPipe;

    static HANDLE WINAPI Hooked_CreateNamedPipeW(
        LPCWSTR lpName,
        DWORD dwOpenMode,
        DWORD dwPipeMode,
        DWORD nMaxInstances,
        DWORD nOutBufferSize,
        DWORD nInBufferSize,
        DWORD nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ) {
        std::wstring pipeName(lpName ? lpName : L"");
        std::string utf8PipeName = WStringToString(pipeName);

        std::ostringstream ss;
        ss << "[NAMED-PIPE] Named Pipe Creation Intercepted!\r\n";
        ss << "  -> Pipe Name: " << utf8PipeName << "\r\n";
        ss << "  -> Open Mode: 0x" << std::hex << dwOpenMode << std::dec << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("NamedPipe", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    }

    static BOOL WINAPI Hooked_ConnectNamedPipe(
        HANDLE hNamedPipe,
        LPOVERLAPPED lpOverlapped
    ) {
        std::ostringstream ss;
        ss << "[NAMED-PIPE] Client Connection Established on Pipe Handle: 0x" << std::hex << (uintptr_t)hNamedPipe << std::dec << "\r\n";

        g_NtAlpcCreatePortLogs += ss.str();

        return Original_ConnectNamedPipe(hNamedPipe, lpOverlapped);
    }

    static void InitializeNamedPipeHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_CreateNamedPipeW = (pfnCreateNamedPipeW)GetProcAddress(hKernel32, "CreateNamedPipeW");
        Original_ConnectNamedPipe = (pfnConnectNamedPipe)GetProcAddress(hKernel32, "ConnectNamedPipe");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CreateNamedPipeW) {
            DetourAttach(&(PVOID&)Original_CreateNamedPipeW, Hooked_CreateNamedPipeW);
        }
        if (Original_ConnectNamedPipe) {
            DetourAttach(&(PVOID&)Original_ConnectNamedPipe, Hooked_ConnectNamedPipe);
        }

        DetourTransactionCommit();
    }

    static void UninitializeNamedPipeHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CreateNamedPipeW) {
            DetourDetach(&(PVOID&)Original_CreateNamedPipeW, Hooked_CreateNamedPipeW);
        }
        if (Original_ConnectNamedPipe) {
            DetourDetach(&(PVOID&)Original_ConnectNamedPipe, Hooked_ConnectNamedPipe);
        }

        DetourTransactionCommit();
    }
};

#endif
