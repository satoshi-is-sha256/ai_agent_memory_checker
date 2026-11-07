// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DLLLOADMONITOR_H
#define DLLLOADMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <iomanip>
#include "detours.h"

typedef HMODULE(WINAPI *pfnLoadLibraryExW)(
    LPCWSTR lpLibFileName,
    HANDLE hFile,
    DWORD dwFlags
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CDllLoadMonitor {
public:
    static pfnLoadLibraryExW Original_LoadLibraryExW;

    static HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
        if (lpLibFileName) {
            std::wstring libPath(lpLibFileName);
            std::string utf8Path = WStringToString(libPath);

            std::ostringstream ss;
            ss << "[DLL-LOAD] Dynamic Library Loading Intercepted!\r\n";
            ss << "  -> Module Path: " << utf8Path << "\r\n";
            ss << "  -> Load Flags: 0x" << std::hex << dwFlags << std::dec << "\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("DllLoad", ss.str(), ThreatCorrelator::ThreatLevel::Low);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    }

    static void InitializeDllLoadHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_LoadLibraryExW = (pfnLoadLibraryExW)GetProcAddress(hKernel32, "LoadLibraryExW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_LoadLibraryExW) {
            DetourAttach(&(PVOID&)Original_LoadLibraryExW, Hooked_LoadLibraryExW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeDllLoadHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_LoadLibraryExW) {
            DetourDetach(&(PVOID&)Original_LoadLibraryExW, Hooked_LoadLibraryExW);
        }
        DetourTransactionCommit();
    }
};

#endif