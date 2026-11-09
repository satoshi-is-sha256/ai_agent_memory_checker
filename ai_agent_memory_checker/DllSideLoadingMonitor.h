// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DLLSIDELOADINGMONITOR_H
#define DLLSIDELOADINGMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <winternl.h>
#include "detours.h"

typedef NTSTATUS (NTAPI *pfnLdrLoadDll)(
    PWSTR SearchPath,
    PULONG LoadFlags,
    PUNICODE_STRING DllName,
    PHANDLE BaseAddress
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CDllSideLoadingMonitor {
public:
    static pfnLdrLoadDll Original_LdrLoadDll;

    static NTSTATUS NTAPI Hooked_LdrLoadDll(
        PWSTR SearchPath,
        PULONG LoadFlags,
        PUNICODE_STRING DllName,
        PHANDLE BaseAddress
    ) {
        std::wstring dllPath = L"";
        if (DllName && DllName->Buffer && DllName->Length > 0) {
            dllPath = std::wstring(DllName->Buffer, DllName->Length / sizeof(WCHAR));
        }
        std::string utf8DllPath = WStringToString(dllPath);

        std::ostringstream ss;
        ss << "[DLL-LOAD-AUDIT] Module Loading Intercepted (LdrLoadDll):\r\n";
        ss << "  -> Target DLL: " << utf8DllPath << "\r\n";


        if (utf8DllPath.find("C:\\Temp\\") != std::string::npos || utf8DllPath.find("AppData\\Local\\Temp") != std::string::npos) {
            ThreatCorrelator::GetInstance().IngestEvent("DllSideLoading", ss.str(), ThreatCorrelator::ThreatLevel::High);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_LdrLoadDll(SearchPath, LoadFlags, DllName, BaseAddress);
    }

    static void InitializeDllSideLoadingHooks() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        Original_LdrLoadDll = (pfnLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_LdrLoadDll) {
            DetourAttach(&(PVOID&)Original_LdrLoadDll, Hooked_LdrLoadDll);
        }

        DetourTransactionCommit();
    }

    static void UninitializeDllSideLoadingHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_LdrLoadDll) {
            DetourDetach(&(PVOID&)Original_LdrLoadDll, Hooked_LdrLoadDll);
        }

        DetourTransactionCommit();
    }
};

#endif
