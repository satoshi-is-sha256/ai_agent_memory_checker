// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DRIVERLOADMONITOR_H
#define DRIVERLOADMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <winternl.h>
#include "detours.h"

typedef NTSTATUS(NTAPI *pfnNtLoadDriver)(
    PUNICODE_STRING DriverServiceName
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CDriverLoadMonitor {
public:
    static pfnNtLoadDriver Original_NtLoadDriver;

    static NTSTATUS NTAPI Hooked_NtLoadDriver(PUNICODE_STRING DriverServiceName) {
        std::wstring servicePath = L"";
        if (DriverServiceName && DriverServiceName->Buffer && DriverServiceName->Length > 0) {
            servicePath = std::wstring(DriverServiceName->Buffer, DriverServiceName->Length / sizeof(WCHAR));
        }
        std::string utf8ServicePath = WStringToString(servicePath);

        std::ostringstream ss;
        ss << "[DRIVER-LOAD-AUDIT] Kernel Driver Load Intercepted (NtLoadDriver)!\r\n";
        ss << "  -> Target Driver Service Path: " << utf8ServicePath << "\r\n";

        if (utf8ServicePath.find("Temp") != std::string::npos || utf8ServicePath.find("AppData") != std::string::npos) {
            ThreatCorrelator::GetInstance().IngestEvent("UnauthorizedDriverLoad", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_NtLoadDriver(DriverServiceName);
    }

    static void InitializeDriverLoadHooks() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        Original_NtLoadDriver = (pfnNtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_NtLoadDriver) {
            DetourAttach(&(PVOID&)Original_NtLoadDriver, Hooked_NtLoadDriver);
        }

        DetourTransactionCommit();
    }

    static void UninitializeDriverLoadHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_NtLoadDriver) {
            DetourDetach(&(PVOID&)Original_NtLoadDriver, Hooked_NtLoadDriver);
        }

        DetourTransactionCommit();
    }
};

#endif
