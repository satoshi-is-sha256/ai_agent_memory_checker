// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HANDLEACCESSMONITOR_H
#define HANDLEACCESSMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <iomanip>
#include "detours.h"

typedef HANDLE(WINAPI *pfnOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CHandleAccessMonitor {
public:
    static pfnOpenProcess Original_OpenProcess;

    static std::string ParseProcessAccessRights(DWORD access) {
        std::ostringstream oss;
        if (access & PROCESS_ALL_ACCESS)           return "PROCESS_ALL_ACCESS (Critical)";
        if (access & PROCESS_VM_WRITE)             oss << "[VM_WRITE] ";
        if (access & PROCESS_VM_OPERATION)         oss << "[VM_OPERATION] ";
        if (access & PROCESS_CREATE_THREAD)        oss << "[CREATE_THREAD] ";
        if (access & PROCESS_DUP_HANDLE)           oss << "[DUP_HANDLE] ";
        if (access & PROCESS_QUERY_LIMITED_INFORMATION) oss << "[QUERY_LIMITED_INFO] ";

        std::string res = oss.str();
        return res.empty() ? "STANDARD_ACCESS" : res;
    }

    static std::string AnalyzeAccessMask(DWORD dwDesiredAccess) {
        std::string details = "";
        if (dwDesiredAccess & PROCESS_ALL_ACCESS) details += "[PROCESS_ALL_ACCESS] ";
        if (dwDesiredAccess & PROCESS_VM_WRITE) details += "[PROCESS_VM_WRITE (Memory Modification)] ";
        if (dwDesiredAccess & PROCESS_VM_READ) details += "[PROCESS_VM_READ (Memory Read / Dumping)] ";
        if (dwDesiredAccess & PROCESS_CREATE_THREAD) details += "[PROCESS_CREATE_THREAD (Remote Thread Injection)] ";
        if (details.empty()) details = "[Standard / Restricted Access]";
        return details;
    }

    static HANDLE WINAPI Hooked_OpenProcess(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        DWORD dwProcessId
    ) {
        std::string accessRightsDesc = ParseProcessAccessRights(dwDesiredAccess);
        std::string accessFlagsDesc = AnalyzeAccessMask(dwDesiredAccess);

        std::ostringstream ss;
        ss << "[HANDLE-AUDIT] Process Handle Acquisition Intercepted!\r\n";
        ss << "  -> Target PID: " << dwProcessId << "\r\n";
        ss << "  -> Requested Access Rights: 0x" << std::hex << dwDesiredAccess << std::dec
           << " (" << accessRightsDesc << ")" << " (" << accessFlagsDesc << ")\r\n";

        if ((dwDesiredAccess & PROCESS_VM_WRITE) || (dwDesiredAccess & PROCESS_CREATE_THREAD)) {
            g_NtAlpcCreatePortLogs += "[SECURITY-ALERT] High-privilege cross-process handle request detected!\n";
        }

        ThreatCorrelator::GetInstance().IngestEvent("HandleAudit", ss.str(), ThreatCorrelator::ThreatLevel::High);

        return Original_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }

    static void InitializeHandleAuditHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_OpenProcess = (pfnOpenProcess)GetProcAddress(hKernel32, "OpenProcess");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_OpenProcess) {
            DetourAttach(&(PVOID&)Original_OpenProcess, Hooked_OpenProcess);
        }

        DetourTransactionCommit();
    }

    static void UninitializeHandleAuditHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_OpenProcess) {
            DetourDetach(&(PVOID&)Original_OpenProcess, Hooked_OpenProcess);
        }
        DetourTransactionCommit();
    }
};

#endif
