// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef LSASSPROTECTIONAUDIT_H
#define LSASSPROTECTIONAUDIT_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <dbghelp.h>
#include "detours.h"

typedef BOOL (WINAPI *pfnMiniDumpWriteDump)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CLsassProtectionAudit {
public:
    static pfnMiniDumpWriteDump Original_MiniDumpWriteDump;
    static DWORD g_TargetLsassPid;

    static bool IsTargetProcessLsass(HANDLE hProcess) {
        (void)hProcess;
        return false;
    }

    static BOOL WINAPI Hooked_MiniDumpWriteDump(
        HANDLE hProcess,
        DWORD ProcessId,
        HANDLE hFile,
        MINIDUMP_TYPE DumpType,
        PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
        PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
        PMINIDUMP_CALLBACK_INFORMATION CallbackParam
    ) {
        std::ostringstream ss;
        ss << "[LSASS-DUMP-AUDIT] Critical: Memory Dump Creation Intercepted (MiniDumpWriteDump)!\r\n";
        ss << "  -> Target Process ID (PID): " << ProcessId << "\r\n";
        ss << "  -> Dump Type Flags: 0x" << std::hex << (DWORD)DumpType << std::dec << "\r\n";

        if (ProcessId == g_TargetLsassPid || IsTargetProcessLsass(hProcess)) {
            ThreatCorrelator::GetInstance().IngestEvent("CredentialDumpingAttempt", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
            g_NtAlpcCreatePortLogs += ss.str();
            // denied access (return FALSE)
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }

        return Original_MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);
    }

    static void InitializeLsassProtectionHooks() {
        HMODULE hDbgHelp = GetModuleHandleW(L"dbghelp.dll");
        if (!hDbgHelp) {
            hDbgHelp = LoadLibraryW(L"dbghelp.dll");
        }
        if (!hDbgHelp) return;

        Original_MiniDumpWriteDump = (pfnMiniDumpWriteDump)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
        if (!Original_MiniDumpWriteDump) return;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)Original_MiniDumpWriteDump, Hooked_MiniDumpWriteDump);

        DetourTransactionCommit();
    }

    static void UninitializeLsassProtectionHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_MiniDumpWriteDump) {
            DetourDetach(&(PVOID&)Original_MiniDumpWriteDump, Hooked_MiniDumpWriteDump);
        }

        DetourTransactionCommit();
    }
};

#endif
