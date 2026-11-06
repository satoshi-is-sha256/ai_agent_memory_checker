// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROCESSINJECTIONMONITOR_H
#define PROCESSINJECTIONMONITOR_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"

typedef NTSTATUS(NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID AttributeList
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CProcessInjection {
public:
    static pfnNtCreateThreadEx Original_NtCreateThreadEx;

    static NTSTATUS NTAPI Hooked_NtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE StartRoutine,
        LPVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        LPVOID AttributeList
    ) {
        if (ProcessHandle && ProcessHandle != GetCurrentProcess()) {
            std::ostringstream ss;
            ss << "[INJECTION-ALERT] Remote Thread Creation / Process Injection Intercepted!\r\n";
            ss << "  -> Target Process Handle: " << ProcessHandle << "\r\n";
            ss << "  -> Start Routine Address: " << (void*)StartRoutine << "\r\n";

            TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Alert, ss.str());
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_NtCreateThreadEx(
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle,
            StartRoutine,
            Argument,
            CreateFlags,
            ZeroBits,
            StackSize,
            MaximumStackSize,
            AttributeList
        );
    }

    static void InitializeInjectionHooks() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        Original_NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_NtCreateThreadEx) {
            DetourAttach(&(PVOID&)Original_NtCreateThreadEx, Hooked_NtCreateThreadEx);
        }

        DetourTransactionCommit();
    }

    static void UninitializeInjectionHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_NtCreateThreadEx) {
            DetourDetach(&(PVOID&)Original_NtCreateThreadEx, Hooked_NtCreateThreadEx);
        }
        DetourTransactionCommit();
    }

};

#endif
