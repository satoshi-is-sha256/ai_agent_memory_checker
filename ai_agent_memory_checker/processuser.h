// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROCESSUSER_H
#define PROCESSUSER_H

#include "common.h"
#include "alpc.h"
#include "detours.h"

typedef NTSTATUS(NTAPI *pfnNtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PVOID ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI *pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InherentAttributes
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CProcessUser {
public:
    static pfnNtCreateUserProcess Original_NtCreateUserProcess;
    static pfnNtCreateProcessEx Original_NtCreateProcessEx;

    static NTSTATUS NTAPI Hooked_NtCreateUserProcess(
        PHANDLE ProcessHandle,
        PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess,
        ACCESS_MASK ThreadDesiredAccess,
        POBJECT_ATTRIBUTES ProcessObjectAttributes,
        POBJECT_ATTRIBUTES ThreadObjectAttributes,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        PVOID ProcessParameters,
        PVOID CreateInfo,
        PVOID AttributeList
    ) {
        DWORD currentPid = GetCurrentProcessId();

        std::ostringstream ss;
        ss << "[PROCESS-SPROUT] NtCreateUserProcess intercepted from PID: " << currentPid << "\r\n";
        ss << "  -> Spawning child process or sub-agent background task.\r\n";

        g_NtAlpcCreatePortLogs += ss.str();

        return Original_NtCreateUserProcess(
            ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
            ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags,
            ThreadFlags, ProcessParameters, CreateInfo, AttributeList
        );
    }

    static NTSTATUS NTAPI Hooked_NtCreateProcessEx(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ParentProcess,
        ULONG Flags,
        HANDLE SectionHandle,
        HANDLE DebugPort,
        HANDLE ExceptionPort,
        BOOLEAN InherentAttributes
    ) {
        DWORD currentPid = GetCurrentProcessId();

        std::ostringstream ss;
        ss << "[PROCESS-SPROUT] NtCreateProcessEx intercepted from PID: " << currentPid << "\r\n";

        g_NtAlpcCreatePortLogs += ss.str();

        return Original_NtCreateProcessEx(
            ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess,
            Flags, SectionHandle, DebugPort, ExceptionPort, InherentAttributes
        );
    }

    static void InitializeProcessCreationHooks() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        Original_NtCreateUserProcess = (pfnNtCreateUserProcess)GetProcAddress(hNtdll, "NtCreateUserProcess");
        Original_NtCreateProcessEx = (pfnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_NtCreateUserProcess) {
            DetourAttach(&(PVOID&)Original_NtCreateUserProcess, Hooked_NtCreateUserProcess);
        }
        if (Original_NtCreateProcessEx) {
            DetourAttach(&(PVOID&)Original_NtCreateProcessEx, Hooked_NtCreateProcessEx);
        }

        DetourTransactionCommit();
    }

    static void UninitializeProcessCreationHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_NtCreateUserProcess) {
            DetourDetach(&(PVOID&)Original_NtCreateUserProcess, Hooked_NtCreateUserProcess);
        }
        if (Original_NtCreateProcessEx) {
            DetourDetach(&(PVOID&)Original_NtCreateProcessEx, Hooked_NtCreateProcessEx);
        }
        DetourTransactionCommit();
    }

};

#endif