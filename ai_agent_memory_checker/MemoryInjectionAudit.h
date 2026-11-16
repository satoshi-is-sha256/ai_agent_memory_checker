// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MEMORYINJECTIONAUDIT_H
#define MEMORYINJECTIONAUDIT_H

#include "common.h"
#include "alpc.h"
#include "detours.h"

typedef LPVOID(WINAPI *PFN_VIRTUALALLOCEX)(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
    );
typedef BOOL(WINAPI *PFN_VIRTUALPROTECTEX)(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect
    );
typedef HANDLE(WINAPI *PFN_CREATEREMOTETHREAD)(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId
    );

//
// block type
//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CMemoryInjectionAudit {
public:
    static PFN_VIRTUALALLOCEX Real_VirtualAllocEx;
    static PFN_VIRTUALPROTECTEX Real_VirtualProtectEx;
    static PFN_CREATEREMOTETHREAD Real_CreateRemoteThread;

    static bool IsDangerousMemoryOperation(HANDLE hProcess, DWORD flProtect) {
        if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
            if ((flProtect & PAGE_EXECUTE_READWRITE) != 0 ||
                (flProtect & PAGE_EXECUTE_WRITECOPY) != 0) {
                return true;
            }
        }
        return false;
    }

    static LPVOID WINAPI Hooked_VirtualAllocEx(
        HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
    ) {
        if (IsDangerousMemoryOperation(hProcess, flProtect)) {
            g_NtAlpcCreatePortLogs += "[!] BLOCKED: Suspicious VirtualAllocEx RWX injection attempt in remote process!\n";
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
        return Real_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    }

    static BOOL WINAPI Hooked_VirtualProtectEx(
        HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect
    ) {
        if (IsDangerousMemoryOperation(hProcess, flNewProtect)) {
            g_NtAlpcCreatePortLogs += "[!] BLOCKED: Suspicious VirtualProtectEx RWX conversion attempt in remote process!\n";
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        return Real_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }

    static HANDLE WINAPI Hooked_CreateRemoteThread(
        HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId
    ) {
        if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
            g_NtAlpcCreatePortLogs += "[!] BLOCKED: Unauthorized CreateRemoteThread injection attempt detected!\n";
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
        return Real_CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }

    static bool InitializeMemoryInjectionAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        Real_VirtualAllocEx = VirtualAllocEx;
        Real_VirtualProtectEx = VirtualProtectEx;
        Real_CreateRemoteThread = CreateRemoteThread;

        DetourAttach(&(PVOID&)Real_VirtualAllocEx, Hooked_VirtualAllocEx);
        DetourAttach(&(PVOID&)Real_VirtualProtectEx, Hooked_VirtualProtectEx);
        DetourAttach(&(PVOID&)Real_CreateRemoteThread, Hooked_CreateRemoteThread);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }

    static bool UninitializeMemoryInjectionAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)Real_VirtualAllocEx, Hooked_VirtualAllocEx);
        DetourDetach(&(PVOID&)Real_VirtualProtectEx, Hooked_VirtualProtectEx);
        DetourDetach(&(PVOID&)Real_CreateRemoteThread, Hooked_CreateRemoteThread);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }
};

#endif
