// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROCESSEXECUTIONAUDIT_H
#define PROCESSEXECUTIONAUDIT_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <winternl.h>
#include "detours.h"

#define STATUS_NOT_IMPLEMENTED 0xC0000002

typedef NTSTATUS(WINAPI *PFN_NTCREATEUSERPROCESS)(
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

typedef BOOL(WINAPI* PFN_CREATEPROCESSW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

class CProcessExecutionAudit {
public:
    static PFN_NTCREATEUSERPROCESS Real_NtCreateUserProcess;
    static PFN_CREATEPROCESSW Real_CreateProcessW;

    static bool IsSuspiciousToolExecution(LPCWSTR commandLine) {
        if (commandLine == nullptr) return false;
    
        if (wcsstr(commandLine, L"powershell") != nullptr ||
            wcsstr(commandLine, L"cmd.exe") != nullptr ||
            wcsstr(commandLine, L"mshta") != nullptr ||
            wcsstr(commandLine, L"rundll32") != nullptr ||
            wcsstr(commandLine, L"-enc") != nullptr ||
            wcsstr(commandLine, L"EncodedCommand") != nullptr) {
            return true;
        }
        return false;
    }

    static BOOL WINAPI Hooked_CreateProcessW(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    ) {
        if (lpCommandLine != nullptr) {
            std::ostringstream ss;
            ss << "[Process Audit] CreateProcessW Intercepted Cmd: " << WStringToString(std::wstring(lpCommandLine)) << "\r\n";
            if (IsSuspiciousToolExecution(lpCommandLine)) {
                ss << "[!] WARNING: Suspicious tool execution or shell spawn detected!\r\n";
            }

            ThreatCorrelator::GetInstance().IngestEvent("Process Audit CreateProcessW", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Real_CreateProcessW(
            lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation
        );
    }

    static NTSTATUS WINAPI Hooked_NtCreateUserProcess(
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
        std::ostringstream ss;
        ss << "[Process Audit] NtCreateUserProcess (Low-level Native Hook) Triggered.\r\n";
        ThreatCorrelator::GetInstance().IngestEvent("Process Audit NtCreateUserProcess", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
        g_NtAlpcCreatePortLogs += ss.str();

        if (Real_NtCreateUserProcess == nullptr) {
            return STATUS_NOT_IMPLEMENTED;
        }

        return Real_NtCreateUserProcess(
            ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
            ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags,
            ProcessParameters, CreateInfo, AttributeList
        );
    }

    static bool InitializeProcessExecutionAudit() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll != nullptr) {
            Real_NtCreateUserProcess = (PFN_NTCREATEUSERPROCESS)GetProcAddress(hNtdll, "NtCreateUserProcess");
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Real_NtCreateUserProcess != nullptr) {
            DetourAttach(&(PVOID&)Real_NtCreateUserProcess, Hooked_NtCreateUserProcess);
        }
        DetourAttach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }

    static bool UninitializProcessExecutionAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Real_NtCreateUserProcess != nullptr) {
            DetourDetach(&(PVOID&)Real_NtCreateUserProcess, Hooked_NtCreateUserProcess);
        }
        DetourDetach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }
};

#endif
