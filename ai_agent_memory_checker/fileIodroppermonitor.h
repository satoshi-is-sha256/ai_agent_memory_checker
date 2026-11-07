// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FILEIODROPPERMONITOR_H
#define FILEIODROPPERMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef HANDLE(WINAPI *pfnCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CFileIoDropperMonitor {
private:
    static std::string ParseCreationDisposition(DWORD disposition) {
        switch (disposition) {
        case CREATE_NEW:        return "CREATE_NEW";
        case CREATE_ALWAYS:     return "CREATE_ALWAYS";
        case OPEN_EXISTING:     return "OPEN_EXISTING";
        case OPEN_ALWAYS:       return "OPEN_ALWAYS";
        case TRUNCATE_EXISTING: return "TRUNCATE_EXISTING";
        default:                return "UNKNOWN";
        }
    }

public:

    static pfnCreateFileW Original_CreateFileW;

    static HANDLE WINAPI Hooked_CreateFileW(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    ) {
        if (lpFileName) {
            std::wstring fileName(lpFileName);
            std::string dispStr = ParseCreationDisposition(dwCreationDisposition);

            if ((dwDesiredAccess & GENERIC_WRITE) || (dwCreationDisposition == CREATE_ALWAYS) || (dwCreationDisposition == CREATE_NEW)) {
                std::ostringstream ss;
                ss << "[FILE-IO-ALERT] File Creation / Write Intercepted!\r\n";
                ss << "  -> Target Path: " << WStringToString(fileName) << "\r\n";
                ss << "  -> Disposition: " << dispStr << "\r\n";

                ThreatCorrelator::GetInstance().IngestEvent("FileDropper", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return Original_CreateFileW(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }

    static void InitializeFileIoHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_CreateFileW = (pfnCreateFileW)GetProcAddress(hKernel32, "CreateFileW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CreateFileW) {
            DetourAttach(&(PVOID&)Original_CreateFileW, Hooked_CreateFileW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeFileIoHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_CreateFileW) {
            DetourDetach(&(PVOID&)Original_CreateFileW, Hooked_CreateFileW);
        }
        DetourTransactionCommit();
    }
};

#endif
