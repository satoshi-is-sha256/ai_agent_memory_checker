// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FILEDROP_H
#define FILEDROP_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"

typedef HANDLE(WINAPI* pfnCreateFileW)(
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
class CFileDrop {
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
            std::wstring filePath(lpFileName);
            if ((dwDesiredAccess & GENERIC_WRITE) || (dwCreationDisposition == CREATE_ALWAYS) || (dwCreationDisposition == OPEN_ALWAYS)) {
                if (filePath.find(L"Temp") != std::wstring::npos || filePath.find(L"AppData") != std::wstring::npos) {
                    std::string utf8Path = WStringToString(filePath);

                    std::ostringstream ss;
                    ss << "[FILE-DROP-WATCH] Suspicious File Staging Intercepted!\r\n";
                    ss << "  -> Target Path: " << utf8Path << "\r\n";

                    TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::FileIO, ss.str());
                    g_NtAlpcCreatePortLogs += ss.str();
                }
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

    static void InitializeFileDropHooks() {
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

    static void UninitializeFileDropHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_CreateFileW) {
            DetourDetach(&(PVOID&)Original_CreateFileW, Hooked_CreateFileW);
        }
        DetourTransactionCommit();
    }
};

#endif
