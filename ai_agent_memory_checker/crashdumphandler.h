// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRASHDUMPHANDLER_H
#define CRASHDUMPHANDLER_H

#include "common.h"
#include <dbghelp.h>
#include <shlobj.h>

#pragma comment(lib, "dbghelp.lib")

class CrashDumpHandler {
public:
    static BOOL WINAPI CreateMinidumpOnException(EXCEPTION_POINTERS *pExceptionPtrs) {
        WCHAR tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath) == 0)
            return FALSE;

        std::wstring dumpFilePath = std::wstring(tempPath) + L"ai_agent_crash_dump.dmp";

        HANDLE hFile = CreateFileW(
            dumpFilePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_WRITE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE)
            return FALSE;

        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = pExceptionPtrs;
        mdei.ClientPointers = FALSE;

        BOOL success = MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hFile,
            MiniDumpWithFullMemory,
            pExceptionPtrs ? &mdei : nullptr,
            nullptr,
            nullptr
        );

        CloseHandle(hFile);

        if (success) {
            OutputDebugStringW((L"[CRASH-DUMP] Minidump successfully generated at: " + dumpFilePath + L"\n").c_str());
        }

        return success;
    }

    static void InitializeCrashHandler() {
        SetUnhandledExceptionFilter([](EXCEPTION_POINTERS *pExceptionPtrs) -> LONG {
            CreateMinidumpOnException(pExceptionPtrs);
            return EXCEPTION_EXECUTE_HANDLER;
            });
    }
};

#endif