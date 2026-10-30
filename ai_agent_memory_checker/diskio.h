// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DISKIO_H
#define DISKIO_H

#include "common.h"
#include "alpc.h"
#include "detours.h"

typedef NTSTATUS(NTAPI *pfnNtWriteFile) (
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CDiskIo {
public:
    static pfnNtWriteFile Original_NtWriteFile;

    static NTSTATUS NTAPI Hooked_NtWriteFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    ) {
        if (Buffer && Length > 0 && Length < 4096) {
            std::string data((const char*)Buffer, Length);
            if (data.find("prompt") != std::string::npos || data.find("user") != std::string::npos) {
                std::ostringstream ss;
                ss << "[FILE-IO-LEAK] Potential Payload Written to Disk/Cache\r\n";
                ss << "  -> Write Length: " << Length << " bytes\r\n";
                ss << "  -> Preview: " << data.substr(0, 200) << "\r\n";

                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return Original_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

    static void InitializeFileIoHooks() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        Original_NtWriteFile = (pfnNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
        if (Original_NtWriteFile) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)Original_NtWriteFile, Hooked_NtWriteFile);
            DetourTransactionCommit();
        }
    }

    static void UninitializeFileIoHooks() {
        if (Original_NtWriteFile) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)Original_NtWriteFile, Hooked_NtWriteFile);
            DetourTransactionCommit();
        }
    }
};

#endif