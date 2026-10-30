// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ALPCBACK_H
#define ALPCBACK_H

#include "common.h"
#include "detours.h"
#include "alpc.h"
#include <mutex>

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CALPCBACK {
public:
    typedef NTSTATUS(NTAPI *pfnNtCreateNamedPipeFile)(
        PHANDLE NamedPipeFileHandle,
        ULONG DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        ULONG TypeMessage,
        ULONG ReadmodeMessage,
        ULONG Nonblocking,
        ULONG MaxInstances,
        ULONG InboundQuota,
        ULONG OutboundQuota,
        PLARGE_INTEGER DefaultTimeout
    );

    static pfnNtCreateNamedPipeFile Original_NtCreateNamedPipeFile;
    static std::mutex g_PipeMutex;

    static NTSTATUS NTAPI Hooked_NtCreateNamedPipeFile(
        PHANDLE NamedPipeFileHandle,
        ULONG DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        ULONG TypeMessage,
        ULONG ReadmodeMessage,
        ULONG Nonblocking,
        ULONG MaxInstances,
        ULONG InboundQuota,
        ULONG OutboundQuota,
        PLARGE_INTEGER DefaultTimeout
    ) {
        std::wstring pipeName = L"(Unknown Pipe)";
        if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
            pipeName = std::wstring(
                ObjectAttributes->ObjectName->Buffer, 
                ObjectAttributes->ObjectName->Length / sizeof(WCHAR)
            );
        }

        std::ostringstream ss;
        {
            std::lock_guard<std::mutex> lock(g_PipeMutex);
            ss << "[PIPE-CREATE] Named Pipe Created\r\n";

            std::string strPipeName = WStringToString(std::wstring(pipeName.begin(), pipeName.end()));
            ss << "  -> Pipe Name/Path: " << strPipeName << "\r\n";
            ss << "  -> DesiredAccess: 0x" << std::hex << DesiredAccess << std::dec << "\r\n";
        }

        g_NtAlpcCreatePortLogs += ss.str();

        return Original_NtCreateNamedPipeFile(
            NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            ShareAccess, CreateDisposition, CreateOptions, TypeMessage,
            ReadmodeMessage, Nonblocking, MaxInstances, InboundQuota,
            OutboundQuota, DefaultTimeout
        );
    }

    static void InitializeNamedPipeHooks() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        Original_NtCreateNamedPipeFile = (pfnNtCreateNamedPipeFile)GetProcAddress(hNtdll, "NtCreateNamedPipeFile");

        if (Original_NtCreateNamedPipeFile) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());

            DetourAttach(&(PVOID&)Original_NtCreateNamedPipeFile, Hooked_NtCreateNamedPipeFile);
        
            DetourTransactionCommit();
        }
    }

    static void UninitializeNamedPipeHooks() {
        if (Original_NtCreateNamedPipeFile) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)Original_NtCreateNamedPipeFile, Hooked_NtCreateNamedPipeFile);
            DetourTransactionCommit();
        }
    }
};

#endif