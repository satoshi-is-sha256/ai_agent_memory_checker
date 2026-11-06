// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ANTIDEBUGMONITOR_H
#define ANTIDEBUGMONITOR_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"

typedef BOOL (WINAPI *pfnIsDebuggerPresent)();
typedef BOOL (WINAPI *pfnCheckRemoteDebuggerPresent)(HANDLE hProcess, PBOOL pbDebuggerPresent);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CAntiDebugMonitor {
public:
    static pfnIsDebuggerPresent Original_IsDebuggerPresent;
    static pfnCheckRemoteDebuggerPresent Original_CheckRemoteDebuggerPresent;

    static BOOL WINAPI Hooked_IsDebuggerPresent() {
        BOOL isDebugged = Original_IsDebuggerPresent();

        std::ostringstream ss;
        ss << "[ANTI-DEBUG-WATCH] Debugger Presence Checked by Agent!\r\n";
        ss << "  -> Result Returned to Agent: " << (isDebugged ? "TRUE (Debugger Detected)" : "FALSE (Clean Environment)") << "\r\n";

        TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Alert, ss.str());
        g_NtAlpcCreatePortLogs += ss.str();

        return isDebugged;
    }

    static BOOL WINAPI Hooked_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
        BOOL status = Original_CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);

        std::ostringstream ss;
        ss << "[ANTI-DEBUG-WATCH] Remote Debugger Check Intercepted!\r\n";
        if (pbDebuggerPresent) {
            ss << "  -> Target Process Debug Status: " << (*pbDebuggerPresent ? "TRUE" : "FALSE") << "\r\n";
        }

        TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Alert, ss.str());
        g_NtAlpcCreatePortLogs += ss.str();

        return status;
    }

    static void InitializeAntiDebugHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_IsDebuggerPresent = (pfnIsDebuggerPresent)GetProcAddress(hKernel32, "IsDebuggerPresent");
        Original_CheckRemoteDebuggerPresent = (pfnCheckRemoteDebuggerPresent)GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_IsDebuggerPresent) {
            DetourAttach(&(PVOID&)Original_IsDebuggerPresent, Hooked_IsDebuggerPresent);
        }
        if (Original_CheckRemoteDebuggerPresent) {
            DetourAttach(&(PVOID&)Original_CheckRemoteDebuggerPresent, Hooked_CheckRemoteDebuggerPresent);
        }

        DetourTransactionCommit();
    }

    static void UninitializeAntiDebugHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_IsDebuggerPresent) {
            DetourDetach(&(PVOID&)Original_IsDebuggerPresent, Hooked_IsDebuggerPresent);
        }
        if (Original_CheckRemoteDebuggerPresent) {
            DetourDetach(&(PVOID&)Original_CheckRemoteDebuggerPresent, Hooked_CheckRemoteDebuggerPresent);
        }
        DetourTransactionCommit();
    }
};

#endif
