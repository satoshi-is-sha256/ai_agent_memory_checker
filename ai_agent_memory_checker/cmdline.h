// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CMDLINE_H
#define CMDLINE_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"

typedef LPWSTR(WINAPI *pfnGetCommandLineW)();

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CCmdLine {
private:
    static bool ContainsSuspiciousFlag(const std::wstring &cmdLine) {
        const wchar_t *flags[] = {
            L"--remote-debugging-port",
            L"--disable-background-timer-throttling",
            L"--enable-automation",
            L"--no-sandbox",
            L"--headless"
        };

        for (const auto *flag : flags) {
            if (cmdLine.find(flag) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

public:
    static pfnGetCommandLineW Original_GetCommandLineW;

    static LPWSTR WINAPI Hooked_GetCommandLineW() {
        LPWSTR cmdLine = Original_GetCommandLineW();

        if (cmdLine) {
            std::wstring cmdStr(cmdLine);
            if (ContainsSuspiciousFlag(cmdStr)) {
                std::string utf8Cmd = WStringToString(cmdStr);

                std::ostringstream ss;
                ss << "[CMD-FLAG-ALERT] Suspicious Startup Flags Intercepted!\r\n";
                ss << "  -> Full Command Line: " << utf8Cmd << "\r\n";

                TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Alert, ss.str());
                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return cmdLine;
    }

    static void InitializeCommandLineHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_GetCommandLineW = (pfnGetCommandLineW)GetProcAddress(hKernel32, "GetCommandLineW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_GetCommandLineW) {
            DetourAttach(&(PVOID&)Original_GetCommandLineW, Hooked_GetCommandLineW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeCommandLineHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_GetCommandLineW) {
            DetourDetach(&(PVOID&)Original_GetCommandLineW, Hooked_GetCommandLineW);
        }

        DetourTransactionCommit();
    }
};

#endif
