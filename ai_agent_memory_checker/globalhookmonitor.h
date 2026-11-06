// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALHOOKMONITOR_H
#define GLOBALHOOKMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef HHOOK(WINAPIV *pfnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CGlobalHookMonitor {
public:
    static pfnSetWindowsHookExW Original_SetWindowsHookExW;

    static std::string GetHookTypeName(int idHook) {
        switch (idHook) {
            case WH_JOURNALPLAYBACK: return "WH_JOURNALPLAYBACK";
            case WH_JOURNALRECORD:   return "WH_JOURNALRECORD";
            case WH_KEYBOARD:        return "WH_KEYBOARD";
            case WH_GETMESSAGE:      return "WH_GETMESSAGE";
            case WH_CALLWNDPROC:     return "WH_CALLWNDPROC";
            case WH_CBT:             return "WH_CBT";
            case WH_SYSMSGFILTER:    return "WH_SYSMSGFILTER";
            case WH_MOUSE:           return "WH_MOUSE";
            //case WH_HARDWARE:        return "WH_HARDWARE";
            case WH_DEBUG:           return "WH_DEBUG";
            case WH_SHELL:           return "WH_SHELL";
            case WH_FOREGROUNDIDLE:  return "WH_FOREGROUNDIDLE";
            case WH_CALLWNDPROCRET:  return "WH_CALLWNDPROCRET";
            case WH_KEYBOARD_LL:     return "WH_KEYBOARD_LL (Low-Level Keyboard Hook)";
            case WH_MOUSE_LL:        return "WH_MOUSE_LL (Low-Level Mouse Hook)";
            default:                 return "UNKNOWN_HOOK_TYPE";
        }
    }

    static HHOOK WINAPIV Hooked_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
        std::string hookName = GetHookTypeName(idHook);

        std::ostringstream ss;
        ss << "[GLOBAL-HOOK-ALERT] Global Windows Hook Installation Intercepted!\r\n";
        ss << "  -> Hook Type: " << hookName << " (ID: " << idHook << ")\r\n";
        ss << "  -> Target Thread ID: " << dwThreadId << " (0 means Global System-wide)\r\n";

        if (idHook == WH_KEYBOARD_LL || idHook == WH_MOUSE_LL || dwThreadId == 0) {
            // OutputDebugStringW(L"[SECURITY] High-risk global input sniffing attempt detected!\n");
        }

        ThreatCorrelator::GetInstance().IngestEvent("GlobalHook", ss.str(), ThreatCorrelator::ThreatLevel::High);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
    }

    static void InitializeGlobalHookHooks() {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (!hUser32) return;

        Original_SetWindowsHookExW = (pfnSetWindowsHookExW)GetProcAddress(hUser32, "SetWindowsHookExW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_SetWindowsHookExW) {
            DetourAttach(&(PVOID&)Original_SetWindowsHookExW, Hooked_SetWindowsHookExW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeGlobalHookHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_SetWindowsHookExW) {
            DetourDetach(&(PVOID&)Original_SetWindowsHookExW, Hooked_SetWindowsHookExW);
        }
        DetourTransactionCommit();
    }
};

#endif