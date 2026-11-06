// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRIPBOARD_H
#define CRIPBOARD_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"

typedef HANDLE(WINAPI *pfnGetClipboardData)(UINT uFormat);
typedef BOOL(WINAPI *pfnAddClipboardFormatListener)(HWND hwnd);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CCripBoard {
public:
    static pfnGetClipboardData Original_GetClipboardData;

    static HANDLE WINAPI Hooked_GetClipboardData(UINT uFormat) {
        HANDLE hData = Original_GetClipboardData(uFormat);

        if (hData && (uFormat == CF_UNICODETEXT || uFormat == CF_TEXT)) {
            void* pLocked = GlobalLock(hData);
            if (pLocked) {
                std::wstring clipText;
                if (uFormat == CF_UNICODETEXT) {
                    clipText = static_cast<wchar_t*>(pLocked);
                }
                GlobalUnlock(hData);

                if (clipText.length() > 80) {
                    clipText = clipText.substr(0, 80) + L"...";
                }

                std::string utf8Text = WStringToString(clipText);

                std::ostringstream ss;
                ss << "[CLIPBOARD-WATCH] Clipboard Read Intercepted!\r\n";
                ss << "  -> Snippet: " << utf8Text << "\r\n";

                TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::SharedMemory, ss.str());
                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return hData;
    }

    static void InitializeClipboardHooks() {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (!hUser32) return;

        Original_GetClipboardData = (pfnGetClipboardData)GetProcAddress(hUser32, "GetClipboardData");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_GetClipboardData) {
            DetourAttach(&(PVOID&)Original_GetClipboardData, Hooked_GetClipboardData);
        }

        DetourTransactionCommit();
    }

    static void UninitializeClipboardHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_GetClipboardData) {
            DetourDetach(&(PVOID&)Original_GetClipboardData, Hooked_GetClipboardData);
        }
        DetourTransactionCommit();
    }
};

#endif
