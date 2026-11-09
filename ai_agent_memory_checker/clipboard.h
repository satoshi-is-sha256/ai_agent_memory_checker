// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRIPBOARD_H
#define CRIPBOARD_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef HANDLE(WINAPI *pfnGetClipboardData)(UINT uFormat);
typedef HANDLE(WINAPI *pfnSetClipboardData)(UINT uFormat, HANDLE hMem);
typedef BOOL(WINAPI *pfnAddClipboardFormatListener)(HWND hwnd);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CCripBoard {
public:
    static pfnGetClipboardData Original_GetClipboardData;
    static pfnSetClipboardData Original_SetClipboardData;

    static std::string GetClipboardFormatNameStr(UINT uFormat) {
        switch (uFormat) {
            case CF_TEXT:         return "CF_TEXT (ANSI Text)";
            case CF_UNICODETEXT:  return "CF_UNICODETEXT (Unicode Text)";
            case CF_HDROP:        return "CF_HDROP (File Drop / Drag-Drop)";
            case CF_BITMAP:       return "CF_BITMAP";
            case CF_DIB:          return "CF_DIB";
            default: {
                char formatName[256] = {0};
                if (GetClipboardFormatNameA(uFormat, formatName, sizeof(formatName)) > 0) {
                    return std::string(formatName);
                }
                return "CUSTOM_OR_UNKNOWN_FORMAT (" + std::to_string(uFormat) + ")";
            }
        }
    }

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

    static HANDLE WINAPI Hooked_SetClipboardData(UINT uFormat, HANDLE hMem) {
        std::string formatStr = GetClipboardFormatNameStr(uFormat);

        std::ostringstream ss;
        ss << "[CLIPBOARD] Clipboard Write / Modification Intercepted!\r\n";
        ss << "  -> Target Format: " << formatStr << "\r\n";
        ss << "  -> Memory Handle: 0x" << std::hex << (uintptr_t)hMem << std::dec << "\r\n";

        if (uFormat == CF_UNICODETEXT && hMem != nullptr) {
            wchar_t* pText = (wchar_t*)GlobalLock(hMem);
            if (pText) {
                GlobalUnlock(hMem);
            }
        }

        ThreatCorrelator::GetInstance().IngestEvent("ClipboardWrite", ss.str(), ThreatCorrelator::ThreatLevel::High);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_SetClipboardData(uFormat, hMem);
    }

    static void InitializeClipboardHooks() {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (!hUser32) {
            hUser32 = LoadLibraryW(L"user32.dll");
        }
        if (!hUser32) return;

        Original_GetClipboardData = (pfnGetClipboardData)GetProcAddress(hUser32, "GetClipboardData");
        Original_SetClipboardData = (pfnSetClipboardData)GetProcAddress(hUser32, "SetClipboardData");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_GetClipboardData) {
            DetourAttach(&(PVOID&)Original_GetClipboardData, Hooked_GetClipboardData);
        }
        if (Original_SetClipboardData) {
            DetourAttach(&(PVOID&)Original_SetClipboardData, Hooked_SetClipboardData);
        }

        DetourTransactionCommit();
    }

    static void UninitializeClipboardHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_GetClipboardData) {
            DetourDetach(&(PVOID&)Original_GetClipboardData, Hooked_GetClipboardData);
        }
        if (Original_SetClipboardData) {
            DetourDetach(&(PVOID&)Original_SetClipboardData, Hooked_SetClipboardData);
        }

        DetourTransactionCommit();
    }
};

#endif
