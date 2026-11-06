// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SSLKEYLOGMONITOR_H
#define SSLKEYLOGMONITOR_H

#include "common.h"

class CSslKeyLogMonitor {
public:
    static bool InitializeSslKeyLogging() {
        WCHAR tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath) == 0) return false;

        std::wstring keyLogFilePath = std::wstring(tempPath) + L"ai_agent_ssl_keys.log";

        if (SetEnvironmentVariableW(L"SSLKEYLOGFILE", keyLogFilePath.c_str())) {
            OutputDebugStringW((L"[SSL-KEYLOG] SSLKEYLOGFILE set to: " + keyLogFilePath + L"\n").c_str());
            return true;
        }

        return false;
    }

    static std::wstring GetKeyLogFilePath() {
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        return std::wstring(tempPath) + L"ai_agent_ssl_keys.log";
    }
};

#endif