// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EVTCLEARLOG_H
#define EVTCLEARLOG_H

#include <WinEvt.h>
#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef BOOL (WINAPI *pfnEvtClearLog)(
    EVT_HANDLE Session,
    LPCWSTR ChannelPath,
    LPCWSTR TargetLogFilePath,
    LPCWSTR Query,
    DWORD Flags
);

typedef BOOL (WINAPI *pfnClearEventLogW)(
    HANDLE hEventLog,
    LPCWSTR lpBackupFileName
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CEventLogAudit {
public:
    static pfnEvtClearLog Original_EvtClearLog;
    static pfnClearEventLogW Original_ClearEventLogW;

    static BOOL WINAPI Hooked_EvtClearLog(
        EVT_HANDLE Session,
        LPCWSTR ChannelPath,
        LPCWSTR TargetLogFilePath,
        LPCWSTR Query,
        DWORD Flags
    ) {
        std::wstring channel = ChannelPath ? ChannelPath : L"UnknownChannel";
        std::string utf8Channel = WStringToString(channel);

        std::ostringstream ss;
        ss << "[EVENTLOG-AUDIT] Critical: Event Log Clearing Attempted (EvtClearLog)!\r\n";
        ss << "  -> Target Channel / Log: " << utf8Channel << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("EventLogCleared", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_EvtClearLog(Session, ChannelPath, TargetLogFilePath, Query, Flags);
    }

    static BOOL WINAPI Hooked_ClearEventLogW(
        HANDLE hEventLog,
        LPCWSTR lpBackupFileName
    ) {
        std::ostringstream ss;
        ss << "[EVENTLOG-AUDIT] Critical: Legacy Event Log Clearing Attempted (ClearEventLogW)!\r\n";
        if (lpBackupFileName) {
            std::wstring backup(lpBackupFileName);
            ss << "  -> Backup File Path: " << WStringToString(backup) << "\r\n";
        }

        ThreatCorrelator::GetInstance().IngestEvent("LegacyEventLogCleared", ss.str(), ThreatCorrelator::ThreatLevel::Critical);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_ClearEventLogW(hEventLog, lpBackupFileName);
    }

    static void InitializeEventLogAuditHooks() {
        HMODULE hWevtapi = GetModuleHandleW(L"wevtapi.dll");
        if (!hWevtapi) {
            hWevtapi = LoadLibraryW(L"wevtapi.dll");
        }
        if (hWevtapi) {
            Original_EvtClearLog = (pfnEvtClearLog)GetProcAddress(hWevtapi, "EvtClearLog");
        }

        HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
        if (!hAdvapi32) {
            hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        }
        if (hAdvapi32) {
            Original_ClearEventLogW = (pfnClearEventLogW)GetProcAddress(hAdvapi32, "ClearEventLogW");
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_EvtClearLog) {
            DetourAttach(&(PVOID&)Original_EvtClearLog, Hooked_EvtClearLog);
        }
        if (Original_ClearEventLogW) {
            DetourAttach(&(PVOID&)Original_ClearEventLogW, Hooked_ClearEventLogW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeEventLogAuditHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_EvtClearLog) {
            DetourDetach(&(PVOID&)Original_EvtClearLog, Hooked_EvtClearLog);
        }
        if (Original_ClearEventLogW) {
            DetourDetach(&(PVOID&)Original_ClearEventLogW, Hooked_ClearEventLogW);
        }

        DetourTransactionCommit();
    }
};

#endif
