// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COMMON_H
#define COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <commctrl.h>
#include <richedit.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <chrono>
#include <iostream>
#include <sstream>
#pragma comment(lib, "comctl32.lib")

#define IDC_PID_INPUT          101
#define IDC_BTN_INJECT         102
#define IDC_LOG_EDIT           103
#define IDC_PROCESS_NAME_INPUT 104
#define IDC_BTN_INJECT_ALL     105
#define WM_ADD_LOG_ENTRY       (WM_USER + 100)
#define WM_ADD_LOG_ENTRY_A     (WM_USER + 101)

using pfnNtQuerySystemInformation = NTSTATUS(NTAPI *)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
using pfnNtQueryObject = NTSTATUS(NTAPI *)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
using pfnNtQueryInformationProcess = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
constexpr DWORD STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

#ifndef ObjectNameInformation
#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)
#endif

#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

inline static std::string GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    struct tm buf;
    localtime_s(&buf, &in_time_t);
    ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

inline std::string WStringToString(const std::wstring &wstr) {
    if (wstr.empty()) return std::string();

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], sizeNeeded, nullptr, nullptr);
    return strTo;
}

inline std::wstring StringToWString(const std::string &str) {
    if (str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    if (sizeNeeded <= 0) return std::wstring();

    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], sizeNeeded);
    return wstr;
}

inline std::string ToHexString(const unsigned char *buf, size_t size) {
    std::ostringstream ss;
    for (size_t i = 0; i < size; ++i) {
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(buf[i]) << " ";
    }

    return ss.str();
}

inline DWORD GetProcessIdByName(const std::wstring &processName) {
    DWORD targetPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                targetPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return targetPid;
}

inline std::vector<DWORD> GetPidsByProcessName(const std::wstring &processName) {
    std::vector<DWORD> pids;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pids;
}

/////// dll common below

#define GUARDIAN_PIPE_NAME L"\\\\.\\pipe\\AIAgentMemoryCheckerPipe"

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

enum class AlertType {
    MemoryRead,
    ProcessOpen,
    CommonMapView,
    DuplicateObject
};

struct GuardianAlertEvent {
    AlertType type;
    DWORD sourcePid;
    DWORD targetPid;
    ULONG_PTR baseAddress;
    SIZE_T bufferSize;
    DWORD desiredAccess;
    BYTE buf[512];

    GuardianAlertEvent() {
        type = AlertType::MemoryRead;
        sourcePid = 0;
        targetPid = 0;
        baseAddress = 0;
        bufferSize = 0;
        desiredAccess = 0;
        memset(buf, 0, sizeof(buf));
    }
};

#endif