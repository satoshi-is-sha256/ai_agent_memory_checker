// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "common.h"
#include <iomanip>
#include <thread>
#include <set>
#include <algorithm>
#include "debugger.h"
#include "checkopenhandles.h"
#include "memorydetector.h"
#include "allsystemhandlesex.h"
#include "tcp.h"
#include "commemory.h"
#include "scanincoming.h"
#include "alpc.h"
#include "realtimechecking.h"

HWND g_hWnd = nullptr;
HWND g_hEditProcessName = nullptr;
bool g_thread = false;

static std::string RunDebuggerForensics(DWORD targetProcessId) {
    std::ostringstream stream;
    stream << "[*] Starting Debugger Forensics for PID: " << targetProcessId << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetProcessId);
    if (!hProcess) {
        stream << "[-] Failed to open target process. Error: " << GetLastError() << std::endl;
        return stream.str();
    }

    bool standardDbg = CheckStandardDebugger(hProcess);
    bool portDbg = CheckDebugPort(hProcess);
    bool objectDbg = CheckDebugObject(hProcess);

    stream << "----------------------------------------" << std::endl;
    stream << " [Check 1] Standard Remote Debugger : " << (standardDbg ? "[DETECTED]" : "Clean") << std::endl;
    stream << " [Check 2] Native Debug Port (7)    : " << (portDbg ? "[DETECTED]" : "Clean") << std::endl;
    stream << " [Check 3] Debug Object Handle (30) : " << (objectDbg ? "[DETECTED]" : "Clean") << std::endl;
    stream << "----------------------------------------" << std::endl;

    if (standardDbg || portDbg || objectDbg)
        std::cout << "[!] WARNING: External debugging / memory inspection mechanism detected!" << std::endl;
    else
        std::cout << "[+] No active debugger hooks found via these vectors." << std::endl;

    CloseHandle(hProcess);
    return stream.str();
}

static std::string GetProcessFullPath(DWORD pid) {
    std::string path = "Unknown";
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        WCHAR buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, buffer, &size)) {
            path = WStringToString(std::wstring(buffer));
        }
        CloseHandle(hProc);
    }
    return path;
}

static std::string GetProcessNameFromPID(DWORD processId) {
    if (processId == 0) return "System Idle Process";
    if (processId == 4) return "System";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return "Unknown Process (Access Denied)";
    }

    WCHAR imagePath[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    std::string processName = "Unknown";

    if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &size)) {
        std::wstring fullPath(imagePath);
        size_t lastSlash = fullPath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            std::wstring fileName = fullPath.substr(lastSlash + 1);
            processName = WStringToString(fileName);
        }
    }

    CloseHandle(hProcess);
    return processName;
}

static std::string GetProcessNameFromPID2(DWORD pid) {
    if (pid == 0) return "System / Idle";

    std::wstring procName = L"Unknown";
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    procName = pe.szExeFile;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    return WStringToString(procName);
}

struct HandleAccessRecord {
    DWORD sourcePid;
    DWORD targetPid;
    DWORD accessRights;

    HandleAccessRecord() {
        sourcePid = 0;
        targetPid = 0;
        accessRights = 0;
    }

    bool operator<(const HandleAccessRecord &other) const {
        if (sourcePid != other.sourcePid) return sourcePid < other.sourcePid;
        if (targetPid != other.targetPid) return targetPid < other.targetPid;
        return accessRights < other.accessRights;
    }
};

static std::string ProcessScanResults(const std::vector<HandleAccessRecord> &currentScan) {
    static std::set<HandleAccessRecord> g_previousHandles;

    std::set<HandleAccessRecord> currentHandles(currentScan.begin(), currentScan.end());
    std::set<HandleAccessRecord> newlyAdded;

    std::set_difference(
        currentHandles.begin(), currentHandles.end(),
        g_previousHandles.begin(), g_previousHandles.end(),
        std::inserter(newlyAdded, newlyAdded.end())
    );

    std::stringstream ss;
    for (const auto &record : newlyAdded) {
        std::string timestamp = GetCurrentTimestamp();
        std::string sourceName = GetProcessNameFromPID2(record.sourcePid);
        std::string targetName = GetProcessNameFromPID2(record.targetPid);

        ss << "[" << timestamp << "] [!] [NEW ACCESS TRIGGERED]" << std::endl;
        ss << "    -> Source: PID " << record.sourcePid << " (" << sourceName << ")" << std::endl;
        ss << "    -> Target: PID " << record.targetPid << " (" << targetName << ")" << std::endl;
        ss << "    -> Rights: 0x" << std::hex << record.accessRights << std::dec << std::endl;
        ss << "--------------------------------------------------" << std::endl;
    }

    g_previousHandles = currentHandles;
    return ss.str();
}

static std::string MemoryDetector(HWND hWnd, const std::vector<HandleAccessRecord> &currentScan) {
    static std::set<HandleAccessRecord> g_previousHandles;
    static bool g_isFirstScan = true;

    std::ostringstream ss;
    ss << "[*] Starting MemoryDetector." << std::endl;

    std::set<HandleAccessRecord> currentHandles(currentScan.begin(), currentScan.end());
    if (g_isFirstScan) {
        g_previousHandles = currentHandles;
        g_isFirstScan = false;
        return ss.str();
    }

    std::set<HandleAccessRecord> newlyAdded;

    std::set_difference(
        currentHandles.begin(), currentHandles.end(),
        g_previousHandles.begin(), g_previousHandles.end(),
        std::inserter(newlyAdded, newlyAdded.end())
    );

    DWORD userSpecifiedPid = GetDlgItemInt(hWnd, IDC_PID_INPUT, nullptr, FALSE);
    char process[MAX_PATH];
    GetDlgItemTextA(hWnd, IDC_PROCESS_NAME_INPUT, process, MAX_PATH);
    std::string userSpecifiedName = process;

    for (const auto &record: newlyAdded) {
        std::string sourceName = GetProcessNameFromPID2(record.sourcePid);
        std::string targetName = GetProcessNameFromPID2(record.targetPid);
        std::string sourcePath = GetProcessFullPath(record.sourcePid);

        if (!IsTargetWatched(record.targetPid, userSpecifiedPid, targetName, userSpecifiedName)) {
            continue;
        }

        bool canRead = (record.accessRights & PROCESS_VM_READ) != 0;
        bool canWrite = (record.accessRights & PROCESS_VM_WRITE) != 0;
        bool canCreateThread = (record.accessRights & PROCESS_CREATE_THREAD) != 0;

        if (canRead || canWrite || canCreateThread) {
            ss << "[!] [TARGET MEMORY ACCESS DETECTED]" << std::endl;
            ss << "    -> Target: PID " << record.targetPid << " (" << targetName << ")" << std::endl;
            ss << "    -> Sleuth: PID " << record.sourcePid << " (" << sourceName << ")" << std::endl;
            ss << "    -> Path:   " << sourcePath << std::endl;
            ss << "    -> Rights: 0x" << std::hex << record.accessRights << std::dec;
        
            if (canRead) ss << " [VM_READ (Memory Sucking?)]";
            if (canWrite) ss << " [VM_WRITE]";
            ss << std::endl << "--------------------------------------------------" << std::endl;
        }
    }

    return ss.str();
}

static std::string ScanSystemMemoryAccess() {
    std::ostringstream ss;
    ss << "[*] Starting ScanSystemMemoryAccess." << std::endl;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ss.str();

    auto NtQuerySysInfo = reinterpret_cast<pfnNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    if (!NtQuerySysInfo) return ss.str();

    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;
    NTSTATUS status = 0;
    do {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return ss.str();

        status = NtQuerySysInfo(SystemHandleInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
            bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        ss << "[-] NtQuerySystemInformation failed." << std::endl;
        return ss.str();
    }

    const auto *handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
    ss << "[+] Total system handles to inspect: " << handleInfo->NumberOfHandles << std::endl;

    std::vector<HandleAccessRecord> currentScan;
    const int limiter = 30;
    int counter = 0;
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; ++i) {
        HandleAccessRecord handleRecord;
        const auto &entry = handleInfo->Handles[i];

        DWORD sourcePid = handleRecord.sourcePid = entry.UniqueProcessId;
        HANDLE hRemoteHandle = reinterpret_cast<HANDLE>(entry.HandleValue);
        ULONG grantedAccess = handleRecord.accessRights = entry.GrantedAccess;
        if (sourcePid == 0 || sourcePid == 4) continue;

        HANDLE hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, sourcePid);
        if (!hTargetProcess) continue;

        std::string typeName, objectName;
        if (GetHandleDetails(hTargetProcess, hRemoteHandle, typeName, objectName)) {
            if (typeName == "Process") {

                const bool canRead = (grantedAccess & PROCESS_VM_READ) != 0;
                const bool canWrite = (grantedAccess & PROCESS_VM_WRITE) != 0;
                const bool canOperate = (grantedAccess & PROCESS_VM_OPERATION) != 0;
                const bool canCreateThread = (grantedAccess & PROCESS_CREATE_THREAD) != 0;
                const bool isFullAccess = (grantedAccess & 0x1F0FFF) == 0x1F0FFF;

                if (canRead || canWrite || canCreateThread || isFullAccess) {
                    HANDLE hLocalDuplicate = nullptr;
                    if (DuplicateHandle(hTargetProcess, hRemoteHandle, GetCurrentProcess(), &hLocalDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                        DWORD targetPid = handleRecord.targetPid = GetProcessId(hLocalDuplicate);
                        CloseHandle(hLocalDuplicate);

                        if (targetPid != 0 && targetPid != sourcePid) {
                            std::string sourceName = GetProcessNameFromPID2(sourcePid);
                            std::string targetName = GetProcessNameFromPID2(targetPid);
                            std::string sourcePath = GetProcessFullPath(sourcePid);

                            std::string threatLevel = "[INFO / Normal]";
                            if (isFullAccess || canCreateThread || canWrite) {
                                threatLevel = "[!] [HIGH RISK] Potential Injection/Control!";
                            } else if (canRead) {
                                threatLevel = "[!] [MEDIUM RISK] Memory Read Access";
                            }

                            ss << threatLevel << std::endl;
                            ss << "    -> Source: PID " << sourcePid << " (" << sourceName << ")" << std::endl;
                            ss << "    -> Path:   " << sourcePath << std::endl;
                            ss << "    -> Target: PID " << targetPid << " (" << targetName << ")" << std::endl;
                            ss << "    -> Rights: 0x" << std::hex << grantedAccess << std::dec;

                            std::wcout << L" [ ";
                            if (isFullAccess) ss << "ALL_ACCESS ";
                            if (canCreateThread) ss << "CREATE_THREAD ";
                            if (canWrite) ss << "VM_WRITE ";
                            if (canRead) ss << "VM_READ ";
                            ss << "]" << std::endl;
                
                            ss << "--------------------------------------------------" << std::endl;

                            if(counter++ == limiter) {
                                CloseHandle(hTargetProcess);
                                break;
                            }
                            currentScan.push_back(handleRecord);
                        }
                    }
                }

                /***
                if ((grantedAccess & PROCESS_VM_READ) || (grantedAccess & 0x1F0FFF)) {
                    HANDLE hLocalDuplicate = nullptr;
                    if (DuplicateHandle(hTargetProcess, hRemoteHandle, GetCurrentProcess(), &hLocalDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                        DWORD targetPid = GetProcessId(hLocalDuplicate);
                        CloseHandle(hLocalDuplicate);

                        if (targetPid != 0 && targetPid != sourcePid) {
                            std::string sourceName = GetProcessNameFromPID2(sourcePid);
                            std::string targetName = GetProcessNameFromPID2(targetPid);

                            ss << "[!] Cross-Process Memory Access Detected!" << std::endl;
                            ss << "    -> Source: PID " << sourcePid << " (" << sourceName << ")" << std::endl;
                            ss << "    -> Target: PID " << targetPid << " (" << targetName << ")" << std::endl;
                            ss << "    -> Access Rights: 0x" << std::hex << grantedAccess << std::dec << std::endl;
                            ss << "--------------------------------------------------" << std::endl;

                            if(counter++ == limiter) {
                                CloseHandle(hTargetProcess);
                                break;
                            }
                        }
                    }
                }
                ***/
            }
        }

        CloseHandle(hTargetProcess);
    }

    ss << ProcessScanResults(currentScan);
    ss << MemoryDetector(g_hWnd, currentScan);

    VirtualFree(buffer, 0, MEM_RELEASE);
    return ss.str();
}

static void PipeServerThread() {
    while (g_thread) {
        /**
        try {
            COLORREF logColor = RGB(255, 180, 0);
            std::string logStr = ScanSystemMemoryAccess();
            char* pText = new char[logStr.size() + 1];
            strcpy_s(pText, logStr.size() + 1, logStr.c_str());

            PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
        }
        catch (const std::string&) {}

        try {
            COLORREF logColor = RGB(255, 180, 0);
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(g_hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) > 0) {
                std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);
                std::ostringstream ss;
                ss << "InspectTargetNetwork ---\n";
                for (auto targetPid: pids) {
                    ss << InspectTargetNetwork(targetPid, WStringToString(std::wstring(procNameBuf)));
                }
                std::string logStr = ss.str();
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());

                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }
        }
        catch (const std::string&) {}

        try {
            COLORREF logColor = RGB(255, 180, 0);
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(g_hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) > 0) {
                std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);
                std::ostringstream ss;
                ss << "InspectSectionObjects Common Memory ---\n";
                for (auto targetPid : pids) {
                    ss << InspectSectionObjects(targetPid, WStringToString(std::wstring(procNameBuf)));
                }
                std::string logStr = ss.str();
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());

                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }
        }
        catch (const std::string&) {}

        try {
            COLORREF logColor = RGB(255, 180, 0);
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(g_hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) > 0) {
                std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);
                std::ostringstream ss;
                ss << "ScanIncomingProcessAccess Common Memory ---\n";
                for (auto targetPid : pids) {
                    ss << ScanIncomingProcessAccess(targetPid, WStringToString(std::wstring(procNameBuf)));
                }
                std::string logStr = ss.str();
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());

                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }
        }
        catch (const std::string&) {}
        **/

        try {

            {
                COLORREF logColor = RGB(255, 180, 0);
                std::string logStr = "Start ...\n\n";
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());
                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }

            COLORREF logColor = RGB(255, 180, 0);
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(g_hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) > 0) {
                std::ostringstream ss;
                ss << WStringToString(std::wstring(procNameBuf)) << " ---\n";
                std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);
                ss << "InspectAlpcAndPipes ---\n";
                for (auto targetPid : pids) {
                    ss << InspectAlpcAndPipes(targetPid, WStringToString(std::wstring(procNameBuf)));
                }
                std::string logStr = ss.str();
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());

                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }
        }
        catch (const std::string&) {}

        try {

            {
                COLORREF logColor = RGB(255, 180, 0);
                std::string logStr = "Start ...\n\n";
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());
                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_RIGHT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }

            COLORREF logColor = RGB(255, 180, 0);
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(g_hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) > 0) {
                std::ostringstream ss;
                ss << WStringToString(std::wstring(procNameBuf)) << " ---\n";
                std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);
                ss << "StartPipeTrafficSniffer ---\n";
                for (auto targetPid : pids) {
                    ss << StartPipeTrafficSniffer(targetPid, WStringToString(std::wstring(procNameBuf)));
                }
                std::string logStr = ss.str();
                char* pText = new char[logStr.size() + 1];
                strcpy_s(pText, logStr.size() + 1, logStr.c_str());

                PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_RIGHT_A, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
            }
        }
        catch (const std::string&) {}

        /**
        * The following code is no longer needed because AI security investigations via DLL injection were blocked on October 16, 2026 (GPT-6 Astra).
        * Therefore, we will continue from here.
        * In the future, we will split this into a separate thread and restart it then (though it will probably still be blocked).
        **/
        Sleep(1000);
        continue;

        HANDLE hPipe = CreateNamedPipeW(
            GUARDIAN_PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(GuardianAlertEvent),
            sizeof(GuardianAlertEvent),
            0, nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            GuardianAlertEvent alert;
            DWORD bytesRead = 0;

            if (ReadFile(hPipe, &alert, sizeof(GuardianAlertEvent), &bytesRead, nullptr)) {
                SYSTEMTIME st;
                GetLocalTime(&st);

                std::wostringstream ss;
                ss << L"[" << std::setfill(L'0') << std::setw(2) << st.wHour << L":"
                    << std::setw(2) << st.wMinute << L":" << std::setw(2) << st.wSecond << L"] ";

                wchar_t procNameBuf[256] = { 0 };
                GetWindowTextW(g_hEditProcessName, procNameBuf, 256);
                ss << InspectTargetHandles(std::wstring(procNameBuf)).c_str();

                COLORREF logColor = RGB(200, 200, 200);
                std::string debugger = RunDebuggerForensics(alert.targetPid);
                std::string handles = CheckOpenHandles(alert.targetPid);

                if (alert.type == AlertType::MemoryRead) {
                    logColor = RGB(255, 80, 80);
                    ss << L"[ALERT: Memory Read Detected]\n"
                       << L"  „¥„Ÿ Source PID : " << alert.sourcePid << " (" << GetProcessNameFromPID(alert.sourcePid).c_str() << L") \n"
                       << L"  „¥„Ÿ Target PID : " << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¥„Ÿ Address    : 0x" << std::hex << alert.baseAddress << std::dec << L"\n"
                       << L"  „¥„Ÿ Size       : " << alert.bufferSize << L" Bytes\n"
                       << L"  „¥„Ÿ Hex        : " << std::hex << ToHexString(alert.buf, sizeof(alert.buf) < alert.bufferSize ? sizeof(alert.buf): alert.bufferSize).c_str() << std::dec << L"\n"
                       << L"  „¥„Ÿ Debugger   : " << debugger.c_str() << L"\n"
                       << L"  „¤„Ÿ Handles    : " << handles.c_str() << L"\n\n";
                }
                else if (alert.type == AlertType::ProcessOpen) {
                    logColor = RGB(255, 180, 0);
                    ss << L"[WARN: Process Handle Opened]\n"
                       << L"  „¥„Ÿ Source PID : " << alert.sourcePid << " (" << GetProcessNameFromPID(alert.sourcePid).c_str() << L") \n"
                       << L"  „¥„Ÿ Target PID : " << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¥„Ÿ Access     : 0x" << std::hex << alert.desiredAccess << std::dec << L"\n"
                       << L"  „¥„Ÿ Debugger   : " << debugger.c_str() << L"\n"
                       << L"  „¤„Ÿ Handles    : " << handles.c_str() << L"\n\n";
                }
                else if (alert.type == AlertType::CommonMapView) {
                    logColor = RGB(255, 180, 0);
                    ss << L"[ALERT: Shared Memory Mapped]\n"
                       << L"  „¥„Ÿ Target PID  : " << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¥„Ÿ Mapped Addr : 0x" << std::hex << alert.baseAddress << std::dec << L"\n"
                       << L"  „¥„Ÿ View Size   : " << std::dec << alert.bufferSize << " Bytes\n"
                       << L"  „¥„Ÿ Data Peek   : " << std::hex << ToHexString(alert.buf, sizeof(alert.buf) < alert.bufferSize ? sizeof(alert.buf) : alert.bufferSize).c_str() << std::dec << L"\n"
                       << L"  „¥„Ÿ Debugger    : " << debugger.c_str() << L"\n"
                       << L"  „¤„Ÿ Handles     : " << handles.c_str() << L"\n\n";
                }
                else if (alert.type == AlertType::DuplicateObject) {
                    logColor = RGB(255, 180, 0);
                    ss << L"[WARN: Foreign Handle Duplicated]\n"
                       << L"  „¥„Ÿ Source PID    : " << alert.sourcePid << " (" << GetProcessNameFromPID(alert.sourcePid).c_str() << L") \n"
                       << L"  „¥„Ÿ DesiredAccess : 0x" << std::hex << alert.desiredAccess << "\n"
                       << L"  „¥„Ÿ Stolen Handle : 0x" << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¥„Ÿ Debugger      : " << debugger.c_str() << L"\n"
                       << L"  „¤„Ÿ Handles       : " << handles.c_str() << L"\n\n";
                } else
                    return;

                try {
                    std::wstring logStr = ss.str();
                    wchar_t *pText = new wchar_t[logStr.size() + 1];
                    wcscpy_s(pText, logStr.size() + 1, logStr.c_str());

                    PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY_LEFT, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
                } catch (const std::string &) {}
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

static void AppendLogText(HWND hRichEdit, const std::wstring &text, COLORREF color) {
    CHARFORMAT2W cf = {0};
    cf.cbSize = sizeof(CHARFORMAT2W);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    const int len = GetWindowTextLengthW(hRichEdit);

    SendMessageW(hRichEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(hRichEdit, EM_SCROLLCARET, 0, 0);
}

static void AppendLogTextA(HWND hRichEdit, const std::string &textA, COLORREF color) {
    CHARFORMAT2W cf = {0};
    cf.cbSize = sizeof(CHARFORMAT2W);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    const int len = GetWindowTextLengthW(hRichEdit);

    std::wstring text = StringToWString(textA);

    SendMessageW(hRichEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(hRichEdit, EM_SCROLLCARET, 0, 0);
}

static bool InjectGuardianCore(DWORD targetPid, const wchar_t *dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProcess) return false;

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteMem, dllPath, pathSize, nullptr);

    HMODULE mod = GetModuleHandleW(L"kernel32.dll");
    if(!mod) {
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(mod, "LoadLibraryW");
    if(!pLoadLibrary) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, nullptr);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hStatic = nullptr;
    static HWND hEditPid = nullptr;
    static HWND hBtnInject = nullptr;
    static HWND hBtnInjectAll = nullptr;
    static HWND hLogEditLeft = nullptr;
    static HWND hLogEditRight = nullptr;
    auto InstanceCheck = []() {
        return hStatic && g_hEditProcessName && hEditPid && hBtnInject && hBtnInjectAll && hLogEditLeft && hLogEditRight;
    };
    auto DisableButton = []() {
        EnableWindow(hBtnInject, FALSE);
        EnableWindow(hBtnInjectAll, FALSE);
    };

    switch (msg) {
    case WM_CREATE: {
        hStatic = CreateWindowW(
            L"STATIC", L"Target PID:",
            WS_VISIBLE | WS_CHILD,
            15, 15, 90, 20,
            hWnd, nullptr, nullptr, nullptr
        );

        hEditPid = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | ES_NUMBER,
            100, 12, 60, 25,
            hWnd, (HMENU)IDC_PID_INPUT, nullptr, nullptr
        );

        g_hEditProcessName = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"ChatGPT.exe",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
            170, 12, 140, 25,
            hWnd, (HMENU)IDC_PROCESS_NAME_INPUT, nullptr, nullptr
        );

        hBtnInject = CreateWindowW(
            L"BUTTON", L"Start Monitoring",
            WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            320, 11, 160, 27,
            hWnd, (HMENU)IDC_BTN_INJECT, nullptr, nullptr
        );

        hBtnInjectAll = CreateWindowW(
            L"BUTTON", L"Attach All Instances",
            WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            490, 11, 160, 27,
            hWnd, (HMENU)IDC_BTN_INJECT_ALL, nullptr, nullptr
        );

        hLogEditLeft = CreateWindowExW(
            WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            15, 50, 650, 420,
            hWnd, (HMENU)IDC_LOG_EDIT, nullptr, nullptr
        );

        hLogEditRight = CreateWindowExW(
            WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            670, 50, 650, 420,
            hWnd, (HMENU)IDC_LOG_EDIT, nullptr, nullptr
        );

        if(!InstanceCheck()) {
            MessageBoxW(nullptr, L"Failure instance.", L"ERROR", MB_OK | MB_ICONWARNING);
            return 0;
        }

        SendMessageW(hLogEditLeft, EM_SETBKGNDCOLOR, 0, (LPARAM)RGB(25, 25, 25));
        SendMessageW(hLogEditRight, EM_SETBKGNDCOLOR, 0, (LPARAM)RGB(25, 25, 25));

        CHARFORMAT2W cf = {0};
        cf.cbSize = sizeof(CHARFORMAT2W);
        cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
        cf.yHeight = 180;
        wcscpy_s(cf.szFaceName, L"Consolas");
        cf.crTextColor = RGB(200, 200, 200);
        SendMessageW(hLogEditLeft, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        SendMessageW(hLogEditRight, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

        AppendLogText(hLogEditLeft, L"[AI Agent Memory Checker] Initialization completed.\n", RGB(100, 200, 250));
        AppendLogText(hLogEditLeft, L"[System] Ready for Windows 11 (x64) process monitoring.\n\n", RGB(150, 150, 150));

        g_thread = true;
        std::thread(PipeServerThread).detach();
        AppendLogText(hLogEditLeft, L"[AI Agent Memory Checker] IPC Pipe listener initialized.\n\n", RGB(100, 200, 250));
        break;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_BTN_INJECT) {
            wchar_t pidBuf[32] = { 0 };
            GetWindowTextW(hEditPid, pidBuf, 32);
            DWORD pid = _wtoi(pidBuf);

            if (pid == 0) {
                MessageBoxW(hWnd, L"Please enter a valid Process ID (PID).", L"Error", MB_OK | MB_ICONERROR);
                break;
            }

            std::wostringstream ss;
            ss << L"[+] Initiating monitoring on PID: " << pid << L"...\n";
            AppendLogText(hLogEditLeft, ss.str(), RGB(100, 255, 100));
            DisableButton();
        } 
        else if (LOWORD(wParam) == IDC_BTN_INJECT_ALL) {
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(g_hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) == 0) {
                MessageBoxW(hWnd, L"Please enter a target process name (e.g. ChatGPT.exe).", L"Error", MB_OK | MB_ICONERROR);
                break;
            }

            std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);

            if (pids.empty()) {
                std::wostringstream ss;
                ss << L"[-] No running instances found for: " << procNameBuf << L"\n";
                AppendLogText(hLogEditLeft, ss.str(), RGB(255, 150, 0));
                break;
            }

            wchar_t currentDir[MAX_PATH];
            GetCurrentDirectoryW(MAX_PATH, currentDir);
            std::wstring dllPath = std::wstring(currentDir) + L"\\GuardianCore.dll";

            std::wostringstream ssHeader;
            ssHeader << L"[+] Found " << pids.size() << L" process instance(s) for " << procNameBuf << L". Attaching...\n";
            AppendLogText(hLogEditLeft, ssHeader.str(), RGB(100, 200, 250));

            size_t successCount = 0;
            for (DWORD pid : pids) {
                if (InjectGuardianCore(pid, dllPath.c_str())) {
                    std::wostringstream ss;
                    ss << L"  „¥„Ÿ [OK] Attached to PID: " << pid << L"\n";
                    AppendLogText(hLogEditLeft, ss.str(), RGB(100, 255, 100));
                    successCount++;
                }
                else {
                    std::wostringstream ss;
                    ss << L"  „¥„Ÿ [FAIL] Could not attach to PID: " << pid << L" (Check admin privileges)\n";
                    AppendLogText(hLogEditLeft, ss.str(), RGB(255, 100, 100));
                }
            }

            std::wostringstream ssFooter;
            ssFooter << L"[+] Monitoring activated on " << successCount << L"/" << pids.size() << L" process(es).\n\n";
            AppendLogText(hLogEditLeft, ssFooter.str(), RGB(100, 255, 100));
            DisableButton();
        }
        break;
    }

    case WM_ADD_LOG_ENTRY_LEFT: {
        const wchar_t *pText = reinterpret_cast<wchar_t *>(wParam);
        COLORREF color = static_cast<COLORREF>(lParam);
        if (pText) {
            AppendLogText(hLogEditLeft, std::wstring(pText), color);
            delete [] pText;
        }
        break;
    }

    case WM_ADD_LOG_ENTRY_LEFT_A: {
        const char *pText = reinterpret_cast<const char *>(wParam);
        COLORREF color = static_cast<COLORREF>(lParam);
        if (pText) {
            AppendLogTextA(hLogEditLeft, std::string(pText), color);
            delete [] pText;
        }
        break;
    }

    case WM_ADD_LOG_ENTRY_RIGHT: {
        const wchar_t* pText = reinterpret_cast<wchar_t*>(wParam);
        COLORREF color = static_cast<COLORREF>(lParam);
        if (pText) {
            AppendLogText(hLogEditRight, std::wstring(pText), color);
            delete[] pText;
        }
        break;
    }

    case WM_ADD_LOG_ENTRY_RIGHT_A: {
        const char* pText = reinterpret_cast<const char*>(wParam);
        COLORREF color = static_cast<COLORREF>(lParam);
        if (pText) {
            AppendLogTextA(hLogEditRight, std::string(pText), color);
            delete[] pText;
        }
        break;
    }

    case WM_DESTROY:
        g_thread = false;
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    LoadLibraryW(L"Msftedit.dll");
    InitCommonControls();

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AIAgentMemoryCheckerClass";
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(
        0,
        L"AIAgentMemoryCheckerClass",
        L"AI Agent Memory Checker v1.14",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1350, 520,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hWnd) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 0;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return static_cast<int>(msg.wParam);
}
