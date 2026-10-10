// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include "common.h"
#include "../GuardianCore.dll/structure.h"

HWND g_hWnd = nullptr;
bool g_thread = false;

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
            processName = std::string(fileName.begin(), fileName.end());
        }
    }

    CloseHandle(hProcess);
    return processName;
}

static void PipeServerThread() {
    while (g_thread) {
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

                COLORREF logColor = RGB(200, 200, 200);

                if (alert.type == AlertType::MemoryRead) {
                    logColor = RGB(255, 80, 80);
                    ss << L"[ALERT: Memory Read Detected]\n"
                       << L"  „¥„Ÿ Source PID : " << alert.sourcePid << " (" << GetProcessNameFromPID(alert.sourcePid).c_str() << L") \n"
                       << L"  „¥„Ÿ Target PID : " << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¥„Ÿ Address    : 0x" << std::hex << alert.baseAddress << std::dec << L"\n"
                       << L"  „¥„Ÿ Size       : " << alert.bufferSize << L" Bytes\n"
                       << L"  „¤„Ÿ Hex        : " << std::hex << ToHexString(alert.buf, sizeof(alert.buf) < alert.bufferSize ? sizeof(alert.buf): alert.bufferSize).c_str() << std::dec << L"\n\n";
                }
                else if (alert.type == AlertType::ProcessOpen) {
                    logColor = RGB(255, 180, 0);
                    ss << L"[WARN: Process Handle Opened]\n"
                       << L"  „¥„Ÿ Source PID : " << alert.sourcePid << " (" << GetProcessNameFromPID(alert.sourcePid).c_str() << L") \n"
                       << L"  „¥„Ÿ Target PID : " << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¤„Ÿ Access     : 0x" << std::hex << alert.desiredAccess << std::dec << L"\n\n";
                }
                else if (alert.type == AlertType::CommonMapView) {
                    logColor = RGB(255, 180, 0);
                    ss << L"[ALERT: Shared Memory Mapped]\n"
                       << L"  „¥„Ÿ Target PID  : " << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n"
                       << L"  „¥„Ÿ Mapped Addr : 0x" << std::hex << alert.baseAddress << std::dec << L"\n"
                       << L"  „¥„Ÿ View Size   : " << std::dec << alert.bufferSize << " Bytes\n"
                       << L"  „¤„Ÿ Data Peek   : " << std::hex << ToHexString(alert.buf, sizeof(alert.buf) < alert.bufferSize ? sizeof(alert.buf) : alert.bufferSize).c_str() << std::dec << L"\n\n";
                }
                else if (alert.type == AlertType::DuplicateObject) {
                    logColor = RGB(255, 180, 0);
                    ss << L"[WARN: Foreign Handle Duplicated]\n"
                       << L"  „¥„Ÿ Source PID    : " << alert.sourcePid << " (" << GetProcessNameFromPID(alert.sourcePid).c_str() << L") \n"
                       << L"  „¥„Ÿ DesiredAccess : 0x" << std::hex << alert.desiredAccess << "\n"
                       << L"  „¤„Ÿ Stolen Handle : 0x" << alert.targetPid << " (" << GetProcessNameFromPID(alert.targetPid).c_str() << L") \n\n";
                } else
                    return;

                try {
                    std::wstring logStr = ss.str();
                    wchar_t *pText = new wchar_t[logStr.size() + 1];
                    wcscpy_s(pText, logStr.size() + 1, logStr.c_str());

                    PostMessageW(g_hWnd, WM_ADD_LOG_ENTRY, reinterpret_cast<WPARAM>(pText), static_cast<LPARAM>(logColor));
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

static std::vector<DWORD> GetPidsByProcessName(const std::wstring &processName) {
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

static bool InjectGuardianCore(DWORD targetPid, const wchar_t *dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProcess) return false;

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteMem, dllPath, pathSize, NULL);

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

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);

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
    static HWND hEditProcessName = nullptr;
    static HWND hEditPid = nullptr;
    static HWND hBtnInject = nullptr;
    static HWND hBtnInjectAll = nullptr;
    static HWND hLogEdit = nullptr;
    auto InstanceCheck = []() {
        return hStatic && hEditProcessName && hEditPid && hBtnInject && hBtnInjectAll && hLogEdit;
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

        hEditProcessName = CreateWindowExW(
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

        hLogEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            15, 50, 650, 420,
            hWnd, (HMENU)IDC_LOG_EDIT, nullptr, nullptr
        );

        if(!InstanceCheck()) {
            MessageBoxW(nullptr, L"Failure instance.", L"ERROR", MB_OK | MB_ICONWARNING);
            return 0;
        }

        SendMessageW(hLogEdit, EM_SETBKGNDCOLOR, 0, (LPARAM)RGB(25, 25, 25));

        CHARFORMAT2W cf = {0};
        cf.cbSize = sizeof(CHARFORMAT2W);
        cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
        cf.yHeight = 180;
        wcscpy_s(cf.szFaceName, L"Consolas");
        cf.crTextColor = RGB(200, 200, 200);
        SendMessageW(hLogEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

        AppendLogText(hLogEdit, L"[AI Agent Memory Checker] Initialization completed.\n", RGB(100, 200, 250));
        AppendLogText(hLogEdit, L"[System] Ready for Windows 11 (x64) process monitoring.\n\n", RGB(150, 150, 150));

        g_thread = true;
        std::thread(PipeServerThread).detach();
        AppendLogText(hLogEdit, L"[AI Agent Memory Checker] IPC Pipe listener initialized.\n\n", RGB(100, 200, 250));
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
            AppendLogText(hLogEdit, ss.str(), RGB(100, 255, 100));
            DisableButton();
        } 
        else if (LOWORD(wParam) == IDC_BTN_INJECT_ALL) {
            wchar_t procNameBuf[256] = { 0 };
            GetWindowTextW(hEditProcessName, procNameBuf, 256);

            if (wcslen(procNameBuf) == 0) {
                MessageBoxW(hWnd, L"Please enter a target process name (e.g. ChatGPT.exe).", L"Error", MB_OK | MB_ICONERROR);
                break;
            }

            std::vector<DWORD> pids = GetPidsByProcessName(procNameBuf);

            if (pids.empty()) {
                std::wostringstream ss;
                ss << L"[-] No running instances found for: " << procNameBuf << L"\n";
                AppendLogText(hLogEdit, ss.str(), RGB(255, 150, 0));
                break;
            }

            wchar_t currentDir[MAX_PATH];
            GetCurrentDirectoryW(MAX_PATH, currentDir);
            std::wstring dllPath = std::wstring(currentDir) + L"\\GuardianCore.dll";

            std::wostringstream ssHeader;
            ssHeader << L"[+] Found " << pids.size() << L" process instance(s) for " << procNameBuf << L". Attaching...\n";
            AppendLogText(hLogEdit, ssHeader.str(), RGB(100, 200, 250));

            size_t successCount = 0;
            for (DWORD pid : pids) {
                if (InjectGuardianCore(pid, dllPath.c_str())) {
                    std::wostringstream ss;
                    ss << L"  „¥„Ÿ [OK] Attached to PID: " << pid << L"\n";
                    AppendLogText(hLogEdit, ss.str(), RGB(100, 255, 100));
                    successCount++;
                }
                else {
                    std::wostringstream ss;
                    ss << L"  „¥„Ÿ [FAIL] Could not attach to PID: " << pid << L" (Check admin privileges)\n";
                    AppendLogText(hLogEdit, ss.str(), RGB(255, 100, 100));
                }
            }

            std::wostringstream ssFooter;
            ssFooter << L"[+] Monitoring activated on " << successCount << L"/" << pids.size() << L" process(es).\n\n";
            AppendLogText(hLogEdit, ssFooter.str(), RGB(100, 255, 100));
            DisableButton();
        }
        break;
    }

    case WM_ADD_LOG_ENTRY: {
        const wchar_t *pText = reinterpret_cast<wchar_t *>(wParam);
        COLORREF color = static_cast<COLORREF>(lParam);
        if (pText) {
            AppendLogText(hLogEdit, std::wstring(pText), color);
            delete [] pText;
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
        L"AI Agent Memory Checker v1.0",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 695, 520,
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
