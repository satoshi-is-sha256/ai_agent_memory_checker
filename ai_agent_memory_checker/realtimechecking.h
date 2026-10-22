// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef REALTIMECHECKING_H
#define REALTIMECHECKING_H

#include "common.h"
#include <fstream>

inline std::string StartPipeTrafficSniffer(DWORD targetPid, const std::string &processName) {
    std::ofstream logFile("pipe_dump.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << "=== New Session Started for PID: " << targetPid << " processName: " << processName << " ===\n";
    }

    std::stringstream ss;
    ss << "[*] Initializing Traffic Sniffer for Target PID: " << targetPid << " (" << processName << ")\n";

    if (!DebugActiveProcess(targetPid)) {
        ss << "[-] Failed to attach debugger. Check privileges (Run as Administrator). Error: " 
           << GetLastError() << "\n";
        return ss.str();
    }

    ss << "[+] Successfully attached to PID " << targetPid << ". Listening for I/O events...\n";

    DEBUG_EVENT de;
    bool isRunning = true;
    while (isRunning) {
        if (!WaitForDebugEvent(&de, 100)) {
            continue;
        }

        DWORD continueStatus = DBG_CONTINUE;

        switch (de.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            ss << "[*] Target process module loaded. Sniffer active.\n";
            break;

        case EXCEPTION_DEBUG_EVENT:
        {
            auto& ex = de.u.Exception.ExceptionRecord;
            if (ex.ExceptionCode == EXCEPTION_BREAKPOINT) {
                //LPVOID hitAddress = ex.ExceptionAddress;
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, de.dwThreadId);
                if (hThread) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            
                    if (GetThreadContext(hThread, &ctx)) {
                        HANDLE hFile = reinterpret_cast<HANDLE>(ctx.Rcx);
                        LPVOID lpBuffer = reinterpret_cast<LPVOID>(ctx.Rdx);
                        DWORD bufferSize = static_cast<DWORD>(ctx.R8);
                        if (bufferSize > 0 && bufferSize < 4096) {
                            std::vector<BYTE> data(bufferSize);
                            SIZE_T bytesRead = 0;
                            HANDLE hTargetProc = OpenProcess(PROCESS_VM_READ, FALSE, de.dwProcessId);
                            if (hTargetProc) {
                                if (ReadProcessMemory(hTargetProc, lpBuffer, data.data(), bufferSize, &bytesRead)) {
                                    std::string payload(reinterpret_cast<char*>(data.data()), bytesRead);
                                    ss << "[>>>] Pipe I/O Captured! Handle: 0x" << std::hex << hFile 
                                       << " | Size: " << std::dec << bytesRead << " bytes\n";
                                    ss << "      Payload: " << payload << "\n\n";

                                    bool isInteresting = (payload.find("token") != std::string::npos ||
                                        payload.find("auth") != std::string::npos ||
                                        payload.find("json") != std::string::npos);

                                    ss << "[>>>] Pipe I/O Captured! Handle: 0x" << std::hex << hFile
                                       << " | Size: " << std::dec << bytesRead << " bytes\n";

                                    if (isInteresting) {
                                        ss << "      [!] KEYWORD MATCHED IN PAYLOAD:\n";
                                    }
                                    ss << "      Payload: " << payload << "\n\n";

                                    if (logFile.is_open()) {
                                        logFile << "[Handle: 0x" << std::hex << hFile << " | Size: " << std::dec << bytesRead << " bytes]\n";
                                        logFile << payload << "\n----------------------------------------\n";
                                        logFile.flush();
                                    }
                                }
                                CloseHandle(hTargetProc);
                            }
                        }
                    }
                    CloseHandle(hThread);
                }

                continueStatus = DBG_CONTINUE;
            }
            else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            ss << "[*] Target process exited.\n";
            isRunning = false;
            break;

        default:
            break;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
    }

    DebugActiveProcessStop(targetPid);
    DebugSetProcessKillOnExit(FALSE);
    ss << "[*] Sniffer detached safely.\n";
    return ss.str();
}

#endif