// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef REALTIMECHECKING_H
#define REALTIMECHECKING_H

#include "common.h"
#include <fstream>

constexpr DWORD EXCEPTION_INTENTIONAL_BREAKPOINT = 0x80000003;

inline LPVOID GetRemoteNtAlpcAddress(HANDLE hProcess) {
    (void)hProcess;

    HMODULE hLocalNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pLocalFunc = GetProcAddress(hLocalNtdll, "NtAlpcSendWaitReceivePort");
    
    if (!pLocalFunc) return nullptr;

    return reinterpret_cast<LPVOID>(pLocalFunc);
}

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
            auto &ex = de.u.Exception.ExceptionRecord;
            LPVOID hitAddress = ex.ExceptionAddress;

            static LPVOID targetNtAlpcFunc = nullptr;
            if (!targetNtAlpcFunc) {
                HANDLE hTargetProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, de.dwProcessId);
                if (hTargetProc) {
                    targetNtAlpcFunc = GetRemoteNtAlpcAddress(hTargetProc);
                    CloseHandle(hTargetProc);
                }
            }

            if (targetNtAlpcFunc && hitAddress == targetNtAlpcFunc) {
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, de.dwThreadId);
                if (hThread) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            
                    if (GetThreadContext(hThread, &ctx)) {
                        HANDLE hPort = reinterpret_cast<HANDLE>(ctx.Rcx);
                        LPVOID pSendMessage = reinterpret_cast<LPVOID>(ctx.R8);

                        if (pSendMessage != nullptr) {
                            struct PORT_MESSAGE_HEADER {
                                USHORT DataSize;
                                USHORT MessageSize;
                                USHORT MessageType;
                                USHORT VirtualRangesOffset;
                            } msgHeader = { 0 };

                            HANDLE hTargetProc = OpenProcess(PROCESS_VM_READ, FALSE, de.dwProcessId);
                            if (hTargetProc) {
                                SIZE_T bytesRead = 0;
                                if (ReadProcessMemory(hTargetProc, pSendMessage, &msgHeader, sizeof(msgHeader), &bytesRead)) {
                                    LPVOID pDataPayload = reinterpret_cast<LPBYTE>(pSendMessage) + sizeof(PORT_MESSAGE_HEADER) + 8;
                                    USHORT payloadSize = msgHeader.DataSize;

                                    if (payloadSize > 0 && payloadSize < 4096) {
                                        std::vector<BYTE> alpcData(payloadSize);
                                        if (ReadProcessMemory(hTargetProc, pDataPayload, alpcData.data(), payloadSize, &bytesRead)) {
                                            std::string alpcPayload(reinterpret_cast<char*>(alpcData.data()), bytesRead);
                                    
                                            ss << "[ALPC-SNIFF] Unnamed/Named ALPC Traffic Captured!\n";
                                            ss << "             Port Handle: 0xstd::hex" << hPort << "\n";
                                            ss << "             Data Size: " << std::dec << bytesRead << " bytes\n";
                                            ss << "             Payload: " << alpcPayload << "\n\n";
                                        }
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
                continueStatus = EXCEPTION_INTENTIONAL_BREAKPOINT == ex.ExceptionCode ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        /**
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
        **/

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