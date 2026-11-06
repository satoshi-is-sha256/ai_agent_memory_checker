// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CALLSTACKINSPECTOR_H
#define CALLSTACKINSPECTOR_H

#include "common.h"
#include <dbghelp.h>
#include <iomanip>

#pragma comment(lib, "dbghelp.lib")

class CCallStackInspector {
private:
    static bool s_symInitialized;

    static void EnsureSymInitialized() {
        if (!s_symInitialized) {
            SymInitialize(GetCurrentProcess(), NULL, TRUE);
            s_symInitialized = true;
        }
    }

public:
    static std::vector<std::string> CaptureStackTrace(DWORD skipFrames = 2, DWORD maxFrames = 32) {
        EnsureSymInitialized();

        std::vector<std::string> stackTraces;
        void* stack[64];

        if (maxFrames > 64) maxFrames = 64;
        USHORT frames = RtlCaptureStackBackTrace(skipFrames, maxFrames, stack, nullptr);

        HANDLE hProcess = GetCurrentProcess();

        char symbolBuffer[sizeof(SYMBOL_INFO) + 256];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = 255;

        for (USHORT i = 0; i < frames; i++) {
            DWORD64 address = (DWORD64)(stack[i]);
            DWORD64 displacement = 0;

            if (SymFromAddr(hProcess, address, &displacement, pSymbol)) {
                std::ostringstream ss;
                ss << "  -> [" << i << "] 0x" << std::hex << address << std::dec
                   << " : " << pSymbol->Name << " (+0x" << std::hex << displacement << std::dec << ")";
                stackTraces.push_back(ss.str());
            }
            else {
                std::ostringstream ss;
                ss << "  -> [" << i << "] 0x" << std::hex << address << std::dec << " : <unknown-symbol>";
                stackTraces.push_back(ss.str());
            }
        }

        return stackTraces;
    }

    static std::string FormatStackTrace(const std::vector<std::string> &traces) {
        std::ostringstream ss;
        ss << "[STACK-TRACE] Captured Call Stack Backtrace:\r\n";
        for (const auto& line : traces) {
            ss << line << "\r\n";
        }
        return ss.str();
    }
};

#endif
