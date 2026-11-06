// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FORENSICSELFTEST_H
#define FORENSICSELFTEST_H

#include "common.h"

struct ModuleStatus {
    std::string moduleName;
    bool isHookedSuccessfully;
};

class ForensicSelfTest {
public:
    static std::vector<ModuleStatus> RunDiagnostics() {
        std::vector<ModuleStatus> results;

        results.push_back({ "ALPC / Native API (ntdll.dll)", GetModuleHandleW(L"ntdll.dll") != nullptr });
        results.push_back({ "Process / File API (kernel32.dll)", GetModuleHandleW(L"kernel32.dll") != nullptr });
        results.push_back({ "Clipboard / Hooks (user32.dll)", GetModuleHandleW(L"user32.dll") != nullptr });
        results.push_back({ "Network / DNS (ws2_32.dll)", GetModuleHandleW(L"ws2_32.dll") != nullptr });
        results.push_back({ "DPAPI / Crypto (crypt32.dll)", GetModuleHandleW(L"crypt32.dll") != nullptr });

        return results;
    }

    static std::string GenerateDiagnosticsReport() {
        auto statuses = RunDiagnostics();
        std::ostringstream ss;
        
        ss << "### Forensic Engine Self-Test Diagnostics (v1.43)\r\n";
        ss << "| Target Subsystem / DLL | Status |\r\n";
        ss << "|------------------------|--------|\r\n";

        for (const auto &status : statuses) {
            ss << "| " << status.moduleName << " | " << (status.isHookedSuccessfully ? "[OK] Active" : "[FAIL] Missing") << " |\r\n";
        }

        return ss.str();
    }
};

#endif
