// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HOOKINTEGRITYMONITOR_H
#define HOOKINTEGRITYMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
// singleton
class CHookIntegrityMonitor {
private:
    CHookIntegrityMonitor() {}

    struct MonitoredFunction {
        std::string functionName;
        FARPROC targetAddress;
        std::vector<BYTE> originalBytes;
    };

    std::vector<MonitoredFunction> m_monitoredList;

public:
    static CHookIntegrityMonitor &GetInstance() {
        static CHookIntegrityMonitor him;
        return him;
    }

    void CheckFunc(MonitoredFunction &mf, FARPROC &pFunc) {
        __try {
            memcpy(mf.originalBytes.data(), (void *)pFunc, 5);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            mf.originalBytes.clear();
        }
    }

    void CheckFunc(BYTE *data, const MonitoredFunction &mf) {
        __try {
            memcpy(data, (void *)mf.targetAddress, 5);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }
    }

    void RegisterFunction(const std::string& moduleName, const std::string &funcName) {
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (!hModule) {
            hModule = LoadLibraryA(moduleName.c_str());
        }
        if (!hModule) return;

        FARPROC pFunc = GetProcAddress(hModule, funcName.c_str());
        if (!pFunc) return;

        MonitoredFunction mf;
        mf.functionName = funcName;
        mf.targetAddress = pFunc;

        mf.originalBytes.resize(5);
        CheckFunc(mf, pFunc);

        if (!mf.originalBytes.empty()) {
            m_monitoredList.push_back(mf);
        }
    }

    struct IntegrityReport {
        bool isTampered;
        std::string details;
    };

    IntegrityReport VerifyIntegrity() {
        IntegrityReport report{ false, "" };
        std::ostringstream ss;

        for (const auto& mf : m_monitoredList) {
            if (mf.originalBytes.empty()) continue;

            std::vector<BYTE> currentBytes(5);
            CheckFunc(&currentBytes.front(), mf);

            if (memcmp(currentBytes.data(), mf.originalBytes.data(), 5) != 0) {
                report.isTampered = true;
                ss << "[ANTI-TAMPER] Hook Integrity Violation Detected!\r\n"
                   << "  -> Function: " << mf.functionName << "\r\n"
                   << "  -> Address: 0x" << std::hex << (uintptr_t)mf.targetAddress << std::dec << "\r\n"
                   << "  -> Reason: Function prologue has been modified, unhooked, or overwritten!\r\n";
            }
        }

        report.details = ss.str();

        if (report.isTampered) {
            ThreatCorrelator::GetInstance().IngestEvent("AntiTamperViolation", report.details, ThreatCorrelator::ThreatLevel::Critical);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return report;
    }
};

#endif
