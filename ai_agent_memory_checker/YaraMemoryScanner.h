// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YARAMEMORYSCANNER_H
#define YARAMEMORYSCANNER_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <iomanip>

struct MemoryScanTarget {
    PVOID baseAddress;
    SIZE_T regionSize;
    DWORD protect;
};

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
// Singleton
class CYaraMemoryScanner {
private:
    CYaraMemoryScanner() {}

    std::vector<BYTE> m_shellcodePattern = { 0x90, 0x90, 0x90, 0x90, 0xCC };

public:
    static CYaraMemoryScanner &GetInstance() {
        static CYaraMemoryScanner yms;
        return yms;
    }

    void ScanProcessMemory() {
        HANDLE hProcess = GetCurrentProcess();
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        PVOID addr = sysInfo.lpMinimumApplicationAddress;
        PVOID maxAddr = sysInfo.lpMaximumApplicationAddress;

        MEMORY_BASIC_INFORMATION mbi;

        while (addr < maxAddr) {
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if ((mbi.State == MEM_COMMIT) &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ)) {

                    InspectMemoryRegion(mbi.BaseAddress, mbi.RegionSize);
                }
                addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            }
            else {
                break;
            }
        }
    }

    void InspectMemoryRegion(PVOID baseAddress, SIZE_T size) {
        BYTE *buffer = (BYTE *)baseAddress;
        try {
            for (SIZE_T i = 0; i < size - m_shellcodePattern.size(); ++i) {
                bool match = true;
                for (SIZE_T j = 0; j < m_shellcodePattern.size(); ++j) {
                    if (buffer[i + j] != m_shellcodePattern[j]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    std::ostringstream ss;
                    ss << "[YARA-SCANNER] Suspicious In-Memory Shellcode / Pattern Match Detected!\r\n";
                    ss << "  -> Base Address: 0x" << std::hex << (uintptr_t)baseAddress << std::dec << "\r\n";
                    ss << "  -> Match Offset: 0x" << std::hex << (uintptr_t)(baseAddress)+i << std::dec << "\r\n";
                    ss << "  -> Region Size: " << size << " bytes\r\n";

                    ThreatCorrelator::GetInstance().IngestEvent("YaraMemoryScan", ss.str(), ThreatCorrelator::ThreatLevel::High);
                    g_NtAlpcCreatePortLogs += ss.str();
                    break;
                }
            }
        }
        catch (const std::string &e) {
            g_NtAlpcCreatePortLogs += e;
            g_NtAlpcCreatePortLogs += "\r\n";
        }
    }
};

#endif
