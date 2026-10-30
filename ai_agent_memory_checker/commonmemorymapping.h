// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COMMONMEMORYMAPPING_H
#define COMMONMEMORYMAPPING_H

#include "common.h"
#include "alpc.h"
#include <winternl.h>
#include <mutex>

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS(NTAPI *pfnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI *pfnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT Inherit,
    ULONG AllocationType,
    ULONG Win32Protect
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CCommonMemory {
    public:
        struct SharedMemoryRegion {
            void *baseAddress;
            size_t viewSize;
            HANDLE sectionHandle;
        };

        static pfnNtCreateSection Original_NtCreateSection;
        static pfnNtMapViewOfSection Original_NtMapViewOfSection;

        static NTSTATUS NTAPI Hooked_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT Inherit, ULONG AllocationType, ULONG Win32Protect) {
            NTSTATUS status = Original_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, Inherit, AllocationType, Win32Protect);

            std::ostringstream ss;
            if (NT_SUCCESS(status) && BaseAddress && *BaseAddress && ViewSize) {
                std::lock_guard<std::mutex> lock(RegionMutex);
                SharedRegions.push_back({ *BaseAddress, *ViewSize, SectionHandle });

                ss << "[SECTION-MAP] Shared Memory Mapped\r\n";
                ss << "  -> Base Address: 0x" << std::hex << *BaseAddress << std::dec << "\r\n";
                ss << "  -> View Size: " << *ViewSize << " bytes\r\n";
            }

            SharedMemoryRegion obj({ *BaseAddress, *ViewSize, SectionHandle });
            ss << ScanSharedMemoryContent(obj);
            ss << DeepScanSharedMemoryBuffer(obj);

            g_NtAlpcCreatePortLogs += ss.str();

            return status;
        }

        static std::string ScanSharedMemoryContent(const SharedMemoryRegion &region) {
            if (!region.baseAddress || region.viewSize == 0) return "";

            size_t scanSize = region.viewSize < 4096 ? region.viewSize : 4096;
            std::string content((const char*)region.baseAddress, scanSize);

            if (content.find("messages") != std::string::npos || content.find("prompt") != std::string::npos) {
                std::ostringstream oss;
                oss << "[SECTION-DATA-INSPECT] Found AI Payload in Shared Memory at 0x" 
                    << std::hex << region.baseAddress << std::dec << "\r\n";
                oss << "  -> Snippet: " << content.substr(0, 300) << "\r\n";
                return oss.str();
            }

            return "";
        }

        static std::string DeepScanSharedMemoryBuffer(const SharedMemoryRegion &region) {
            if (!region.baseAddress || region.viewSize == 0) return "";
            size_t scanSize = region.viewSize < 65536 ? region.viewSize : 65536;

            std::string buffer((const char *)region.baseAddress, scanSize);
            if (buffer.find("prompt") != std::string::npos ||
                buffer.find("messages") != std::string::npos ||
                buffer.find("content") != std::string::npos) {

                std::ostringstream ss;
                ss << "[DEEP-SCAN] AI Context/Payload Detected in Shared Memory!\r\n";
                ss << "  -> BaseAddress: 0x" << std::hex << region.baseAddress << std::dec << "\r\n";
                ss << "  -> Snippet: " << buffer.substr(0, 500) << "\r\n";

                return ss.str();
            }

            return "";
        }

        static void InitializeSectionHooks() {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return;

            Original_NtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
            Original_NtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

            if (Original_NtMapViewOfSection) {
                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
        
                DetourAttach(&(PVOID&)Original_NtMapViewOfSection, Hooked_NtMapViewOfSection);
        
                DetourTransactionCommit();
            }
        }

        static void UninitializeSectionHooks() {
            if (Original_NtMapViewOfSection) {
                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
                DetourDetach(&(PVOID&)Original_NtMapViewOfSection, Hooked_NtMapViewOfSection);
                DetourTransactionCommit();
            }
        }

    private:
        static std::vector<SharedMemoryRegion> SharedRegions;
        static std::mutex RegionMutex;

};

#endif