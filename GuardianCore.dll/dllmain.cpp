// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <algorithm>
#include "structure.h"
#include "detours.h"

typedef CLIENT_ID* PCLIENT_ID;

typedef NTSTATUS (NTAPI *pfnNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead);
typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS (NTAPI *pnfNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS (NTAPI *pnfNtDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

static pfnNtReadVirtualMemory Real_NtReadVirtualMemory = nullptr;
static pfnNtOpenProcess Real_NtOpenProcess = nullptr;
static pnfNtMapViewOfSection Real_NtMapViewOfSection = nullptr;
static pnfNtDuplicateObject Real_NtDuplicateObject = nullptr;

static void SendAlertToHost(const GuardianAlertEvent &alert) {
    HANDLE hPipe = CreateFileW(GUARDIAN_PIPE_NAME, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(hPipe, &alert, sizeof(GuardianAlertEvent), &bytesWritten, nullptr);
        CloseHandle(hPipe);
    }
}

static NTSTATUS NTAPI Hooked_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead) {
    NTSTATUS status = Real_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    if (NT_SUCCESS(status) && Buffer != nullptr) {
        DWORD targetPid = GetProcessId(ProcessHandle);
        DWORD currentPid = GetCurrentProcessId();

        if (targetPid != 0 && targetPid != currentPid) {
            GuardianAlertEvent alert;
            alert.type = AlertType::MemoryRead;
            alert.sourcePid = currentPid;
            alert.targetPid = targetPid;
            alert.baseAddress = reinterpret_cast<ULONG_PTR>(BaseAddress);
            alert.bufferSize = BufferSize;

            SIZE_T actualRead = (NumberOfBytesRead != nullptr) ? *NumberOfBytesRead : BufferSize;
            if (actualRead > 0) {
                std::string peekData = FormatMemoryPeek_512bytes(Buffer, actualRead);
                memcpy(alert.buf, Buffer, actualRead);
                SendAlertToHost(alert);
            }
        }
    }

    return status;
}

static NTSTATUS NTAPI Hooked_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    DWORD currentPid = GetCurrentProcessId();
    DWORD targetPid = 0;
    if (ClientId && ClientId->UniqueProcess) {
        targetPid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueProcess));
    }

    if (targetPid != 0 && targetPid != currentPid && (DesiredAccess & (PROCESS_VM_READ | PROCESS_ALL_ACCESS))) {
        GuardianAlertEvent alert;
        alert.type = AlertType::ProcessOpen;
        alert.sourcePid = currentPid;
        alert.targetPid = targetPid;
        alert.desiredAccess = DesiredAccess;

        SendAlertToHost(alert);
    }

    return Real_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

static NTSTATUS NTAPI Hooked_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    NTSTATUS status = Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

    if (NT_SUCCESS(status) && BaseAddress != nullptr && *BaseAddress != nullptr) {
        SIZE_T mappedSize = (ViewSize != nullptr) ? *ViewSize : CommitSize;
        DWORD targetPid = GetProcessId(ProcessHandle);
        DWORD currentPid = GetCurrentProcessId();

        if (targetPid != GetCurrentProcessId() || (Win32Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            GuardianAlertEvent alert;
            alert.type = AlertType::CommonMapView;
            alert.sourcePid = currentPid;
            alert.targetPid = targetPid;
            alert.baseAddress = reinterpret_cast<ULONG_PTR>(BaseAddress);
            alert.bufferSize = mappedSize;

            if (mappedSize > 0) {
                std::string peekData = FormatMemoryPeek_512bytes(*BaseAddress, mappedSize);
                memcpy(alert.buf, *BaseAddress, mappedSize);
                SendAlertToHost(alert);
            }
        }
    }

    return status;
}

static NTSTATUS NTAPI Hooked_NtDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
    NTSTATUS status = Real_NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
    if (NT_SUCCESS(status)) {
        DWORD sourcePid = GetProcessId(SourceProcessHandle);
        DWORD myPid = GetCurrentProcessId();

        if (sourcePid != 0 && sourcePid != myPid) {
            GuardianAlertEvent alert;
            alert.type = AlertType::DuplicateObject;
            alert.sourcePid = sourcePid;
            alert.targetPid = myPid;
            alert.baseAddress = reinterpret_cast<ULONG_PTR>(TargetHandle ? *TargetHandle : 0); // Stolen Handle
            alert.desiredAccess = DesiredAccess;

            SendAlertToHost(alert);
        }
    }

    return status;
}

static void InstallHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    Real_NtReadVirtualMemory = reinterpret_cast<pfnNtReadVirtualMemory>(GetProcAddress(hNtdll, "NtReadVirtualMemory"));
    Real_NtOpenProcess = reinterpret_cast<pfnNtOpenProcess>(GetProcAddress(hNtdll, "NtOpenProcess"));

    Real_NtMapViewOfSection = reinterpret_cast<pnfNtMapViewOfSection>(GetProcAddress(hNtdll, "NtMapViewOfSection"));
    Real_NtDuplicateObject = reinterpret_cast<pnfNtDuplicateObject>(GetProcAddress(hNtdll, "NtDuplicateObject"));

    if (!Real_NtReadVirtualMemory || !Real_NtOpenProcess || !Real_NtMapViewOfSection || !Real_NtDuplicateObject)
        return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)Real_NtReadVirtualMemory, Hooked_NtReadVirtualMemory);
    DetourAttach(&(PVOID&)Real_NtOpenProcess, Hooked_NtOpenProcess);
    DetourAttach(&(PVOID&)Real_NtMapViewOfSection, Hooked_NtMapViewOfSection);
    DetourAttach(&(PVOID&)Real_NtDuplicateObject, Hooked_NtDuplicateObject);
}

static void RemoveHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_NtReadVirtualMemory, Hooked_NtReadVirtualMemory);
    DetourDetach(&(PVOID&)Real_NtOpenProcess, Hooked_NtOpenProcess);
    DetourDetach(&(PVOID&)Real_NtReadVirtualMemory, Hooked_NtMapViewOfSection);
    DetourDetach(&(PVOID&)Real_NtOpenProcess, Hooked_NtDuplicateObject);
    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
        break;
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        break;
    }

    return TRUE;
}
