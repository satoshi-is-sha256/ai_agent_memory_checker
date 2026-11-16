// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FORENSICAUDITLOG_H
#define FORENSICAUDITLOG_H

#include "common.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

typedef bool (*PFN_PQC_SIGN_RECORD)(
    uint8_t algorithmId,
    const uint8_t* hashData,
    size_t hashLen,
    uint8_t* outSignature,
    size_t* inOutSigLen
    );

class ForensicAuditCryptLogger {
private:
    HANDLE m_hLogFile;
    CRITICAL_SECTION m_csLock;
    uint64_t m_sequenceNumber;
    uint8_t m_prevHash[32];
    PFN_PQC_SIGN_RECORD m_pfnPqcSign;
    uint8_t m_activePqcAlgId;

    void BytesToHex(const uint8_t* bytes, size_t len, char* outHex) {
        static const char hexChars[] = "0123456789abcdef";
        for (size_t i = 0; i < len; ++i) {
            outHex[i * 2] = hexChars[(bytes[i] >> 4) & 0x0F];
            outHex[i * 2 + 1] = hexChars[bytes[i] & 0x0F];
        }
        outHex[len * 2] = '\0';
    }

    bool ComputeHash(const uint8_t* data, size_t dataLen, uint8_t outHash[32]) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        bool success = false;

        LPCWSTR algName = BCRYPT_SHA3_256_ALGORITHM;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, algName, NULL, 0))) {
            algName = BCRYPT_SHA256_ALGORITHM;
            if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, algName, NULL, 0))) {
                return false;
            }
        }

        if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
            if (BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0))) {
                if (BCRYPT_SUCCESS(BCryptFinishHash(hHash, outHash, 32, 0))) {
                    success = true;
                }
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return success;
    }

public:
    ForensicAuditCryptLogger()
        : m_hLogFile(INVALID_HANDLE_VALUE),
        m_sequenceNumber(0),
        m_pfnPqcSign(nullptr),
        m_activePqcAlgId(0x01) { // ML-DSA-44
        InitializeCriticalSection(&m_csLock);
        memset(m_prevHash, 0, sizeof(m_prevHash));
    }

    ~ForensicAuditCryptLogger() {
        Close();
        DeleteCriticalSection(&m_csLock);
    }

    bool Open(LPCWSTR filePath, PFN_PQC_SIGN_RECORD pfnSignCallback = nullptr, uint8_t pqcAlgId = 0x01) {
        EnterCriticalSection(&m_csLock);

        if (m_hLogFile != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hLogFile);
            m_hLogFile = INVALID_HANDLE_VALUE;
        }

        m_pfnPqcSign = pfnSignCallback;
        m_activePqcAlgId = pqcAlgId;
        m_hLogFile = CreateFileW(
            filePath,
            FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            NULL
        );

        bool ok = (m_hLogFile != INVALID_HANDLE_VALUE);
        LeaveCriticalSection(&m_csLock);
        return ok;
    }

    bool WriteAuditEvent(const char *moduleName, const char *severity, const char *eventDetail) {
        if (m_hLogFile == INVALID_HANDLE_VALUE) return false;

        EnterCriticalSection(&m_csLock);
        m_sequenceNumber++;

        SYSTEMTIME st;
        GetSystemTime(&st);

        char prevHashHex[65];
        BytesToHex(m_prevHash, 32, prevHashHex);

        char corePayload[2048];
        int coreLen = _snprintf_s(
            corePayload, sizeof(corePayload), _TRUNCATE,
            "{\"seq\":%llu,\"ts\":\"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ\",\"mod\":\"%s\",\"sev\":\"%s\",\"prev\":\"%s\",\"msg\":\"%s\"}",
            m_sequenceNumber,
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            moduleName ? moduleName : "UNKNOWN",
            severity ? severity : "INFO",
            prevHashHex,
            eventDetail ? eventDetail : ""
        );

        if (coreLen <= 0) {
            LeaveCriticalSection(&m_csLock);
            return false;
        }

        uint8_t currentHash[32];
        if (!ComputeHash(reinterpret_cast<const uint8_t*>(corePayload), (size_t)coreLen, currentHash)) {
            LeaveCriticalSection(&m_csLock);
            return false;
        }
        memcpy(m_prevHash, currentHash, 32);

        char currHashHex[65];
        BytesToHex(currentHash, 32, currHashHex);

        char sigHex[5120] = "UNSIGNED";
        if (m_pfnPqcSign != nullptr) {
            uint8_t sigBuf[2560];
            size_t sigLen = sizeof(sigBuf);
            if (m_pfnPqcSign(m_activePqcAlgId, currentHash, 32, sigBuf, &sigLen) && sigLen <= 2500) {
                BytesToHex(sigBuf, sigLen, sigHex);
            }
        }

        char finalLine[8192];
        int finalLen = _snprintf_s(
            finalLine, sizeof(finalLine), _TRUNCATE,
            "{\"record\":%s,\"hash\":\"%s\",\"pqc_alg\":%u,\"sig\":\"%s\"}\r\n",
            corePayload, currHashHex, m_activePqcAlgId, sigHex
        );

        DWORD bytesWritten = 0;
        BOOL writeOk = FALSE;
        if (finalLen > 0) {
            writeOk = WriteFile(m_hLogFile, finalLine, (DWORD)finalLen, &bytesWritten, NULL);
        }

        LeaveCriticalSection(&m_csLock);

        return (writeOk && bytesWritten == (DWORD)finalLen);
    }

    void Close() {
        EnterCriticalSection(&m_csLock);
        if (m_hLogFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(m_hLogFile);
            CloseHandle(m_hLogFile);
            m_hLogFile = INVALID_HANDLE_VALUE;
        }
        LeaveCriticalSection(&m_csLock);
    }
};

#endif
