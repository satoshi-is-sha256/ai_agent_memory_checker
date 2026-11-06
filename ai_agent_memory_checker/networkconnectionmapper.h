// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NETWORKCONNECTIONMAPPER_H
#define NETWORKCONNECTIONMAPPER_H

#include <winsock2.h>
#include <iphlpapi.h>
#include "common.h"
#include <iomanip>
#include <WS2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct TcpConnectionInfo2 : public TcpConnectionInfo {
    DWORD processId;
};

class NetworkConnectionMapper {
private:
    static std::string StateToString(DWORD state) {
        switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default:                       return "UNKNOWN";
        }
    }

public:
    static std::vector<TcpConnectionInfo2> GetActiveConnections() {
        std::vector<TcpConnectionInfo2> connections;

        PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
        DWORD dwSize = 0;

        //if (GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        //    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        //}

        if (pTcpTable) {
            if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];

                    IN_ADDR localAddr, remoteAddr;
                    localAddr.S_un.S_addr = row.dwLocalAddr;
                    remoteAddr.S_un.S_addr = row.dwRemoteAddr;

                    char localIpStr[INET_ADDRSTRLEN];
                    char remoteIpStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &localAddr, localIpStr, sizeof(localIpStr));
                    inet_ntop(AF_INET, &remoteAddr, remoteIpStr, sizeof(remoteIpStr));

                    TcpConnectionInfo2 info;
                    info.localIp = localIpStr;
                    info.localPort = ntohs((u_short)row.dwLocalPort);
                    info.remoteIp = remoteIpStr;
                    info.remotePort = ntohs((u_short)row.dwRemotePort);
                    info.processId = row.dwOwningPid;
                    info.state = row.dwState;

                    connections.push_back(info);
                }
            }
            free(pTcpTable);
        }

        return connections;
    }

    static std::string FormatConnectionsReport(const std::vector<TcpConnectionInfo2> &connections) {
        std::ostringstream ss;
        ss << "[NETWORK-MAP] Active TCP Connections & PID Mapping:\r\n";
        for (const auto &conn : connections) {
            ss << "  -> PID: " << conn.processId
               << " | " << conn.localIp << ":" << conn.localPort
               << " <-> " << conn.remoteIp << ":" << conn.remotePort
               << " [" << conn.state << "]\r\n";
        }
        return ss.str();
    }
};

#endif