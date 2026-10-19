// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TCP_H
#define TCP_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct TcpConnectionInfo {
    DWORD pid;
    std::string localIp;
    USHORT localPort;
    std::string remoteIp;
    USHORT remotePort;
    DWORD state;
};

std::string TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default:                       return "UNKNOWN";
    }
}

inline std::vector<TcpConnectionInfo> QueryActiveTcpConnections() {
    std::vector<TcpConnectionInfo> connections;
    ULONG bufferSize = 0;

    DWORD result = GetExtendedTcpTable(nullptr, &bufferSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return connections;
    }

    std::vector<BYTE> buffer(bufferSize);
    PMIB_TCPTABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    result = GetExtendedTcpTable(tcpTable, &bufferSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID row = tcpTable->table[i];

            in_addr localAddr;
            localAddr.s_addr = row.dwLocalAddr;
            char localIpStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &localAddr, localIpStr, sizeof(localIpStr));

            in_addr remoteAddr;
            remoteAddr.s_addr = row.dwRemoteAddr;
            char remoteIpStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &remoteAddr, remoteIpStr, sizeof(remoteIpStr));

            TcpConnectionInfo info;
            info.pid = row.dwOwningPid;
            info.localIp = localIpStr;
            info.localPort = ntohs(static_cast<USHORT>(row.dwLocalPort));
            info.remoteIp = remoteIpStr;
            info.remotePort = ntohs(static_cast<USHORT>(row.dwRemotePort));
            info.state = row.dwState;

            connections.push_back(info);
        }
    }

    return connections;
}

inline std::string InspectTargetNetwork(DWORD targetPid, const std::string &processName) {
    auto tcpConns = QueryActiveTcpConnections();

    std::stringstream ss;
    ss << "=== Network Forensic Report: " << processName << " (PID: " << targetPid << ") ===\n";
    
    size_t matchCount = 0;
    for (const auto &conn : tcpConns) {
        if (conn.pid == targetPid) {
            matchCount++;
            ss << "  > [TCP] " << conn.localIp << ":" << conn.localPort
               << " <==> " << conn.remoteIp << ":" << conn.remotePort
               << " | State: " << TcpStateToString(conn.state) << "\n";
        }
    }

    if (matchCount == 0) {
        ss << "  (No active TCP connections found for this PID)\n";
    }
    ss << "---------------------------------------------------------\n\n";

    return ss.str();
}

#endif
