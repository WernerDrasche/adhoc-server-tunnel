/*
 * This file is part of PRO ONLINE.

 * PRO ONLINE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * PRO ONLINE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PRO ONLINE. If not, see <http://www.gnu.org/licenses/ .
 */
#include <stdint.h>
#include "pspstructs.h"

#ifndef _PACKETS_H_
#define _PACKETS_H_

#define OPCODE_PING 0
#define OPCODE_LOGIN 1
#define OPCODE_CONNECT 2
#define OPCODE_DISCONNECT 3
#define OPCODE_SCAN 4
#define OPCODE_SCAN_COMPLETE 5
#define OPCODE_CONNECT_BSSID 6
#define OPCODE_CHAT 7
#define OPCODE_PORTS 8
#define OPCODE_PORTS_COMPLETE 9
#define OPCODE_PEERS 10
#define OPCODE_PEERS_COMPLETE 11
#define OPCODE_TUNNEL_LOGIN 12
#define OPCODE_END_OF_CONV 13
#define OPCODE_LOCAL 14
#define OPCODE_LISTEN 15

#define PROTOCOL_TCP 0
#define PROTOCOL_UDP 1

// PSP Product Code
#define PRODUCT_CODE_LENGTH 9
typedef struct
{
    // Game Product Code (ex. ULUS12345)
    char data[PRODUCT_CODE_LENGTH];
} __attribute__((packed)) SceNetAdhocctlProductCode;

// Basic Packet
typedef struct
{
    uint8_t opcode;
} __attribute__((packed)) SceNetAdhocctlPacketBase;

// C2S Login Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetEtherAddr mac;
    SceNetAdhocctlNickname name;
    SceNetAdhocctlProductCode game;
} __attribute__((packed)) SceNetAdhocctlLoginPacketC2S;

// C2S Connect Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetAdhocctlGroupName group;
} __attribute__((packed)) SceNetAdhocctlConnectPacketC2S;

typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetEtherAddr mac;
    uint32_t local_ip;
} __attribute__((packed)) SceNetAdhocctlLocalPacketT2S;

// S2T Connect Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetAdhocctlProductCode game;
    SceNetAdhocctlGroupName group;
    uint32_t virt_ip;
    // if opcode is OPCODE_LISTEN then public else local
    uint32_t ip;
} __attribute__((packed)) SceNetAdhocctlConnectPacketS2T;

// S2T Port Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    uint8_t protocol;
    uint16_t port;
} __attribute__((packed)) SceNetAdhocctlPortPacketS2T;

// S2T Peer Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    uint32_t virt_ip;
    uint32_t pub_ip;
} __attribute__((packed)) SceNetAdhocctlPeerPacketS2T;

// C2S Chat Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    char message[64];
} __attribute__((packed)) SceNetAdhocctlChatPacketC2S;

// S2C Connect Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetAdhocctlNickname name;
    SceNetEtherAddr mac;
    uint32_t ip;
} __attribute__((packed)) SceNetAdhocctlConnectPacketS2C;

// S2C Disconnect Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    uint32_t ip;
} __attribute__((packed)) SceNetAdhocctlDisconnectPacketS2C;

// S2C Scan Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetAdhocctlGroupName group;
    SceNetEtherAddr mac;
} __attribute__((packed)) SceNetAdhocctlScanPacketS2C;

// S2C Connect BSSID Packet
typedef struct
{
    SceNetAdhocctlPacketBase base;
    SceNetEtherAddr mac;
} __attribute__((packed)) SceNetAdhocctlConnectBSSIDPacketS2C;

// S2C Chat Packet
typedef struct
{
    SceNetAdhocctlChatPacketC2S base;
    SceNetAdhocctlNickname name;
} __attribute__((packed)) SceNetAdhocctlChatPacketS2C;

#endif
