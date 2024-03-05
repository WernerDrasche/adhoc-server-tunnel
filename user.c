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

//#if !defined(__APPLE__)
//#include <malloc.h>
//#endif
#include <stdint.h>
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "pspstructs.h"
#include "user.h"
#include "status.h"
#include "config.h"
#include "util.h"
#include <sqlite3.h>
#include <inttypes.h>
#include <errno.h>

// User Count
uint32_t _db_user_count = 0;

// User Database
SceNetAdhocctlUserNode * _db_user = NULL;

// Game Database
SceNetAdhocctlGameNode * _db_game = NULL;

// Virtual IPs
SceNetEtherAddr virt_ips[SUBNET_SIZE] = {0};

// Mac to Local IP
struct MacMapEntry *mac_map = NULL;

void add_local_addr(SceNetAdhocctlLocalPacketT2S packet)
{
    uint64_t mac = mac_to_int(packet.mac);
    printf("Adding %" PRIx64 " -> ", mac);
    print_ip(packet.local_ip);
    puts("");
    hmput(mac_map, mac, packet.local_ip);
}

/**
 * Login User into Database (Stream)
 * @param fd Socket
 * @param ip IP Address (Network Order)
 */
void login_user_stream(int fd, uint32_t ip)
{
    // Enough Space available
    if(_db_user_count < SERVER_USER_MAXIMUM)
    {
        // Check IP Duplication
        SceNetAdhocctlUserNode * u = _db_user;
        SceNetAdhocctlUserNode * tunnel = 0;
        bool unique = true;
        while(u != NULL) {
            if (u->resolver.ip == ip) {
                unique = false;
                if (is_tunnel(u)) {
                    tunnel = u;
                    break;
                }
            }
            u = u->next;
        }
        
        // Unique IP Address
        if(tunnel || unique)
        {
            // Allocate User Node Memory
            SceNetAdhocctlUserNode * user = (SceNetAdhocctlUserNode *)malloc(sizeof(SceNetAdhocctlUserNode));
            
            // Allocated User Node Memory
            if(user != NULL)
            {
                // Clear Memory
                memset(user, 0, sizeof(SceNetAdhocctlUserNode));
                
                // Save Socket
                user->stream = fd;
                user->tunnel = tunnel;
                
                // Save IP
                user->resolver.ip = ip;
                
                // Link into User List
                user->next = _db_user;
                if(_db_user != NULL) _db_user->prev = user;
                _db_user = user;
                
                // Initialize Death Clock
                user->last_recv = time(NULL);
                
                // Notify User
                uint8_t * ipa = (uint8_t *)&user->resolver.ip;
                printf("New Connection from %u.%u.%u.%u.\n", ipa[0], ipa[1], ipa[2], ipa[3]);
                
                // Fix User Counter
                _db_user_count++;
                
                // Update Status Log
                update_status();

                // Exit Function
                return;
            }
        }
    }
        
    // Duplicate IP, Allocation Error or not enough space - Close Stream
    close(fd);
}

/**
 * Login User into Database (Login Data)
 * @param user User Node
 * @param data Login Packet
 */
void login_user_data(SceNetAdhocctlUserNode * user, SceNetAdhocctlLoginPacketC2S * data)
{
    // Product Code Check
    int valid_product_code = 1;
    
    // Iterate Characters
    int i = 0; for(; i < PRODUCT_CODE_LENGTH && valid_product_code == 1; i++)
    {
        // Valid Characters
        if(!((data->game.data[i] >= 'A' && data->game.data[i] <= 'Z') || (data->game.data[i] >= '0' && data->game.data[i] <= '9'))) valid_product_code = 0;
    }
    
    // Valid Packet Data
    if(valid_product_code == 1 && memcmp(&data->mac, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(data->mac)) != 0 && memcmp(&data->mac, "\x00\x00\x00\x00\x00\x00", sizeof(data->mac)) != 0 && data->name.data[0] != 0)
    {
        // Game Product Override
        game_product_override(&data->game);
        
        // Find existing Game
        SceNetAdhocctlGameNode * game = _db_game;
        while(game != NULL && strncmp(game->game.data, data->game.data, PRODUCT_CODE_LENGTH) != 0) game = game->next;
        
        // Game not found
        if(game == NULL)
        {
            // Allocate Game Node Memory
            game = (SceNetAdhocctlGameNode *)malloc(sizeof(SceNetAdhocctlGameNode));
            
            // Allocated Game Node Memory
            if(game != NULL)
            {
                // Clear Memory
                memset(game, 0, sizeof(SceNetAdhocctlGameNode));
                
                // Save Game Product ID
                game->game = data->game;
                
                // Link into Game List
                game->next = _db_game;
                if(_db_game != NULL) _db_game->prev = game;
                _db_game = game;
            }
        }
        
        // Game now available
        if(game != NULL)
        {
            // Save MAC
            user->resolver.mac = data->mac;
            
            // Save Nickname
            user->resolver.name = data->name;
            
            // Increase Player Count in Game Node
            game->playercount++;
            
            // Link Game to Player
            user->game = game;
            
            // Notify User
            uint8_t * ip = (uint8_t *)&user->resolver.ip;
            char safegamestr[10];
            memset(safegamestr, 0, sizeof(safegamestr));
            strncpy(safegamestr, game->game.data, PRODUCT_CODE_LENGTH);
            printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) started playing %s.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr);
            
            // Update Status Log
            update_status();
            
            // Leave Function
            return;
        }
    }
    
    // Invalid Packet Data
    else
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        printf("Invalid Login Packet Contents from %u.%u.%u.%u.\n", ip[0], ip[1], ip[2], ip[3]);
    }
    
    // Logout User - Out of Memory or Invalid Arguments
    logout_user(user);
}

/**
 * Logout User from Database
 * @param user User Node
 */
void logout_user(SceNetAdhocctlUserNode * user)
{
    if (is_tunnel(user)) {
        SceNetAdhocctlUserNode * * to_delete = NULL;
        for (SceNetAdhocctlUserNode * current = _db_user; current != NULL; current = current->next) {
            if (current->tunnel == user)
                arrput(to_delete, current);
        }
        for (int i = 0; i < arrlen(to_delete); ++i) {
            logout_user(to_delete[i]);
        }
        arrfree(to_delete);
    }

    // Disconnect from Group
    if(user->group != NULL) disconnect_user(user);

    // Unlink Leftside (Beginning)
    if(user->prev == NULL) _db_user = user->next;
    
    // Unlink Leftside (Other)
    else user->prev->next = user->next;
    
    // Unlink Rightside
    if(user->next != NULL) user->next->prev = user->prev;
    
    // Close Stream
    close(user->stream);
    
    // Playing User
    if(user->game != NULL)
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) stopped playing %s.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr);
        
        // Fix Game Player Count
        user->game->playercount--;
        
        // Empty Game Node
        if(user->game->playercount == 0)
        {
            // Unlink Leftside (Beginning)
            if(user->game->prev == NULL) _db_game = user->game->next;
            
            // Unlink Leftside (Other)
            else user->game->prev->next = user->game->next;
            
            // Unlink Rightside
            if(user->game->next != NULL) user->game->next->prev = user->game->prev;
            
            // Free Game Node Memory
            free(user->game);
        }
    }
    
    // Unidentified User
    else
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        printf("Dropped Connection to %u.%u.%u.%u.\n", ip[0], ip[1], ip[2], ip[3]);
    }
    
    // Free Memory
    free(user);
    
    // Fix User Counter
    _db_user_count--;
    
    // Update Status Log
    update_status();
}

/**
 * Free Database Memory
 */
void free_database(void)
{
    // There are users playing
    if(_db_user_count > 0)
    {
        // Send Shutdown Notice
        spread_message(NULL, SERVER_SHUTDOWN_MESSAGE);
    }
    
    // Iterate Users for Deletion
    SceNetAdhocctlUserNode * user = _db_user;
    while(user != NULL)
    {
        // Next User (for safe delete)
        SceNetAdhocctlUserNode * next = user->next;
        
        // Logout User
        logout_user(user);
        
        // Move Pointer
        user = next;
    }
}

int connect_tunnel(SceNetAdhocctlUserNode * tunnel, SceNetAdhocctlUserNode * peers, SceNetAdhocctlGameNode * game, SceNetAdhocctlConnectPacketS2T * packet)
{
    send(tunnel->stream, packet, sizeof(*packet), 0);
    SceNetAdhocctlPortPacketS2T port;
    SceNetAdhocctlPeerPacketS2T peer;
    port.base.opcode = OPCODE_PORTS;
    peer.base.opcode = OPCODE_PEERS;
    bool conversation = true;
    while (true)
    {
        uint8_t opcode;
        int recvresult = recv(tunnel->stream, tunnel->rx + tunnel->rxpos, sizeof(tunnel->rx) - tunnel->rxpos, 0);
        if (recvresult == 0 || (recvresult == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
        if (recvresult > 0 || tunnel->rxpos > 0)
        {
            if (recvresult > 0)
                tunnel->rxpos += recvresult;
            switch (tunnel->rx[0])
            {
                case OPCODE_END_OF_CONV:
                    puts("got opcode endofconv");
                    conversation = false;
                    break;
                case OPCODE_PORTS:
                    puts("got opcode ports");
                    struct Port *ports = get_ports(&game->game);
                    if (ports) {
                        for (int i = 0; i < arrlen(ports); ++i) {
                            port.protocol = ports[i].protocol;
                            port.port = ports[i].port;
                            send(tunnel->stream, &port, sizeof(port), 0);
                        }
                        arrfree(ports);
                    } else {
                        char productid[PRODUCT_CODE_LENGTH + 1];
                        strncpy(productid, game->game.data, PRODUCT_CODE_LENGTH);
                        productid[PRODUCT_CODE_LENGTH] = 0;
                        printf("WARN: no port info found for %s\n", productid);
                    }
                    opcode = OPCODE_PORTS_COMPLETE;
                    break;
                case OPCODE_PEERS:
                    puts("got opcode peers");
                    while (peers != NULL) {
                        if (peers->resolver.ip != tunnel->resolver.ip) {
                            peer.virt_ip = peers->virt_ip;
                            peer.pub_ip = ntohl(peers->resolver.ip);
                            send(tunnel->stream, &peer, sizeof(peer), 0);
                        }
                        peers = peers->group_next;
                    }
                    opcode = OPCODE_PEERS_COMPLETE;
                    break;
            }
            clear_user_rxbuf(tunnel, 1);
            if (!conversation) break;
            send(tunnel->stream, &opcode, 1, 0);
        }
    }
    return 0;
}

/**
 * Connect User to Game Group
 * @param user User Node
 * @param group Group Name
 */
void connect_user(SceNetAdhocctlUserNode * user, SceNetAdhocctlGroupName * group)
{
    // Group Name Check
    int valid_group_name = 1;
    {
        // Iterate Characters
        int i = 0; for(; i < ADHOCCTL_GROUPNAME_LEN && valid_group_name == 1; i++)
        {
            // End of Name
            if(group->data[i] == 0) break;
            
            // A - Z
            if(group->data[i] >= 'A' && group->data[i] <= 'Z') continue;
            
            // a - z
            if(group->data[i] >= 'a' && group->data[i] <= 'z') continue;
            
            // 0 - 9
            if(group->data[i] >= '0' && group->data[i] <= '9') continue;
            
            // Invalid Symbol
            valid_group_name = 0;
        }
    }
    
    // Valid Group Name
    if(valid_group_name == 1)
    {
        // User is disconnected
        if(user->group == NULL)
        {
            // Find Group in Game Node
            SceNetAdhocctlGroupNode * g = user->game->group;
            while(g != NULL && strncmp((char *)g->group.data, (char *)group->data, ADHOCCTL_GROUPNAME_LEN) != 0) g = g->next;
            
            // BSSID Packet
            SceNetAdhocctlConnectBSSIDPacketS2C bssid;
            
            // Set BSSID Opcode
            bssid.base.opcode = OPCODE_CONNECT_BSSID;
            
            // Set Default BSSID
            bssid.mac = user->resolver.mac;
            
            // No Group found
            if(g == NULL)
            {
                // Allocate Group Memory
                g = (SceNetAdhocctlGroupNode *)malloc(sizeof(SceNetAdhocctlGroupNode));
                
                // Allocated Group Memory
                if(g != NULL)
                {
                    // Clear Memory
                    memset(g, 0, sizeof(SceNetAdhocctlGroupNode));
                    
                    // Link Game Node
                    g->game = user->game;
                    
                    // Link Group Node
                    g->next = g->game->group;
                    if(g->game->group != NULL) g->game->group->prev = g;
                    g->game->group = g;
                    
                    // Copy Group Name
                    g->group = *group;
                    
                    // Increase Group Counter for Game
                    g->game->groupcount++;

                    g->virt_enabled = user->tunnel != NULL;
                }
            }
            
            // Group now available
            if((g != NULL) && ((g->virt_enabled && user->tunnel) || (!g->virt_enabled && !user->tunnel)))
            {
                if (g->virt_enabled)
                {
                    int l_idx = hmgeti(mac_map, mac_to_int(user->resolver.mac));
                    if (l_idx != -1)
                    {
                        uint32_t local_ip = mac_map[l_idx].value;
                        user->local_ip = local_ip;
                    }
                    int i;
                    for (i = 0; i < SUBNET_SIZE; ++i)
                    {
                        SceNetEtherAddr mac = virt_ips[i];
                        int j;
                        for (j = 0; j < ETHER_ADDR_LEN && !mac.data[j]; ++j);
                        if (j == ETHER_ADDR_LEN) break;
                    }
                    if (i < SUBNET_SIZE)
                    {
                        uint32_t virt_ip = SUBNET_BASE + i;
                        virt_ips[i] = user->resolver.mac;
                        user->virt_ip = virt_ip;
                        SceNetAdhocctlConnectPacketS2T packet;
                        packet.base.opcode = OPCODE_LISTEN;
                        packet.game = user->game->game;
                        packet.group = g->group;
                        packet.virt_ip = virt_ip;
                        packet.ip = ntohl(user->resolver.ip);
                        SceNetAdhocctlUserNode * peers = g->player;
                        while (peers != NULL)
                        {
                            if (peers->resolver.ip != user->resolver.ip)
                                send(peers->tunnel->stream, &packet, sizeof(packet), 0);
                            peers = peers->group_next;
                        }
                        packet.base.opcode = OPCODE_CONNECT;
                        packet.ip = user->local_ip;
                        if (connect_tunnel(user->tunnel, g->player, g->game, &packet))
                        {
                            printf("WARN: lost connection to tunnel ");
                            print_ip(user->resolver.ip);
                            puts(" during local device connect conversation.");
                            logout_user(user->tunnel);
                            return;
                        }
                    }
                }

                // Iterate remaining Group Players
                SceNetAdhocctlUserNode * peer = g->player;
                while(peer != NULL)
                {
                    // ips sent to peer, user
                    uint32_t ips[2];
                    if (g->virt_enabled)
                    {
                        if (user->resolver.ip == peer->resolver.ip)
                        {
                            ips[0] = htonl(user->local_ip);
                            ips[1] = htonl(peer->local_ip);
                        }
                        else
                        {
                            ips[0] = htonl(user->virt_ip);
                            ips[1] = htonl(peer->virt_ip);
                        }
                    }
                    else
                    {
                        ips[0] = user->resolver.ip;
                        ips[1] = peer->resolver.ip;
                    }

                    // Connect Packet
                    SceNetAdhocctlConnectPacketS2C packet;
                    
                    // Clear Memory
                    // memset(&packet, 0, sizeof(packet));
                    
                    // Set Connect Opcode
                    packet.base.opcode = OPCODE_CONNECT;
                    
                    // Set Player Name
                    packet.name = user->resolver.name;
                    
                    // Set Player MAC
                    packet.mac = user->resolver.mac;
                    
                    // Set Player IP
                    packet.ip = ips[0];

                    printf("Sent peer ");
                    print_ip(peer->resolver.ip);
                    printf(" with local ip ");
                    print_ip(peer->local_ip);
                    printf(" the ip ");
                    print_ip(ips[0]);
                    puts("");
                    // Send Data
                    send(peer->stream, &packet, sizeof(packet), 0);
                    
                    // Set Player Name
                    packet.name = peer->resolver.name;
                    
                    // Set Player MAC
                    packet.mac = peer->resolver.mac;
                    
                    // Set Player IP
                    packet.ip = ips[1];
                    
                    printf("Sent user ");
                    print_ip(user->resolver.ip);
                    printf(" with local ip ");
                    print_ip(user->local_ip);
                    printf(" the ip ");
                    print_ip(ips[1]);
                    puts("");
                    // Send Data
                    send(user->stream, &packet, sizeof(packet), 0);
                    
                    // Set BSSID
                    if(peer->group_next == NULL) bssid.mac = peer->resolver.mac;
                    
                    // Move Pointer
                    peer = peer->group_next;
                }
                
                // Link User to Group
                user->group_next = g->player;
                if(g->player != NULL) g->player->group_prev = user;
                g->player = user;
                
                // Link Group to User
                user->group = g;
                
                // Increase Player Count
                g->playercount++;
                
                // Send Network BSSID to User
                send(user->stream, &bssid, sizeof(bssid), 0);
                
                // Notify User
                uint8_t * ip = (uint8_t *)&user->resolver.ip;
                char safegamestr[10];
                memset(safegamestr, 0, sizeof(safegamestr));
                strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
                char safegroupstr[9];
                memset(safegroupstr, 0, sizeof(safegroupstr));
                strncpy(safegroupstr, (char *)user->group->group.data, ADHOCCTL_GROUPNAME_LEN);
                printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) joined %s group %s.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr, safegroupstr);

                // Update Status Log
                update_status();
                
                // Exit Function
                return;
            } // TODO: error message in else
        }
        
        // Already connected to another group
        else
        {
            // Notify User
            uint8_t * ip = (uint8_t *)&user->resolver.ip;
            char safegamestr[10];
            memset(safegamestr, 0, sizeof(safegamestr));
            strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
            char safegroupstr[9];
            memset(safegroupstr, 0, sizeof(safegroupstr));
            strncpy(safegroupstr, (char *)group->data, ADHOCCTL_GROUPNAME_LEN);
            char safegroupstr2[9];
            memset(safegroupstr2, 0, sizeof(safegroupstr2));
            strncpy(safegroupstr2, (char *)user->group->group.data, ADHOCCTL_GROUPNAME_LEN);
            printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) attempted to join %s group %s without disconnecting from %s first.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr, safegroupstr, safegroupstr2);
        }
    }
    
    // Invalid Group Name
    else
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        char safegroupstr[9];
        memset(safegroupstr, 0, sizeof(safegroupstr));
        strncpy(safegroupstr, (char *)group->data, ADHOCCTL_GROUPNAME_LEN);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) attempted to join invalid %s group %s.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr, safegroupstr);
    }
    
    // Invalid State, Out of Memory or Invalid Group Name
    logout_user(user);
}

/**
 * Disconnect User from Game Group
 * @param user User Node
 */
void disconnect_user(SceNetAdhocctlUserNode * user)
{
    // User is connected
    if(user->group != NULL)
    {
        // Unlink Leftside (Beginning)
        if(user->group_prev == NULL) user->group->player = user->group_next;
        
        // Unlink Leftside (Other)
        else user->group_prev->group_next = user->group_next;
        
        // Unlink Rightside
        if(user->group_next != NULL) user->group_next->group_prev = user->group_prev;
        
        // Fix Player Count
        user->group->playercount--;

        SceNetAdhocctlDisconnectPacketS2C tunnel_disc;
        if (user->group->virt_enabled)
        {
            virt_ips[user->virt_ip - SUBNET_BASE] = (SceNetEtherAddr){0};
            tunnel_disc.base.opcode = OPCODE_DISCONNECT;
        }
        
        // Iterate remaining Group Players
        SceNetAdhocctlUserNode * peer = user->group->player;
        while(peer != NULL)
        {
            uint32_t ip;
            if (user->group->virt_enabled)
            {
                if (user->resolver.ip == peer->resolver.ip)
                {
                    ip = htonl(user->local_ip);
                }
                else
                {
                    tunnel_disc.ip = user->virt_ip;
                    send(peer->tunnel->stream, &tunnel_disc, sizeof(tunnel_disc), 0);
                    tunnel_disc.ip = peer->virt_ip;
                    send(user->tunnel->stream, &tunnel_disc, sizeof(tunnel_disc), 0);
                    ip = htonl(user->virt_ip);
                }
            }
            else
            {
                ip = user->resolver.ip;
            }

            // Disconnect Packet
            SceNetAdhocctlDisconnectPacketS2C packet;
            
            // Clear Memory
            // memset(&packet, 0, sizeof(packet));
            
            // Set Disconnect Opcode
            packet.base.opcode = OPCODE_DISCONNECT;
            
            // Set User IP
            packet.ip = ip;
            
            // Send Data
            send(peer->stream, &packet, sizeof(packet), 0);
            
            // Move Pointer
            peer = peer->group_next;
        }
        
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        char safegroupstr[9];
        memset(safegroupstr, 0, sizeof(safegroupstr));
        strncpy(safegroupstr, (char *)user->group->group.data, ADHOCCTL_GROUPNAME_LEN);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) left %s group %s.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr, safegroupstr);
        
        // Empty Group
        if(user->group->playercount == 0)
        {
            // Unlink Leftside (Beginning)
            if(user->group->prev == NULL) user->group->game->group = user->group->next;
            
            // Unlink Leftside (Other)
            else user->group->prev->next = user->group->next;
            
            // Unlink Rightside
            if(user->group->next != NULL) user->group->next->prev = user->group->prev;
            
            // Free Group Memory
            free(user->group);
            
            // Decrease Group Counter in Game Node
            user->game->groupcount--;
        }
        
        // Unlink from Group
        user->group = NULL;
        user->group_next = NULL;
        user->group_prev = NULL;
        
        // Update Status Log
        update_status();
        
        // Exit Function
        return;
    }
    
    // Not in a game group
    else
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) attempted to leave %s group without joining one first.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr);
    }
    
    // Delete User
    logout_user(user);
}

/**
 * Send Game Group List
 * @param user User Node
 */
void send_scan_results(SceNetAdhocctlUserNode * user)
{
    // User is disconnected
    if(user->group == NULL)
    {
        // Iterate Groups
        SceNetAdhocctlGroupNode * group = user->game->group;
        for(; group != NULL; group = group->next)
        {
            // Scan Result Packet
            SceNetAdhocctlScanPacketS2C packet;
            
            // Clear Memory
            // memset(&packet, 0, sizeof(packet));
            
            // Set Opcode
            packet.base.opcode = OPCODE_SCAN;
            
            // Set Group Name
            packet.group = group->group;
            
            // Iterate Players in Network Group
            SceNetAdhocctlUserNode * peer = group->player;
            for(; peer != NULL; peer = peer->group_next)
            {
                // Found Network Founder
                if(peer->group_next == NULL)
                {
                    // Set Group Host MAC
                    packet.mac = peer->resolver.mac;
                }
            }
            
            // Send Group Packet
            send(user->stream, &packet, sizeof(packet), 0);
        }
        
        // Notify Player of End of Scan
        uint8_t opcode = OPCODE_SCAN_COMPLETE;
        send(user->stream, &opcode, 1, 0);
        
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) requested information on %d %s groups.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], user->game->groupcount, safegamestr);
        
        // Exit Function
        return;
    }
    
    // User in a game group
    else
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        char safegroupstr[9];
        memset(safegroupstr, 0, sizeof(safegroupstr));
        strncpy(safegroupstr, (char *)user->group->group.data, ADHOCCTL_GROUPNAME_LEN);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) attempted to scan for %s groups without disconnecting from %s first.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr, safegroupstr);
    }
    
    // Delete User
    logout_user(user);
}

/**
 * Spread Chat Message in P2P Network
 * @param user Sender User Node
 * @param message Chat Message
 */
void spread_message(SceNetAdhocctlUserNode * user, char * message)
{
    // Global Notice
    if(user == NULL)
    {
        // Iterate Players
        for(user = _db_user; user != NULL; user = user->next)
        {
            // Player has access to chat
            if(user->group != NULL)
            {
                // Chat Packet
                SceNetAdhocctlChatPacketS2C packet;
                
                // Clear Memory
                memset(&packet, 0, sizeof(packet));
                
                // Set Chat Opcode
                packet.base.base.opcode = OPCODE_CHAT;
                
                // Set Chat Message
                strcpy(packet.base.message, message);
                
                // Send Data
                send(user->stream, &packet, sizeof(packet), 0);
            }
        }
        
        // Prevent NULL Error
        return;
    }
    
    // User is connected
    else if(user->group != NULL)
    {
        // Broadcast Range Counter
        uint32_t counter = 0;
        
        // Iterate Group Players
        SceNetAdhocctlUserNode * peer = user->group->player;
        while(peer != NULL)
        {
            // Skip Self
            if(peer == user)
            {
                // Move Pointer
                peer = peer->group_next;
                
                // Continue Loop
                continue;
            }
            
            // Chat Packet
            SceNetAdhocctlChatPacketS2C packet;
            
            // Set Chat Opcode
            packet.base.base.opcode = OPCODE_CHAT;
            
            // Set Chat Message
            strcpy(packet.base.message, message);
            
            // Set Sender Nickname
            packet.name = user->resolver.name;
            
            // Send Data
            send(peer->stream, &packet, sizeof(packet), 0);
            
            // Move Pointer
            peer = peer->group_next;
            
            // Increase Broadcast Range Counter
            counter++;
        }
        
        // Message Sent
        if(counter > 0)
        {
            // Notify User
            uint8_t * ip = (uint8_t *)&user->resolver.ip;
            char safegamestr[10];
            memset(safegamestr, 0, sizeof(safegamestr));
            strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
            char safegroupstr[9];
            memset(safegroupstr, 0, sizeof(safegroupstr));
            strncpy(safegroupstr, (char *)user->group->group.data, ADHOCCTL_GROUPNAME_LEN);
            printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) sent \"%s\" to %d players in %s group %s.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], message, counter, safegamestr, safegroupstr);
        }
        
        // Exit Function
        return;
    }
    
    // User not in a game group
    else
    {
        // Notify User
        uint8_t * ip = (uint8_t *)&user->resolver.ip;
        char safegamestr[10];
        memset(safegamestr, 0, sizeof(safegamestr));
        strncpy(safegamestr, user->game->game.data, PRODUCT_CODE_LENGTH);
        printf("%s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u) attempted to send a text message without joining a %s group first.\n", (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3], safegamestr);
    }
    
    // Delete User
    logout_user(user);
}

/**
 * Get User State
 * @param user User Node
 */
int get_user_state(SceNetAdhocctlUserNode * user)
{
    // Timeout Status
    if((time(NULL) - user->last_recv) >= SERVER_USER_TIMEOUT && !is_tunnel(user)) return USER_STATE_TIMED_OUT;
    
    // Waiting Status
    if(user->game == NULL) return USER_STATE_WAITING;
    
    // Logged-In Status
    return USER_STATE_LOGGED_IN;
}

/**
 * Clear RX Buffer
 * @param user User Node
 * @param clear Number of Bytes to clear (-1 for all)
 */
void clear_user_rxbuf(SceNetAdhocctlUserNode * user, int clear)
{
    // Fix Clear Length
    if(clear == -1 || clear > user->rxpos) clear = user->rxpos;
    
    // Move Buffer
    memmove(user->rx, user->rx + clear, sizeof(user->rx) - clear);
    
    // Fix RX Buffer Pointer
    user->rxpos -= clear;
}

/**
 * Patch Game Product Code
 * @param product To-be-patched Product Code
 * @param from If the Product Code matches this...
 * @param to ... then change it to this one.
 */
void game_product_relink(SceNetAdhocctlProductCode * product, char * from, char * to)
{
    // Relink Region Code
    if(strncmp(product->data, from, PRODUCT_CODE_LENGTH) == 0) strncpy(product->data, to, PRODUCT_CODE_LENGTH);
}

/**
 * Game Product Override (used for mixing multi-region games)
 * @param product IN: Source Product OUT: Override Product
 */
void game_product_override(SceNetAdhocctlProductCode * product)
{
    // Safe Product Code
    char productid[PRODUCT_CODE_LENGTH + 1];
    
    // Prepare Safe Product Code
    strncpy(productid, product->data, PRODUCT_CODE_LENGTH);
    productid[PRODUCT_CODE_LENGTH] = 0;
    
    // Database Handle
    sqlite3 * db = NULL;
    
    // Open Database
    if(sqlite3_open(SERVER_DATABASE, &db) == SQLITE_OK)
    {
        // Crosslinked Flag
        int crosslinked = 0;
        
        // Exists Flag
        int exists = 0;
        
        // SQL Statements
        const char * sql = "SELECT id_to FROM crosslinks WHERE id_from=?;";
        const char * sql2 = "SELECT * FROM productids WHERE id=?;";
        const char * sql3 = "INSERT INTO productids(id, name) VALUES(?, ?);";
        
        // Prepared SQL Statement
        sqlite3_stmt * statement = NULL;
        
        // Prepare SQL Statement
        if(sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &statement, NULL) == SQLITE_OK)
        {
            // Bind SQL Statement Data
            if(sqlite3_bind_text(statement, 1, productid, strlen(productid), SQLITE_STATIC) == SQLITE_OK)
            {
                // Found Matching Row
                if(sqlite3_step(statement) == SQLITE_ROW)
                {
                    // Grab Crosslink ID
                    const char * crosslink = (const char *)sqlite3_column_text(statement, 0);
                    
                    // Crosslink Product Code
                    strncpy(product->data, crosslink, PRODUCT_CODE_LENGTH);
                    
                    // Log Crosslink
                    printf("Crosslinked %s to %s.\n", productid, crosslink);
                    
                    // Set Crosslinked Flag
                    crosslinked = 1;
                }
            }
            
            // Destroy Prepared SQL Statement
            sqlite3_finalize(statement);
        }
        
        // Not Crosslinked
        if(!crosslinked)
        {
            // Prepare SQL Statement
            if(sqlite3_prepare_v2(db, sql2, strlen(sql2) + 1, &statement, NULL) == SQLITE_OK)
            {
                // Bind SQL Statement Data
                if(sqlite3_bind_text(statement, 1, productid, strlen(productid), SQLITE_STATIC) == SQLITE_OK)
                {
                    // Found Matching Row
                    if(sqlite3_step(statement) == SQLITE_ROW)
                    {
                        // Set Exists Flag
                        exists = 1;
                    }
                }
                
                // Destroy Prepare SQL Statement
                sqlite3_finalize(statement);
            }
            
            // Game doesn't exist in Database
            if(!exists)
            {
                // Prepare SQL Statement
                if(sqlite3_prepare_v2(db, sql3, strlen(sql3) + 1, &statement, NULL) == SQLITE_OK)
                {
                    // Bind SQL Statement Data
                    if(sqlite3_bind_text(statement, 1, productid, strlen(productid), SQLITE_STATIC) == SQLITE_OK && sqlite3_bind_text(statement, 2, productid, strlen(productid), SQLITE_STATIC) == SQLITE_OK)
                    {
                        // Save Product ID to Database
                        if(sqlite3_step(statement) == SQLITE_DONE)
                        {
                            // Log Addition
                            printf("Added Unknown Product ID %s to Database.\n", productid);
                        }
                    }
                    
                    // Destroy Prepare SQL Statement
                    sqlite3_finalize(statement);
                }
            }
        }
        
        // Close Database
        sqlite3_close(db);
    }
}

struct Port *get_ports(SceNetAdhocctlProductCode * product) {
    struct Port *ports = NULL;
    sqlite3 * db = NULL;
    if (sqlite3_open(SERVER_DATABASE, &db) == SQLITE_OK)
    {
        const char * sql = "SELECT protocol, port FROM ports WHERE id=?;";
        sqlite3_stmt * statement = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) == SQLITE_OK)
        {
            if (sqlite3_bind_text(statement, 1, product->data, PRODUCT_CODE_LENGTH, SQLITE_STATIC) == SQLITE_OK)
            {
                while (sqlite3_step(statement) == SQLITE_ROW)
                {
                    const unsigned char *protocol_str = sqlite3_column_text(statement, 0);
                    int port = sqlite3_column_int(statement, 1);
                    uint8_t protocol;
                    if (!strncmp(protocol_str, "TCP", 3))
                        protocol = PROTOCOL_TCP;
                    else if (!strncmp(protocol_str, "UDP", 3))
                        protocol = PROTOCOL_UDP;
                    else {
                        printf("WARN: invalid protocol %s; setting to UDP\n", protocol_str);
                        protocol = PROTOCOL_UDP;
                    }
                    arrput(ports, ((struct Port){
                        .protocol = protocol,
                        .port = (uint16_t)port,
                    }));
                }
            }
            sqlite3_finalize(statement);
        }
        sqlite3_close(db);
    }
    return ports;
}
