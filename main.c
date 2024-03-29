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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

//#if !defined(__APPLE__)
//#include <malloc.h>
//#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "config.h"
#include "user.h"
#include "status.h"
#include "util.h"

// Server Status
int _status = 0;

// Function Prototypes
void interrupt(int sig);
int server_loop(int server);

/**
 * Server Entry Point
 * @param argc Number of Arguments
 * @param argv Arguments
 * @return OS Error Code
 */
int main(int argc, char * argv[])
{
    // Result
    int result = 0;
    
    // Create Signal Receiver for CTRL + C
    signal(SIGINT, interrupt);
    
    // Create Signal Receiver for kill / killall
    signal(SIGTERM, interrupt);
    
    // Create Listening Socket
    //int server = create_listen_socket(INADDR_ANY, SERVER_PORT);
    int server = create_listen_socket(inet_addr("0.0.0.0"), SERVER_PORT);
    
    // Created Listening Socket
    if(server != -1)
    {
        // Notify User
        printf("Listening for Connections on TCP Port %u.\n", SERVER_PORT);
        
        // Enter Server Loop
        result = server_loop(server);
        
        // Notify User
        printf("Shutdown complete.\n");
    }
    
    // Return Result
    return result;
}

/**
 * Server Shutdown Request Handler
 * @param sig Captured Signal
 */
void interrupt(int sig)
{
    // Notify User
    printf("Shutting down... please wait.\n");
    
    // Trigger Shutdown
    _status = 0;
}

/**
 * Server Main Loop
 * @param server Server Listening Socket
 * @return OS Error Code
 */
int server_loop(int server)
{
    // Set Running Status
    _status = 1;
    
    // Create Empty Status Logfile
    update_status();
    
    // Handling Loop
    while(_status == 1)
    {
        // Login Block
        {
            // Login Result
            int loginresult = 0;
            
            // Login Processing Loop
            do
            {
                // Prepare Address Structure
                struct sockaddr_in addr;
                socklen_t addrlen = sizeof(addr);
                memset(&addr, 0, sizeof(addr));
                
                // Accept Login Requests
                // loginresult = accept4(server, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
                
                // Alternative Accept Approach (some Linux Kernel don't support the accept4 Syscall... wtf?)
                loginresult = accept(server, (struct sockaddr *)&addr, &addrlen);
                if(loginresult != -1)
                {
                    // Switch Socket into Non-Blocking Mode
                    change_blocking_mode(loginresult, 1);
                }
                
                // Login User (Stream)
                if(loginresult != -1) login_user_stream(loginresult, addr.sin_addr.s_addr);
            } while(loginresult != -1);
        }
        
        // Receive Data from Users
        SceNetAdhocctlUserNode * user = _db_user;
        while(user != NULL)
        {
            // Next User (for safe delete)
            SceNetAdhocctlUserNode * next = user->next;
            
            // Receive Data from User
            int recvresult = recv(user->stream, user->rx + user->rxpos, sizeof(user->rx) - user->rxpos, 0);
            
            // Connection Closed or Timed Out
            if(recvresult == 0 || (recvresult == -1 && errno != EAGAIN && errno != EWOULDBLOCK) || get_user_state(user) == USER_STATE_TIMED_OUT)
            {
                // Logout User
                logout_user(user);
            }
            
            // Received Data (or leftovers in RX-Buffer)
            else if(recvresult > 0 || user->rxpos > 0)
            {
                // New Incoming Data
                if(recvresult > 0)
                {
                    // Move RX Pointer
                    user->rxpos += recvresult;
                    
                    // Update Death Clock
                    user->last_recv = time(NULL);
                }
                
                // Waiting for Login Packet
                if(get_user_state(user) == USER_STATE_WAITING)
                {
                    // Valid Opcode
                    if(user->rx[0] == OPCODE_LOGIN)
                    {
                        // Enough Data available
                        if(user->rxpos >= sizeof(SceNetAdhocctlLoginPacketC2S))
                        {
                            // Clone Packet
                            SceNetAdhocctlLoginPacketC2S packet = *(SceNetAdhocctlLoginPacketC2S *)user->rx;
                            
                            // Remove Packet from RX Buffer
                            clear_user_rxbuf(user, sizeof(SceNetAdhocctlLoginPacketC2S));
                            
                            // Login User (Data)
                            login_user_data(user, &packet);
                        }
                    }

                    // Tunnel Login Packet
                    else if (user->rx[0] == OPCODE_TUNNEL_LOGIN)
                    {
                        puts("got tunnel login");
                        user->tunnel = (SceNetAdhocctlUserNode *)1;
                        clear_user_rxbuf(user, 1);
                    }

                    else if (user->rx[0] == OPCODE_LOCAL)
                    {
                        //puts("got local");
                        add_local_addr(*(SceNetAdhocctlLocalPacketT2S *)user->rx);
                        clear_user_rxbuf(user, sizeof(SceNetAdhocctlLocalPacketT2S));
                    }

                    // Invalid Opcode
                    else
                    {
                        // Notify User
                        uint8_t * ip = (uint8_t *)&user->resolver.ip;
                        printf("Invalid Opcode 0x%02X in Waiting State from %u.%u.%u.%u.\n", user->rx[0], ip[0], ip[1], ip[2], ip[3]);
                        
                        // Logout User
                        logout_user(user);
                    }
                }
                
                // Logged-In User
                else if(get_user_state(user) == USER_STATE_LOGGED_IN)
                {
                    // Ping Packet
                    if(user->rx[0] == OPCODE_PING)
                    {
                        // Delete Packet from RX Buffer
                        clear_user_rxbuf(user, 1);
                    }
                    
                    // Group Connect Packet
                    else if(user->rx[0] == OPCODE_CONNECT)
                    {
                        // Enough Data available
                        if(user->rxpos >= sizeof(SceNetAdhocctlConnectPacketC2S))
                        {
                            // Cast Packet
                            SceNetAdhocctlConnectPacketC2S * packet = (SceNetAdhocctlConnectPacketC2S *)user->rx;
                            
                            // Clone Group Name
                            SceNetAdhocctlGroupName group = packet->group;
                            
                            // Remove Packet from RX Buffer
                            clear_user_rxbuf(user, sizeof(SceNetAdhocctlConnectPacketC2S));
                            
                            // Change Game Group
                            connect_user(user, &group);
                        }
                    }
                    
                    // Group Disconnect Packet
                    else if(user->rx[0] == OPCODE_DISCONNECT)
                    {
                        // Remove Packet from RX Buffer
                        clear_user_rxbuf(user, 1);
                        
                        // Leave Game Group
                        disconnect_user(user);
                    }
                    
                    // Network Scan Packet
                    else if(user->rx[0] == OPCODE_SCAN)
                    {
                        // Remove Packet from RX Buffer
                        clear_user_rxbuf(user, 1);
                        
                        // Send Network List
                        send_scan_results(user);
                    }
                    
                    // Chat Text Packet
                    else if(user->rx[0] == OPCODE_CHAT)
                    {
                        // Enough Data available
                        if(user->rxpos >= sizeof(SceNetAdhocctlChatPacketC2S))
                        {
                            // Cast Packet
                            SceNetAdhocctlChatPacketC2S * packet = (SceNetAdhocctlChatPacketC2S *)user->rx;
                            
                            // Clone Buffer for Message
                            char message[64];
                            memset(message, 0, sizeof(message));
                            strncpy(message, packet->message, sizeof(message) - 1);
                            
                            // Remove Packet from RX Buffer
                            clear_user_rxbuf(user, sizeof(SceNetAdhocctlChatPacketC2S));
                            
                            // Spread Chat Message
                            spread_message(user, message);
                        }
                    }
                    
                    // Invalid Opcode
                    else
                    {
                        // Notify User
                        uint8_t * ip = (uint8_t *)&user->resolver.ip;
                        printf("Invalid Opcode 0x%02X in Logged-In State from %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X - IP: %u.%u.%u.%u).\n", user->rx[0], (char *)user->resolver.name.data, user->resolver.mac.data[0], user->resolver.mac.data[1], user->resolver.mac.data[2], user->resolver.mac.data[3], user->resolver.mac.data[4], user->resolver.mac.data[5], ip[0], ip[1], ip[2], ip[3]);

                        // Logout User
                        logout_user(user);
                    }
                }
            }
            
            // Move Pointer
            user = next;
        }
        
        // Prevent needless CPU Overload (1ms Sleep)
        usleep(1000);
    }
    
    // Free User Database Memory
    free_database();
    
    // Close Server Socket
    close(server);
    
    // Return Success
    return 0;
}
