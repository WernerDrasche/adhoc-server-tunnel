#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include "util.h"
#include "config.h"

in_addr_t resolve_hostname(const char *hostname) {
    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        printf("ERROR: failed to resolve hostname %s", hostname);
        herror(NULL);
        return 0;
    }
    in_addr_t addr = *(in_addr_t *)host->h_addr_list[0];
    printf("Resolving %s to ", hostname);
    print_ip(addr);
    puts("");
    return addr;
}

int set_recv_timeout(int socket, unsigned long usecs) {
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = usecs;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

void print_ip(uint32_t ip) {
    uint8_t arr[4];
    for (int i = 0; i < 4; ++i) {
        arr[i] = (uint8_t)(ip & 0xff);
        ip >>= 8;
    }
    printf("%d.%d.%d.%d", arr[3], arr[2], arr[1], arr[0]);
}

int create_udp_socket(in_addr_t ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd != -1)
    {
        enable_address_reuse(fd);
        change_blocking_mode(fd, 1);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ip;
        addr.sin_port = htons(port);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) return fd;
        else
        {
            perror("ERROR: Couldn't bind udp socket");
            close(fd);
        }
    }
    else perror("ERROR: Couldn't create udp socket");
    return -1;
}

int create_connected_socket(in_addr_t dest_ip, uint16_t dest_port, in_addr_t src_ip, uint16_t src_port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd != -1)
    {
        enable_address_reuse(fd);
        change_blocking_mode(fd, 1);
        struct sockaddr_in server;
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        if (src_ip) {
            server.sin_addr.s_addr = src_ip;
            server.sin_port = htons(src_port);
            if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) {
                perror("ERROR: Couldn't bind tcp socket");
                close(fd);
                return -1;
            }
        }
        server.sin_addr.s_addr = dest_ip;
        server.sin_port = htons(dest_port);
        int conn_result = connect(fd, (struct sockaddr *)&server, sizeof(server));
        if (conn_result != -1) {
            return fd;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
            int sel_result = select(fd + 1, NULL, &wfds, NULL, &tv);
            if (sel_result > 0) {
                printf("DEBUG: %i\n", fd);
                return fd;
            }
            else if (sel_result == 0) errno = ETIMEDOUT;
        }
        perror("ERROR: Couldn't connect tcp socket");
        close(fd);
    }
    else perror("ERROR: Couldn't create tcp socket");
    return -1;
}

int create_listen_socket(in_addr_t ip, uint16_t port)
{
    // Create Socket
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    // Created Socket
    if(fd != -1)
    {
        // Enable Address Reuse
        enable_address_reuse(fd);
        change_blocking_mode(fd, 1);

        // Prepare Local Address Information
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = ip;
        local.sin_port = htons(port);
        
        // Bind Local Address to Socket
        int bindresult = bind(fd, (struct sockaddr *)&local, sizeof(local));
        
        // Bound Local Address to Socket
        if(bindresult != -1)
        {
            // Switch Socket into Listening Mode
            listen(fd, SERVER_LISTEN_BACKLOG);
            
            // Return Socket
            return fd;
        }
        
        // Notify User
        else printf("%s: bind returned %d.\n", __func__, bindresult);
        
        // Close Socket
        close(fd);
    }
    
    // Notify User
    else printf("%s: socket returned %d.\n", __func__, fd);
    
    // Return Error
    return -1;
}

void enable_address_reuse(int fd)
{
    // Enable Value
    int on = 1;
    
    // Enable Port Reuse
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

void change_blocking_mode(int fd, int nonblocking)
{
    // Change to Non-Blocking Mode
    if(nonblocking) fcntl(fd, F_SETFL, O_NONBLOCK);

    // Change to Blocking Mode
    else
    {
        // Get Flags
        int flags = fcntl(fd, F_GETFL);

        // Remove Non-Blocking Flag
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
}
