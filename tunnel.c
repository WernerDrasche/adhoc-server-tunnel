#include <stdint.h>
#define STB_DS_IMPLEMENTATION
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "stb_ds.h"
#include "packets.h"
#include "util.h"
#include "config.h"
#include "tunnel.h"

#define log(stmts) {pthread_mutex_lock(&log_lock); stmts; pthread_mutex_unlock(&log_lock);}

const char *const UDP_STR = "UDP";
const char *const TCP_STR = "TCP";

struct ThreadGroupInfo thread_groups[SUBNET_SIZE] = {0};
// for groups or tunnels
pthread_rwlock_t deletion;
pthread_mutex_t log_lock;
uint32_t local_ips[SUBNET_SIZE] = {0};
volatile bool running = true;
struct Game *games = NULL;
size_t current_game = -1;
SceNetAdhocctlGroupName current_group = {0};

void print_header(struct Header *header, bool dest_is_local) {
    printf("(");
    print_ip(header->src_ip);
    if (!dest_is_local && is_virt_ip(header->src_ip)) {
        printf("[");
        print_ip(local_ips[header->src_ip - SUBNET_BASE]);
        printf("]");
    }
    printf(":%d -> ", header->src_port);
    print_ip(header->dest_ip);
    if (dest_is_local && is_virt_ip(header->dest_ip)) {
        printf("[");
        print_ip(local_ips[header->dest_ip - SUBNET_BASE]);
        printf("]");
    }
    printf(":%d)", header->dest_port);
}

void print_thread(struct ThreadInfo *info) {
    printf("%s(", info->protocol == PROTOCOL_TCP ? TCP_STR : UDP_STR);
    print_ip(info->src_ip);
    printf(":%d -> ", info->src_port);
    print_ip(info->common->dest_ip);
    printf(":%d)", info->dest_port);
}

void print_game(struct Game *game) {
    char *product_code = malloc(PRODUCT_CODE_LENGTH + 1);
    strncpy(product_code, game->game.data, PRODUCT_CODE_LENGTH);
    product_code[PRODUCT_CODE_LENGTH] = 0;
    printf("Game %s {\n", product_code);
    struct Port *ports = game->ports;
    for (int i = 0; i < arrlen(ports); ++i) {
        struct Port *port = &ports[i];
        const char *prot_str = port->protocol == PROTOCOL_TCP ? TCP_STR : UDP_STR;
        printf("  %s %d\n", prot_str, port->port);
    }
    printf("}\n");
    free(product_code);
}

void interrupt(int sig) {
    puts("Shutting down... please wait.");
    for (int i = 0; i < SUBNET_SIZE; ++i) {
        struct ThreadGroupInfo *thread_group = &thread_groups[i];
        if (thread_group->dest_ip == 0) continue;
        thread_group->tunnel->stop = true;
    }
    running = false;
}

void unreachable() {
    printf("FATAL: reached unreachable state");
    exit(EXIT_FAILURE);
}

void clear_rxbuf(struct ReceiveBuffer *rx, int clear) {
    printf("clearing %d bytes and rxpos = %lu\n", clear, rx->pos);
    if(clear == -1 || clear > rx->pos) {
        puts("FUCK");
        clear = rx->pos;
    }
    memmove(rx->buf, rx->buf + clear, rx->pos - clear);
    rx->pos -= clear;
    printf("new rxpos = %lu\n", rx->pos);
}

// invariant: threads that have group rwlock also already have deletion read lock
// therefore it is unnecessary to write lock group
void delete_thread(struct ThreadInfo *info) {
    log({
        printf("Deleting thread ");
        print_thread(info);
        puts("");
    });
    info->stop = true;
    void *tmp;
    pthread_join(info->thread, &tmp);
    close(info->stream);
    struct ThreadInfo *current = info->common->info;
    if (current != info) {
        while (current->next != info) current = current->next;
        current->next = info->next;
    } else info->common->info = info->next;
    // check for the server thread which has no connection in the conn_map
    // otherwise the udp conn would be deleted by accident
    if (info->protocol != PROTOCOL_TCP || info->src_ip != 0) {
        uint64_t key = info->protocol == PROTOCOL_TCP ? connkey(info->src_ip, info->src_port, info->dest_port) : info->dest_port;
        struct ConnectionMapEntry *conn_map = info->common->conn_map;
        int i = hmgeti(conn_map, key);
        if (i != -1) {
            free(conn_map[i].value);
            hmdel(conn_map, key);
        }
    }
    log({
        printf("Successfully deleted thread ");
        print_thread(info);
        puts("");
    });
    free(info);
}

void delete_tunnel(struct Tunnel *tunnel) {
    log({
        printf("Deleting tunnel ");
        print_ip(tunnel->ip);
        puts("");
    });
    for (int i = 0; i < SUBNET_SIZE; ++i) {
        struct ThreadGroupInfo *thread_group = &thread_groups[i];
        if (thread_group->dest_ip == 0) continue;
        if (thread_group->tunnel == tunnel) {
            delete_group(thread_group);
        }
    }
    tunnel->stop = true;
    void *tmp;
    pthread_join(tunnel->thread, &tmp);
    close(tunnel->stream);
    log({
        printf("Successfully deleted tunnel ");
        print_ip(tunnel->ip);
        puts("");
    });
    free(tunnel);
}

void delete_group(struct ThreadGroupInfo *group_info) {
    log({
        printf("Deleting thread-group ");
        print_ip(group_info->dest_ip);
        puts("");
    });
    struct ThreadInfo **to_delete = NULL;
    for (struct ThreadInfo *current = group_info->info; current != NULL; current = current->next) {
        arrput(to_delete, current);
    }
    for (int i = 0; i < arrlen(to_delete); ++i) {
        delete_thread(to_delete[i]);
    }
    arrfree(to_delete);
    hmfree(group_info->conn_map);
    uint32_t dest_ip = group_info->dest_ip;
    // invalidate the group
    group_info->dest_ip = 0;
    struct Tunnel *tunnel = group_info->tunnel;
    if (--tunnel->refcount == 0) {
        tunnel->stop = true;
    }
    log({
        printf("Successfully deleted thread-group ");
        print_ip(dest_ip);
        puts("");
    });
}

bool handle_connect(int server, struct ReceiveBuffer *rx, SceNetAdhocctlConnectPacketS2T packet) {
    bool passive_mode = true;
    log({
        printf("Local device ");
        print_ip(packet.ip);
        printf(" was assigned virtual ip ");
        print_ip(packet.virt_ip);
        puts("");
    });
    local_ips[packet.virt_ip - SUBNET_BASE] = packet.ip;
    int i;
    for (i = 0; i < SUBNET_SIZE; ++i) {
        if (thread_groups[i].dest_ip == 0) continue;
        SceNetAdhocctlGroupName group = thread_groups[i].group;
        if (!strncmp(group.data, packet.group.data, ADHOCCTL_GROUPNAME_LEN)) break;
    }
    uint8_t opcode;
    // we are the first connection to the group from our ip
    if (i == SUBNET_SIZE) {
        passive_mode = false;
        current_group = packet.group;
        size_t num_games = arrlen(games);
        for (i = 0; i < num_games; ++i) {
            if (!strncmp(games[i].game.data, packet.game.data, PRODUCT_CODE_LENGTH)) break;
        }
        if (i == num_games) {
            arrput(games, ((struct Game){
                .game = packet.game,
                .ports = NULL,
            }));
            current_game = num_games; 
            opcode = OPCODE_PORTS;
            send(server, &opcode, 1, 0);
        } else {
            current_game = i;
        }
        opcode = OPCODE_PEERS;
        send(server, &opcode, 1, 0);
    }
    opcode = OPCODE_END_OF_CONV;
    send(server, &opcode, 1, 0);
    return passive_mode;
}

void *dmux_thread(void *arg) {
    struct Tunnel *tunnel = (struct Tunnel *)arg;
    int src = tunnel->stream;
    uint8_t *buffer = malloc(RECV_BUFSIZE);
    while (running && !tunnel->stop) {
        if (recvall(src, buffer, HEADER_SIZE, &tunnel->stop) == -1) break;
        struct Header header = *(struct Header *)buffer;
        uint64_t key = header.src_port ? *(uint64_t *)(buffer + 6) : header.dest_port;
        printf("key = %llu\n", key);
        uint16_t len = header.len;
        printf("len = %u\n", header.len);
        pthread_rwlock_rdlock(&deletion);
        struct ThreadGroupInfo *thread_group = &thread_groups[header.src_ip - SUBNET_BASE];
        log({
            printf("sending from ");
            print_ip(thread_group->dest_ip);
            puts("");
        });
        if (thread_group->dest_ip == 0) {
            log({
                printf("WARN: unsolicited connection attempt from ");
                print_ip(header.src_ip);
                puts("");
            });
            pthread_rwlock_unlock(&deletion);
            continue;
        }
        if (len == 0) {
            uint8_t code;
            if (recvall(src, &code, 1, &tunnel->stop) == -1) {
                pthread_rwlock_unlock(&deletion);
                break;
            }
            if (code == TCP_CONNECT) {
                uint32_t local_ip = local_ips[header.dest_ip - SUBNET_BASE];
                log({
                    printf("Creating TCP connection ");
                    print_header(&header, true);
                    puts("");
                });
                if (!local_ip) {
                    log({
                        printf("WARN: connection attempt to ");
                        print_ip(header.dest_ip);
                        printf(" which is not in local network\n");
                    });
                    pthread_rwlock_unlock(&deletion);
                    continue;
                }
                int stream = create_connected_socket(htonl(local_ip), header.dest_port);
                if (stream == -1) {
                    log({
                        printf("WARN: couldn't create connection to ");
                        print_ip(local_ip);
                        puts("");
                    });
                    pthread_rwlock_unlock(&deletion);
                    continue;
                }
                struct Connection *conn = malloc(sizeof(struct Connection));
                conn->stream = stream;
                pthread_mutex_init(&conn->lock, NULL);
                struct ThreadInfo *info = malloc(sizeof(struct ThreadInfo));
                *info = (struct ThreadInfo){
                    .common = thread_group,
                    .src_ip = header.dest_ip,
                    .src_port = header.dest_port,
                    .dest_port = header.src_port,
                    .protocol = PROTOCOL_TCP,
                    .stream = stream,
                };
                pthread_rwlock_wrlock(&thread_group->rwlock);
                hmput(thread_group->conn_map, key, conn);
                struct ThreadInfo *current = thread_group->info;
                if (current != NULL) {
                    while (current->next != NULL) current = current->next;
                    current->next = info;
                } else thread_group->info = info;
                pthread_rwlock_unlock(&thread_group->rwlock);
                pthread_create(&info->thread, NULL, mux_thread, info);
                log({
                    printf("TCP connection ");
                    print_thread(info);
                    printf(" successfully established\n");
                });
            } else if (code == TCP_DISCONNECT) {
                log({
                    printf("Closing TCP connection ");
                    print_header(&header, true);
                    puts("");
                });
                for (struct ThreadInfo *current = thread_group->info; current != NULL; current = current->next) {
                    if (current->src_ip == header.dest_ip &&
                        current->src_port == header.dest_port &&
                        current->dest_port == header.src_port)
                    {
                        log({
                            printf("Closed TCP connection ");
                            print_thread(current);
                            puts("");
                        });
                        current->stop = true;
                        break;
                    }
                }
            }
            pthread_rwlock_unlock(&deletion);
            continue;
        }
        if (recvall(src, buffer, header.len, &tunnel->stop) == -1) {
            pthread_rwlock_unlock(&deletion);
            break;
        }
        pthread_rwlock_rdlock(&thread_group->rwlock);
        int i = hmgeti(thread_group->conn_map, key);
        printf("i = %i\n", i);
        if (i != -1) {
            puts("HIIHHI");
            struct Connection *conn = thread_group->conn_map[i].value;
            pthread_mutex_lock(&conn->lock);
            puts("HAHAHAH");
            if (header.src_port) {
                log({
                    printf("Forwarding %d bytes over TCP via ", header.len);
                    print_header(&header, true);
                    puts("");
                });
                sendall(conn->stream, buffer, header.len, 0, 0);
            } else {
                uint32_t local_ip = local_ips[header.dest_ip - SUBNET_BASE];
                log({
                    printf("Forwarding %d bytes over UDP via ", header.len);
                    print_header(&header, true);
                    puts("");
                });
                if (local_ip != 0)
                    sendall(conn->stream, buffer, header.len, htonl(local_ip), header.dest_port);
                else {
                    log({
                        printf("WARN: couldn't send to non-existing local device ");
                        print_ip(local_ip);
                        puts("");
                    });
                }
            }
            pthread_mutex_unlock(&conn->lock);
        } else printf("WARN: connection does not exist.\n");
        pthread_rwlock_unlock(&thread_group->rwlock);
        pthread_rwlock_unlock(&deletion);
    }
    free(buffer);
    tunnel->stop = true;
    return NULL;
}

// this increments refcount
struct Tunnel *get_or_create_tunnel(int sock, uint32_t ip, enum TunnelCreationMode mode) {
    for (int i = 0; i < SUBNET_SIZE; ++i) {
        if (thread_groups[i].dest_ip == 0) continue;
        struct Tunnel *tunnel = thread_groups[i].tunnel;
        if (tunnel->ip == ip) {
            ++tunnel->refcount;
            return tunnel;
        }
    }
    int stream;
    struct sockaddr_in sockaddr = {0};
    socklen_t socklen = sizeof(sockaddr);
    switch (mode) {
        case MODE_CONNECT:
            log({
                printf("Connecting to tunnel ");
                print_ip(ip);
                puts("");
            });
            stream = create_connected_socket(htonl(ip), TUNNEL_PORT);
            change_blocking_mode(stream, 1);
            break;
        case MODE_LISTEN:
            log({
                printf("Accepting connection from tunnel ");
                print_ip(ip);
                puts("");
            });
            //TODO: set a timeout for listening
            stream = accept(sock, (struct sockaddr *)&sockaddr, &socklen);
            change_blocking_mode(stream, 1);
            break;
        default: unreachable();
    }
    if (stream == -1) {
        log({
            printf("ERROR: Couldn't create connection to tunnel ");
            print_ip(ip);
            perror(NULL);
        });
        return NULL;
    }
    struct Tunnel *tunnel = malloc(sizeof(struct Tunnel));
    *tunnel = (struct Tunnel){
        .ip = ip,
        .stream = stream,
        .refcount = 1,
    };
    pthread_mutex_init(&tunnel->lock, NULL);
    pthread_create(&tunnel->thread, NULL, dmux_thread, tunnel);
    log({
        printf("Tunnel ");
        print_ip(ip);
        printf(" created successfully\n");
    });
    return tunnel;
}

int recvall(int stream, void *data, size_t len, bool *stop) {
    size_t received = 0;
    while (received < len) {
        if (*stop) return -1;
        int n = recv(stream, data + received, len - received, 0);
        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n == -1 || n == 0) return -1;
        received += n;
    }
    return received;
}

int sendall(int stream, const void *data, size_t len, in_addr_t ip, uint16_t port) {
    struct sockaddr_in sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    if (ip) {
        memset(&sockaddr, 0, socklen);
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = ip;
        sockaddr.sin_port = htons(port);
    }
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (ip)
            n = sendto(stream, data + sent, len - sent, 0, (struct sockaddr *)&sockaddr, socklen);
        else
            n = send(stream, data + sent, len - sent, 0);
        if (n < 1) return n;
        sent += n;
    }
    return sent;
}

void *mux_thread(void *arg) {
    struct ThreadInfo *info = (struct ThreadInfo *)arg;
    int src = info->stream;
    int dest = info->common->tunnel->stream;
    uint8_t protocol = info->protocol;
    pthread_mutex_t *lock = &info->common->tunnel->lock;
    uint8_t *buffer = malloc(RECV_BUFSIZE + HEADER_SIZE);
    struct Header *header = (struct Header *)buffer;
    header->dest_ip = info->common->dest_ip;
    header->dest_port = info->dest_port;
    uint8_t *data = buffer + HEADER_SIZE;
    struct sockaddr_in sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    while (running && !info->stop) {
        int n = 0;
        if (info->protocol == PROTOCOL_TCP) {
            n = recv(src, data, RECV_BUFSIZE, 0);
            if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (n == -1 || n == 0) {
                log({
                    print_thread(info);
                    printf(" is forwarding a TCP disconnect message\n");
                });
                *data = TCP_DISCONNECT;
                header->len = 0;
                sendall(dest, buffer, 1 + HEADER_SIZE, 0, 0);
                break;
            }
            header->src_ip = info->src_ip;
            header->src_port = info->src_port;
        } else if (info->protocol == PROTOCOL_UDP) {
            n = recvfrom(src, data, RECV_BUFSIZE, 0, (struct sockaddr *)&sockaddr, &socklen);
            if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (n == -1 || n == 0) break;
            uint32_t local_ip = ntohl(sockaddr.sin_addr.s_addr);
            //local can be virt if emulator on same machine as tunnel
            if (!is_virt_ip(local_ip)) {
                //TODO: make a reverse hash map for this
                int i;
                for (i = 0; i < SUBNET_SIZE && local_ips[i] != local_ip; ++i);
                if (i == SUBNET_SIZE) {
                    log({
                        printf("UDP message from ");
                        print_ip(local_ip);
                        printf(" not in virtual network\n");
                    });
                    continue;
                }
                header->src_ip = i + SUBNET_BASE;
            } else header->src_ip = local_ip;
            header->src_port = 0; // indicates UDP
        }
        header->len = n;
        pthread_mutex_lock(lock);
        sendall(dest, buffer, n + HEADER_SIZE, 0, 0);
        log({
            printf("Forwarding %d bytes via ", n);
            print_header(header, false);
            puts("");
        });
        pthread_mutex_unlock(lock);
    }
    free(buffer);
    info->stop = true;
    return NULL;
}

void *mux_thread_server(void *arg) {
    struct ThreadInfo *info = (struct ThreadInfo *)arg;
    uint32_t dest_ip = info->common->dest_ip;
    uint16_t dest_port = info->dest_port;
    int dest = info->common->tunnel->stream;
    int server = create_listen_socket(htonl(dest_ip), dest_port);
    change_blocking_mode(server, 1);
    uint8_t ctrl_buf[HEADER_SIZE + 1];
    struct Header *header = (struct Header *)ctrl_buf;
    header->len = 0;
    header->dest_ip = dest_ip;
    header->dest_port = dest_port;
    ctrl_buf[HEADER_SIZE] = TCP_CONNECT;
    struct sockaddr_in sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    while (running && !info->stop) {
        int fd = accept(server, (struct sockaddr *)&sockaddr, &socklen);
        if (fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (fd == -1) break;
        change_blocking_mode(fd, 1);
        uint16_t src_port = ntohs(sockaddr.sin_port);
        uint32_t local_ip = ntohl(sockaddr.sin_addr.s_addr);
        puts("gugu");
        int i;
        for (i = 0; i < SUBNET_SIZE && local_ips[i] != local_ip; ++i);
        if (i == SUBNET_SIZE) {
            log({
                printf("WARN: Couldn't find virtual ip for ");
                print_ip(local_ip);
                puts("");
            });
            close(fd);
            continue;
        }
        puts("GAGA");
        uint32_t src_ip = SUBNET_BASE + i;
        header->src_ip = src_ip;
        header->src_port = src_port;
        puts("BLIBLI");
        log({
            print_thread(info);
            puts("BLUBLU");
            printf(" is forwarding TCP connect message ");
            print_header(header, false);
            puts("");
        });
        sendall(dest, ctrl_buf, HEADER_SIZE + 1, 0, 0);
        puts("KJLFJDKLJ");
        struct Connection *conn = malloc(sizeof(struct Connection));
        puts("FIFI");
        conn->stream = fd;
        pthread_mutex_init(&conn->lock, NULL);
        struct ThreadGroupInfo *thread_group = info->common;
        struct ThreadInfo *conn_info = malloc(sizeof(struct ThreadInfo));
        puts("FUFU");
        *conn_info = (struct ThreadInfo){
            .common = info->common,
            .src_ip = src_ip,
            .src_port = src_port,
            .dest_port = dest_port,
            .protocol = info->protocol,
            .stream = fd,
        };
        pthread_rwlock_wrlock(&thread_group->rwlock);
        hmput(thread_group->conn_map, connkey(src_ip, src_port, dest_port), conn);
        puts("baba");
        struct ThreadInfo *current = info->common->info;
        while (current->next != NULL) current = current->next;
        current->next = conn_info;
        pthread_rwlock_unlock(&thread_group->rwlock);
        pthread_create(&conn_info->thread, NULL, mux_thread, conn_info);
        log({
            printf("Successfully established TCP connection ");
            print_thread(conn_info);
            puts("");
        });
    }
    info->stop = true;
    return NULL;
}

void create_mux_threads(struct ThreadGroupInfo *thread_group) {
    struct Port *ports = games[thread_group->game].ports;
    struct ThreadInfo *prev = NULL;
    pthread_rwlock_wrlock(&thread_group->rwlock);
    for (int i = 0; i < arrlen(ports); ++i) {
        struct ThreadInfo *info = malloc(sizeof(struct ThreadInfo));
        *info = (struct ThreadInfo){
            .common = thread_group,
            .next = prev,
            .dest_port = ports[i].port,
            .protocol = ports[i].protocol,
        };
        if (info->protocol == PROTOCOL_TCP)
            pthread_create(&info->thread, NULL, mux_thread_server, info);
        else if (info->protocol == PROTOCOL_UDP) {
            info->src_port = 0;
            int stream = create_udp_socket(htonl(thread_group->dest_ip), info->dest_port);
            change_blocking_mode(stream, 1);
            if (stream == -1) {
                log({
                    printf("WARN: udp socket for ");
                    print_ip(thread_group->dest_ip);
                    puts("is fucked");
                });
                free(info);
                continue;
            }
            info->stream = stream;
            struct Connection *conn = malloc(sizeof(struct Connection));
            conn->stream = stream;
            pthread_mutex_init(&conn->lock, NULL);
            hmput(thread_group->conn_map, connkey(0, 0, info->dest_port), conn);
            pthread_create(&info->thread, NULL, mux_thread, info);
        } else {
            printf("WARN: unsupported protocol %d\n", info->protocol);
        };
        prev = info;
    }
    thread_group->info = prev;
    pthread_rwlock_unlock(&thread_group->rwlock);
}

void garbage_collect() {
    pthread_rwlock_wrlock(&deletion);
    for (int i = 0; i < SUBNET_SIZE; ++i) {
        struct ThreadGroupInfo *thread_group = &thread_groups[i];
        if (thread_group->dest_ip == 0) continue;
        if (thread_group->tunnel->stop) {
            delete_tunnel(thread_group->tunnel);
            continue;
        }
        for (struct ThreadInfo *current = thread_group->info; current != NULL; current = current->next) {
            if (current->stop)
                delete_thread(current);
        }
    }
    pthread_rwlock_unlock(&deletion);
}

int main() {
    pthread_rwlock_init(&deletion, NULL);
    pthread_mutex_init(&log_lock, NULL);
    signal(SIGINT, interrupt);
    signal(SIGTERM, interrupt);
    int server = create_connected_socket(inet_addr("192.168.178.124"), SERVER_PORT);
    if (server == -1) {
        printf("Couldn't connect to adhoc server.\n");
        exit(EXIT_FAILURE);
    }
    change_blocking_mode(server, 1);
    int peer_listener = create_listen_socket(INADDR_ANY, TUNNEL_PORT);
    if (peer_listener == -1) {
        printf("Couldn't create peer listening socket.\n");
        exit(EXIT_FAILURE);
    }
    uint8_t opcode = OPCODE_TUNNEL_LOGIN;
    send(server, &opcode, 1, 0);

    SceNetAdhocctlLocalPacketT2S mac_to_local;
    mac_to_local.base.opcode = OPCODE_LOCAL;
    set_mac(mac_to_local.mac, 0x70, 0x77, 0x81, 0xe5, 0x77, 0xe0);
    mac_to_local.local_ip = ip_to_int(192, 168, 178, 179);
    send(server, &mac_to_local, sizeof(mac_to_local), 0);
    set_mac(mac_to_local.mac, 0xcc, 0x58, 0x56, 0xd2, 0x55, 0xd3);
    mac_to_local.local_ip = ip_to_int(192, 168, 178, 37);
    send(server, &mac_to_local, sizeof(mac_to_local), 0);

    set_mac(mac_to_local.mac, 0xfc, 0x60, 0x1d, 0xbb, 0xf0, 0x7a);
    mac_to_local.local_ip = ip_to_int(192, 168, 178, 124);
    send(server, &mac_to_local, sizeof(mac_to_local), 0);
    set_mac(mac_to_local.mac, 0x78, 0xdc, 0x81, 0x94, 0x83, 0xbd);
    mac_to_local.local_ip = ip_to_int(192, 168, 178, 57);
    send(server, &mac_to_local, sizeof(mac_to_local), 0);

    struct ReceiveBuffer rx = {.buf = malloc(RECV_BUFSIZE), .pos = 0};
    bool passive_mode = true;
    while (running) {
        int result = recv(server, rx.buf + rx.pos, RECV_BUFSIZE - rx.pos, 0);
        if (result == 0 || (result == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) break;
        if (result > 0 || rx.pos > 0) {
            if (result > 0) {
                printf("received %d bytes\n", result);
                rx.pos += result;
            }
            if (rx.buf[0] == OPCODE_CONNECT) {
                puts("got a connect");
                SceNetAdhocctlConnectPacketS2T packet = *(SceNetAdhocctlConnectPacketS2T *)rx.buf;
                clear_rxbuf(&rx, sizeof(packet));
                passive_mode = handle_connect(server, &rx, packet);
            } else if (rx.buf[0] == OPCODE_PORTS) {
                SceNetAdhocctlPortPacketS2T packet = *(SceNetAdhocctlPortPacketS2T *)rx.buf;
                clear_rxbuf(&rx, sizeof(packet));
                if (packet.protocol == PROTOCOL_TCP) printf("TCP "); else printf("UDP ");
                printf("%d\n", packet.port);
                struct Port port = {
                    .protocol = packet.protocol,
                    .port = packet.port
                };
                arrput(games[current_game].ports, port);
            } else if (rx.buf[0] == OPCODE_PORTS_COMPLETE) {
                puts("finished ports");
                // we rely on the fact that ports will always finish before peers (enforced by handle_connect)
                clear_rxbuf(&rx, 1);
                print_game(&games[current_game]);
            } else if (rx.buf[0] == OPCODE_PEERS) {
                puts("got a peer");
                SceNetAdhocctlPeerPacketS2T packet = *(SceNetAdhocctlPeerPacketS2T *)rx.buf;
                clear_rxbuf(&rx, sizeof(packet));
                struct Tunnel *tunnel = get_or_create_tunnel(peer_listener, packet.pub_ip, MODE_CONNECT);
                if (tunnel == NULL) continue;
                struct ThreadGroupInfo *thread_group = &thread_groups[packet.virt_ip - SUBNET_BASE];
                *thread_group = (struct ThreadGroupInfo){
                    .group = current_group,
                    .game = current_game,
                    .tunnel = tunnel,
                    .dest_ip = packet.virt_ip,
                };
                pthread_rwlock_init(&thread_group->rwlock, NULL);
                create_mux_threads(thread_group);
            } else if (rx.buf[0] == OPCODE_PEERS_COMPLETE) {
                puts("finished peers");
                passive_mode = true;
                clear_rxbuf(&rx, 1);
            } else if (rx.buf[0] == OPCODE_LISTEN) {
                puts("got a listen");
                SceNetAdhocctlConnectPacketS2T packet = *(SceNetAdhocctlConnectPacketS2T *)rx.buf;
                clear_rxbuf(&rx, sizeof(packet));
                struct Tunnel *tunnel = get_or_create_tunnel(peer_listener, packet.ip, MODE_LISTEN);
                if (tunnel == NULL) continue;
                struct ThreadGroupInfo *thread_group = &thread_groups[packet.virt_ip - SUBNET_BASE];
                size_t game = 0;
                for (int i = 0; i < arrlen(games); ++i) {
                    if (!strncmp(games[i].game.data, packet.game.data, ADHOCCTL_GROUPNAME_LEN)) {
                        game = i;
                        break;
                    }
                }
                *thread_group = (struct ThreadGroupInfo){
                    .game = game,
                    .group = packet.group,
                    .tunnel = tunnel,
                    .dest_ip = packet.virt_ip,
                };
                pthread_rwlock_init(&thread_group->rwlock, NULL);
                create_mux_threads(thread_group);
            } else if (rx.buf[0] == OPCODE_DISCONNECT) {
                puts("got a disconnect");
                SceNetAdhocctlDisconnectPacketS2C packet = *(SceNetAdhocctlDisconnectPacketS2C *)rx.buf;
                clear_rxbuf(&rx, sizeof(packet));
                pthread_rwlock_wrlock(&deletion);
                struct ThreadGroupInfo *thread_group = &thread_groups[packet.ip - SUBNET_BASE];
                if (thread_group->dest_ip != 0)
                    delete_group(thread_group);
                pthread_rwlock_unlock(&deletion);
            } else {
                printf("Invalid opcode!\n");
                break;
            }
        } 
        if (passive_mode) {
            garbage_collect();
            usleep(1000);
        }
    }
    garbage_collect();
    for (int i = 0; i < arrlen(games); ++i) {
        arrfree(games[i].ports);
    }
    arrfree(games);
    close(server);
    close(peer_listener);
    free(rx.buf);
    puts("Shutdown complete");
    return EXIT_SUCCESS;
}
