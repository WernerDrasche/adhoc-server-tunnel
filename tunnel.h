#include <netinet/in.h>
#include <pthread.h>
#include "packets.h"

#define RECV_BUFSIZE 1024

enum TunnelCreationMode {
    MODE_CONNECT,
    MODE_LISTEN,
};

struct Tunnel {
    int stream;
    pthread_mutex_t lock;
    uint32_t ip;
    unsigned int refcount;
    pthread_t thread;
    bool stop;
};

struct Port {
    uint8_t protocol;
    uint16_t port;
};

struct Game {
    SceNetAdhocctlProductCode game;
    struct Port *ports;
};

// for the dmux thread
struct ConnectionMapEntry {
    // (dest ip, local port, remote port)
    uint64_t key;
    struct Connection *value;
};

struct ThreadGroupInfo {
    struct Tunnel *tunnel;
    uint32_t dest_ip;
    SceNetAdhocctlGroupName group;
    size_t game;
    struct ConnectionMapEntry *conn_map;
    struct ThreadInfo *info;
    pthread_rwlock_t rwlock;
};

// linked list with info passed to the mux threads
struct ThreadInfo {
    // next in group
    struct ThreadInfo *next;
    struct ThreadGroupInfo *common;
    pthread_t thread;
    int stream;
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t protocol;
    bool stop;
};

#define TCP_CONNECT 0
#define TCP_DISCONNECT 1
struct Header {
    // len is the length of packet without header
    // if len is 0 then a control byte follows (like TCP connect)
    // remote port 0 indicates udp "connection"
    uint16_t len;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint16_t src_port;
} __attribute__((packed));

const size_t HEADER_SIZE = sizeof(struct Header);

struct Connection {
    int stream;
    pthread_mutex_t lock;
};

struct ReceiveBuffer {
    uint8_t *buf;
    size_t pos;
};

void interrupt(int sig);
void unreachable();
void clear_rxbuf(struct ReceiveBuffer *rx, int clear);
bool handle_connect(int server, struct ReceiveBuffer *rx, SceNetAdhocctlConnectPacketS2T packet);
void *dmux_thread(void *arg);
struct Tunnel *get_or_create_tunnel(int socket, uint32_t ip, enum TunnelCreationMode mode);
int recvall(int stream, void *data, size_t len, bool *stop);
int sendall(int stream, const void *data, size_t len, in_addr_t ip, uint16_t port);
void *mux_thread(void *arg);
void *mux_thread_server(void *arg);
void create_mux_threads(struct ThreadGroupInfo *thread_group);
void delete_tunnel(struct Tunnel *tunnel);
void delete_group(struct ThreadGroupInfo *group_info);
void delete_thread(struct ThreadInfo *info);
void garbage_collect();
