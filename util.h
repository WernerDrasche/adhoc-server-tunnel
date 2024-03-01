#include <netinet/in.h>
#include <stdint.h>

#define mac_to_int(mac) (*(uint64_t *)(void *)&(uint8_t[8]){0, 0, mac.data[5], mac.data[4], mac.data[3], mac.data[2], mac.data[1], mac.data[0]})
#define set_mac(mac, m5, m4, m3, m2, m1, m0) {mac.data[0]=m5;mac.data[1]=m4;mac.data[2]=m3;mac.data[3]=m2;mac.data[4]=m1;mac.data[5]=m0;}
#define ip_to_int(a3, a2, a1, a0) (((a3) << 24) + ((a2) << 16) + ((a1) << 8) + (a0))
#define connkey(ip, loc, rem) (((uint64_t)(ip) << 32) + ((uint64_t)(loc) << 16) + (uint64_t)(rem))
#define is_virt_ip(ip) ((ip) >= SUBNET_BASE && (ip) < SUBNET_BASE + SUBNET_SIZE)

int set_recv_timeout(int socket, unsigned long secs);

void print_ip(uint32_t ip);

int create_udp_socket(in_addr_t ip, uint16_t port);

/**
 * Create Port-Bound Listening Socket
 * @param ip IPv4 Address (in network byte order)
 * @param port TCP Port
 * @return Socket Descriptor
 */
int create_listen_socket(in_addr_t ip, uint16_t port);

/**
 * Create Port-Bound Connected Socket
 * @param ip IPv4 Address (in network byte order)
 * @param port TCP Port
 * @return Socket Descriptor
 */
int create_connected_socket(in_addr_t ip, uint16_t port);

/**
 * Enable Address Reuse on Socket
 * @param fd Socket
 */
void enable_address_reuse(int fd);

/**
 * Change Socket Blocking Mode
 * @param fd Socket
 * @param nonblocking 1 for Nonblocking, 0 for Blocking
 */
void change_blocking_mode(int fd, int nonblocking);
