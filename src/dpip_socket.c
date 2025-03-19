#include "dpip_socket.h"

#include <arpa/inet.h>

static struct socket_table socket_table = { 0 };            // socket表

// 通过fd获取socket实体 
struct socket_entry* get_socket_entry_by_fd(uint32_t fd) {
    pthread_rwlock_rdlock(&socket_table.rwlock);
    struct socket_entry* entry = socket_table.head;
    while (entry) {
        if (entry->fd == fd) {
            return entry;
        }
        entry = entry->next;
    }
    pthread_rwlock_unlock(&socket_table.rwlock);
    return NULL;
}

// 通过协议、IP地址和端口号获取socket实体
struct socket_entry* get_socket_entry_by_ip_port_protocol(uint8_t protocol
                                                        , uint32_t local_ip
                                                        , uint16_t local_port
                                                        , __attribute__((unused)) uint32_t remote_ip
                                                        , __attribute__((unused)) uint16_t remote_port) {
    pthread_rwlock_rdlock(&socket_table.rwlock);
    struct socket_entry* entry = socket_table.head;
    while (entry) {
        if (entry->protocol == protocol) {
            if (entry->protocol == IPPROTO_UDP) {
                if (entry->udp.local_ip == local_ip && entry->udp.local_port == local_port) {
                    return entry;
                }
            } else if (entry->protocol == IPPROTO_TCP) {
                // TODO
            }
        }
        entry = entry->next;
    }
    pthread_rwlock_unlock(&socket_table.rwlock);
    return NULL;
}

// 获取socket表
struct socket_table* get_socket_table(void) {
    return &socket_table;
}