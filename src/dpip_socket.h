#ifndef __DPIP_SOCKET_H__
#define __DPIP_SOCKET_H__

#include "dpip_config.h"

#include <rte_ether.h>

#include <sys/socket.h>

// UDP 数据报
struct udp_datagram
{
    uint32_t src_ip;    // 源IP地址
    uint32_t dst_ip;    // 目的IP地址
    uint16_t src_port;  // 源端口
    uint16_t dst_port;  // 目的端口

    uint16_t length;    // 数据的长度   (小端序)
    uint8_t* data;      // 数据
};

// TCP 报文段
struct tcp_segment
{

};

// UDP 实体数据
struct udp_entry
{
    uint32_t local_ip;              // 本地IP地址
    uint16_t local_port;            // 本地端口

    struct rte_ring* recv_ring;     // 接收缓冲区
    struct rte_ring* send_ring;     // 发送缓冲区
};

// TCP 实体数据
struct tcp_entry
{

};

// socket实体
struct socket_entry
{
    uint32_t fd;                        // 文件描述符

    uint8_t protocol;                   // 协议类型

    union
    {                             // 相关实体数据
        struct udp_entry udp;
        struct tcp_entry tcp;
    };

    struct socket_entry* prev;
    struct socket_entry* next;

    pthread_cond_t notfull;
    pthread_cond_t notempty;
    pthread_mutex_t mutex;
};

// socket表
struct socket_table
{
    struct socket_entry* head;

    uint8_t fd_bitmap[MAX_FD_COUNT / 8];

    pthread_rwlock_t rwlock;
};

// 通过fd获取socket实体
struct socket_entry* get_socket_entry_by_fd(uint32_t fd);

// 通过协议、IP地址和端口号获取socket实体
struct socket_entry* get_socket_entry_by_ip_port_protocol(uint8_t protocol
                                                        , uint32_t local_ip
                                                        , uint16_t local_port
                                                        , __attribute__((unused)) uint32_t remote_ip
                                                        , __attribute__((unused)) uint16_t remote_port);

// 获取socket表
struct socket_table* get_socket_table(void);

// 添加socket实体
void add_socket_entry(struct socket_entry* entry);

// 删除socket实体
void del_socket_entry(struct socket_entry* entry);

int dpip_socket(__attribute__((unused)) int domain
                , int type
                , __attribute__((unused)) int protocol);

int dpip_bind(int sockfd
            , const struct sockaddr* addr
            , __attribute__((unused)) socklen_t addrlen);

int dpip_sendto(int sockfd
                , const void* buf
                , size_t len
                , __attribute__((unused)) int flags
                , const struct sockaddr* dest_addr
                , __attribute__((unused)) socklen_t addrlen);

int dpip_recvfrom(int sockfd
                , void* buf
                , size_t len
                , __attribute__((unused)) int flags
                , struct sockaddr* src_addr
                , __attribute__((unused)) socklen_t* addrlen);

int dpip_close(int sockfd);


#endif