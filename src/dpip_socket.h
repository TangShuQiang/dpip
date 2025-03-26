#ifndef __DPIP_SOCKET_H__
#define __DPIP_SOCKET_H__

#include "dpip_config.h"

#include <rte_ether.h>
#include <rte_hash.h>

#include <sys/socket.h>

// TCP状态
enum DPIP_TCP_STATUS
{
    DPIP_TCP_CLOSED = 0,        // 关闭
    DPIP_TCP_LISTEN,            // 监听
    DPIP_TCP_SYN_SENT,          // SYN已发送
    DPIP_TCP_SYN_RECEIVED,      // SYN已接收
    DPIP_TCP_ESTABLISHED,       // 已建立
    DPIP_TCP_FIN_WAIT_1,        // FIN_WAIT_1
    DPIP_TCP_FIN_WAIT_2,        // FIN_WAIT_2
    DPIP_TCP_CLOSE_WAIT,        // CLOSE_WAIT
    DPIP_TCP_CLOSING,           // CLOSING
    DPIP_TCP_LAST_ACK,          // LAST_ACK
    DPIP_TCP_TIME_WAIT,         // TIME_WAIT
};

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
    uint32_t src_ip;    // 源IP地址
    uint32_t dst_ip;    // 目的IP地址
    uint16_t src_port;  // 源端口
    uint16_t dst_port;  // 目的端口

    uint32_t seq;       // 序列号
    uint32_t ack;       // 确认号
    uint8_t data_off;   // 数据偏移, 4bit，单位为4字节
    uint8_t flags;      // TCP标志
    uint16_t rx_win;    // 接收窗口
    uint16_t tcp_urp;   // 紧急指针

    uint16_t length;    // 数据的长度   (小端序)
    uint8_t* data;      // 数据
};

// socket实体
struct socket_entry
{
    int32_t fd;                        // 文件描述符

    uint8_t protocol;                   // 协议类型

    union                               // 协议数据
    {           
        // UDP 实体数据
        struct udp_entry
        {
            uint32_t local_ip;              // 本地IP地址
            uint16_t local_port;            // 本地端口

            struct rte_ring* recv_ring;     // 接收缓冲区
            struct rte_ring* send_ring;     // 发送缓冲区
        }udp;

        // TCP 实体数据
        struct tcp_entry
        {
            uint32_t local_ip;              // 本地IP地址
            uint16_t local_port;            // 本地端口
            uint32_t remote_ip;             // 远程IP地址
            uint16_t remote_port;           // 远程端口

            struct
            {
                uint8_t* buf;               // 接收数据缓冲区
                uint32_t capacity;          // 缓冲区容量
                uint32_t size;              // 缓冲区大小
                uint32_t write_index;       // 写索引
                uint32_t read_index;        // 读索引
                
                struct rte_hash* recv_hash_table; // 乱序缓冲区
            } recv_info;

            struct
            {
                uint8_t* buf;               // 发送数据缓冲区
                uint32_t capacity;          // 缓冲区容量
                uint32_t size;              // 缓冲区大小
                uint32_t write_index;       // 写索引
                uint32_t read_index;        // 读索引

            }send_info;

            uint8_t nead_send_fin;          // 需要发送FIN标志

            uint8_t status;                 // TCP状态

            uint32_t send_next;             // 下一个发送序列号
            uint32_t send_una;              // 已发送但未确认区域的起始序列号

            uint32_t recv_next;             // 期待接收的下一个序列号


            uint32_t dup_ack_count;         // 重复确认计数

            uint16_t rx_win;                // 接收窗口

            struct socket_entry* syn_queue;      // 半连接队列
            struct socket_entry* accept_queue;   // 全连接队列
            uint32_t syn_queue_length;           // 半连接队列的长度
            uint32_t backlog;                    // 全连接队列的长度
            uint32_t current_syn_queue_length;   // 当前半连接队列的长度
            uint32_t current_accept_queue_length;    // 当前全连接队列的长度

            pthread_cond_t accept_queue_not_empty;   // 全连接队列非空条件变量
        }tcp;
    };

    struct socket_entry* prev;
    struct socket_entry* next;

    pthread_cond_t notfull;             // send_ring未满条件变量, 用于通知应用层可以继续发送数据
    pthread_cond_t notempty;            // recv_ring非空条件变量, 用于通知应用层可以继续接收数据
    pthread_mutex_t mutex;
};

// 查找半连接
struct socket_entry* get_syn_by_ip_port(struct socket_entry* listen_sock_entry
                                        , uint32_t local_ip
                                        , uint16_t local_port
                                        , uint32_t remote_ip
                                        , uint16_t remote_port);
// 查找全连接
struct socket_entry* get_accept_by_ip_port(struct socket_entry* listen_sock_entry
                                        , uint32_t local_ip
                                        , uint16_t local_port
                                        , uint32_t remote_ip
                                        , uint16_t remote_port);

struct socket_key
{
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;
};

// socket表
struct socket_table
{
    struct rte_hash* socket_hash_table;
    struct rte_hash* fd_hash_table;

    uint8_t fd_bitmap[MAX_FD_COUNT / 8];

    pthread_rwlock_t rwlock;
};

// 通过fd获取socket实体
struct socket_entry* get_socket_entry_by_fd(int32_t fd);

// 通过协议、IP地址和端口号获取socket实体
struct socket_entry* get_socket_entry_by_ip_port_protocol(uint8_t protocol
                                                        , uint32_t local_ip
                                                        , uint16_t local_port
                                                        , uint32_t remote_ip
                                                        , uint16_t remote_port);

// 获取socket表
struct socket_table* get_socket_table(void);

// 添加socket实体
void add_socket_entry(struct socket_entry* entry);

void add_socket_entry_fdkey(struct socket_entry* entry);

void add_socket_entry_socketkey(struct socket_entry* entry);

// 删除socket实体
void del_socket_entry(struct socket_entry* entry);

int dpip_socket(int domain
                , int type
                , __attribute__((unused)) int protocol);

int dpip_bind(int sockfd
            , const struct sockaddr* addr
            , __attribute__((unused)) socklen_t addrlen);

ssize_t dpip_sendto(int sockfd
                    , const void* buf
                    , size_t len
                    , __attribute__((unused)) int flags
                    , const struct sockaddr* dest_addr
                    , __attribute__((unused)) socklen_t addrlen);

ssize_t dpip_recvfrom(int sockfd
                    , void* buf
                    , size_t len
                    , __attribute__((unused)) int flags
                    , struct sockaddr* src_addr
                    , __attribute__((unused)) socklen_t* addrlen);

int dpip_close(int sockfd);

int dpip_listen(int sockfd
                , int backlog);

int dpip_accept(int sockfd
                , struct sockaddr* addr
                , __attribute__((unused)) socklen_t* addrlen);

ssize_t dpip_recv(int sockfd
                , void* buf
                , size_t len
                , __attribute__((unused)) int flags);

ssize_t dpip_send(int sockfd
                , const void* buf
                , size_t len
                , __attribute__((unused)) int flags);

#endif