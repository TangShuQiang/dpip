#include "dpip_socket.h"
#include "dpip_logger.h"
#include "dpip_pkt.h"

#include <rte_malloc.h>
#include <rte_tcp.h>
#include <rte_jhash.h>

#include <arpa/inet.h>

static struct socket_table socket_table = { 0 };            // socket表

pthread_once_t once = PTHREAD_ONCE_INIT;

// 初始化socket表
static void init_socket_table(void) {
    static uint32_t count = 0;
    char name[32];
    sprintf(name, "socket_table_%d", count);
    struct rte_hash_parameters socket_hash_params = {
        .name = name,
        .entries = MAX_FD_COUNT,
        .key_len = sizeof(struct socket_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    socket_table.socket_hash_table = rte_hash_create(&socket_hash_params);
    if (!socket_table.socket_hash_table) {
        LOGGER_ERROR("rte_hash_create %s error", name);
        rte_exit(EXIT_FAILURE, "rte_hash_create error\n");
    }
    sprintf(name, "fd_bitmap_%d", count++);
    struct rte_hash_parameters fd_hash_params = {
        .name = name,
        .entries = MAX_FD_COUNT,
        .key_len = sizeof(int32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    socket_table.fd_hash_table = rte_hash_create(&fd_hash_params);
    if (!socket_table.fd_hash_table) {
        LOGGER_ERROR("rte_hash_create %s error", name);
        rte_exit(EXIT_FAILURE, "rte_hash_create error\n");
    }
    pthread_rwlock_init(&socket_table.rwlock, NULL);
}

// 查找半连接
struct socket_entry* get_syn_by_ip_port(struct socket_entry* listen_sock_entry
                                        , uint32_t local_ip
                                        , uint16_t local_port
                                        , uint32_t remote_ip
                                        , uint16_t remote_port) {
    pthread_mutex_lock(&listen_sock_entry->mutex);
    // 如果已经存在全连接，则返回NULL(不再接受新的半连接)
    struct socket_entry* entry = listen_sock_entry->tcp.accept_queue;
    while (entry) {
        if (entry->tcp.local_ip == local_ip
            && entry->tcp.local_port == local_port
            && entry->tcp.remote_ip == remote_ip
            && entry->tcp.remote_port == remote_port) {

            pthread_mutex_unlock(&listen_sock_entry->mutex);
            return NULL;
        }
        entry = entry->next;
    }
    // 不存在全连接，查找是否已经建立了半连接
    entry = listen_sock_entry->tcp.syn_queue;
    while (entry) {
        if (entry->tcp.local_ip == local_ip
            && entry->tcp.local_port == local_port
            && entry->tcp.remote_ip == remote_ip
            && entry->tcp.remote_port == remote_port) {

            pthread_mutex_unlock(&listen_sock_entry->mutex);
            return entry;
        }
        entry = entry->next;
    }
    // 队列已满, 不再接受新的半连接
    if (listen_sock_entry->tcp.current_syn_queue_length == listen_sock_entry->tcp.syn_queue_length) {
        LOGGER_WARN("syn queue is full");

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }
    // 创建新的半连接
    struct socket_entry* new_syn_entry = (struct socket_entry*) rte_malloc("socket_entry", sizeof(struct socket_entry), 0);
    if (!new_syn_entry) {
        LOGGER_WARN("rte_malloc socket_entry error");

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }
    memset(new_syn_entry, 0, sizeof(struct socket_entry));
    new_syn_entry->fd = -1;
    new_syn_entry->protocol = IPPROTO_TCP;
    new_syn_entry->tcp.local_ip = local_ip;
    new_syn_entry->tcp.local_port = local_port;
    new_syn_entry->tcp.remote_ip = remote_ip;
    new_syn_entry->tcp.remote_port = remote_port;
    new_syn_entry->tcp.status = DPIP_TCP_SYN_RECEIVED;

    pthread_cond_init(&new_syn_entry->notfull, NULL);
    pthread_cond_init(&new_syn_entry->notempty, NULL);
    pthread_mutex_init(&new_syn_entry->mutex, NULL);

    new_syn_entry->tcp.send_next = TCP_MAX_SEQ;

    new_syn_entry->tcp.recv_info.buf = (uint8_t*) rte_malloc("tcp_recv_buf", DPIP_TCP_RECV_BUF_SIZE, 0);
    if (!new_syn_entry->tcp.recv_info.buf) {
        LOGGER_WARN("rte_malloc tcp_recv_buf error");
        rte_free(new_syn_entry);

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }
    new_syn_entry->tcp.recv_info.capacity = DPIP_TCP_RECV_BUF_SIZE;

    static uint32_t count = 0;
    char name[32];
    sprintf(name, "recv_hash_table_%d", count++);
    struct rte_hash_parameters recv_hash_table_params = {
        .name = name,
        .entries = MAX_FD_COUNT,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    new_syn_entry->tcp.recv_info.recv_hash_table = rte_hash_create(&recv_hash_table_params);
    if (!new_syn_entry->tcp.recv_info.recv_hash_table) {
        LOGGER_WARN("rte_hash_create %s error", name);
        rte_free(new_syn_entry->tcp.recv_info.buf);
        rte_free(new_syn_entry);

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }

    new_syn_entry->tcp.send_info.buf = (uint8_t*) rte_malloc("tcp_send_buf", DPIP_TCP_SEND_BUF_SIZE, 0);
    if (!new_syn_entry->tcp.send_info.buf) {
        LOGGER_WARN("rte_malloc tcp_send_buf error");
        rte_free(new_syn_entry->tcp.recv_info.buf);
        rte_free(new_syn_entry);

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }
    new_syn_entry->tcp.send_info.capacity = DPIP_TCP_SEND_BUF_SIZE;

    new_syn_entry->next = listen_sock_entry->tcp.syn_queue;
    if (listen_sock_entry->tcp.syn_queue) {
        listen_sock_entry->tcp.syn_queue->prev = new_syn_entry;
    }
    listen_sock_entry->tcp.syn_queue = new_syn_entry;
    ++listen_sock_entry->tcp.current_syn_queue_length;

    pthread_mutex_unlock(&listen_sock_entry->mutex);
    return new_syn_entry;
}

// 查找全连接
struct socket_entry* get_accept_by_ip_port(struct socket_entry* listen_sock_entry
                                        , uint32_t local_ip
                                        , uint16_t local_port
                                        , uint32_t remote_ip
                                        , uint16_t remote_port) {
    pthread_mutex_lock(&listen_sock_entry->mutex);
    // 是否已经存在全连接
    struct socket_entry* entry = listen_sock_entry->tcp.accept_queue;
    while (entry) {
        if (entry->tcp.local_ip == local_ip
            && entry->tcp.local_port == local_port
            && entry->tcp.remote_ip == remote_ip
            && entry->tcp.remote_port == remote_port) {

            pthread_mutex_unlock(&listen_sock_entry->mutex);
            return entry;
        }
        entry = entry->next;
    }
    // 是否存在半连接
    entry = listen_sock_entry->tcp.syn_queue;
    while (entry) {
        if (entry->tcp.local_ip == local_ip
            && entry->tcp.local_port == local_port
            && entry->tcp.remote_ip == remote_ip
            && entry->tcp.remote_port == remote_port) {

            pthread_mutex_unlock(&listen_sock_entry->mutex);
            return entry;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&listen_sock_entry->mutex);
    return NULL;
}

// 通过fd获取socket实体 
struct socket_entry* get_socket_entry_by_fd(int32_t fd) {
    struct socket_table* table = get_socket_table();
    if (!table) {
        LOGGER_ERROR("socket_table is NULL");
        return NULL;
    }
    struct socket_entry* entry = NULL;
    // rte_smp_rmb();  // 读内存屏障
    pthread_rwlock_rdlock(&table->rwlock);
    rte_hash_lookup_data(table->fd_hash_table, &fd, (void**)&entry);
    pthread_rwlock_unlock(&table->rwlock);
    return entry;
}

// 通过协议、IP地址和端口号获取socket实体
struct socket_entry* get_socket_entry_by_ip_port_protocol(uint8_t protocol
                                                        , uint32_t local_ip
                                                        , uint16_t local_port
                                                        , uint32_t remote_ip
                                                        , uint16_t remote_port) {
    struct socket_table* table = get_socket_table();
    if (!table) {
        LOGGER_ERROR("socket_table is NULL");
        return NULL;
    }
    struct socket_key key;      // 内存对齐，sizeof(struct socket_key) = 16
    memset(&key, 0, sizeof(struct socket_key));
    key.protocol = protocol;
    key.local_ip = local_ip;
    key.local_port = local_port;
    key.remote_ip = remote_ip;
    key.remote_port = remote_port;
    struct socket_entry* entry = NULL;
    if (protocol == IPPROTO_UDP) {
        key.remote_ip = 0;
        key.remote_port = 0;
        pthread_rwlock_rdlock(&table->rwlock);
        rte_hash_lookup_data(table->socket_hash_table, &key, (void**)&entry);
        pthread_rwlock_unlock(&table->rwlock);
        return entry;
    } else if (protocol == IPPROTO_TCP) {
        pthread_rwlock_rdlock(&table->rwlock);
        rte_hash_lookup_data(table->socket_hash_table, &key, (void**)&entry);
        pthread_rwlock_unlock(&table->rwlock);
        if (entry) {
            return entry;
        }
        key.remote_ip = 0;
        key.remote_port = 0;
        pthread_rwlock_rdlock(&table->rwlock);
        rte_hash_lookup_data(table->socket_hash_table, &key, (void**)&entry);
        pthread_rwlock_unlock(&table->rwlock);
        if (entry && entry->tcp.status == DPIP_TCP_LISTEN) {
            return entry;
        }
        return NULL;
    }
    return NULL;
}

// 获取socket表
struct socket_table* get_socket_table(void) {
    if (pthread_once(&once, init_socket_table) != 0) {
        LOGGER_ERROR("pthread_once error");
        return NULL;
    }
    return &socket_table;
}

// 添加socket实体
void add_socket_entry(struct socket_entry* entry) {
    struct socket_table* table = get_socket_table();
    if (!table) {
        LOGGER_ERROR("socket_table is NULL");
        return;
    }
    pthread_rwlock_wrlock(&table->rwlock);
    int32_t fd_key = entry->fd;
    struct socket_key socket_key;
    memset(&socket_key, 0, sizeof(struct socket_key));
    if (entry->protocol == IPPROTO_UDP) {
        socket_key.protocol = entry->protocol;
        socket_key.local_ip = entry->udp.local_ip;
        socket_key.local_port = entry->udp.local_port;
        socket_key.remote_ip = 0;
        socket_key.remote_port = 0;
    } else if (entry->protocol == IPPROTO_TCP) {
        socket_key.protocol = entry->protocol;
        socket_key.local_ip = entry->tcp.local_ip;
        socket_key.local_port = entry->tcp.local_port;
        socket_key.remote_ip = entry->tcp.remote_ip;
        socket_key.remote_port = entry->tcp.remote_port;
    }
    rte_hash_add_key_data(table->fd_hash_table, &fd_key, entry);
    rte_hash_add_key_data(table->socket_hash_table, &socket_key, entry);
    pthread_rwlock_unlock(&table->rwlock);
}

void add_socket_entry_fdkey(struct socket_entry* entry) {
    struct socket_table* table = get_socket_table();
    if (!table) {
        LOGGER_ERROR("socket_table is NULL");
        return;
    }
    pthread_rwlock_wrlock(&table->rwlock);
    int32_t key = entry->fd;
    rte_hash_add_key_data(table->fd_hash_table, &key, entry);
    pthread_rwlock_unlock(&table->rwlock);
}

void add_socket_entry_socketkey(struct socket_entry* entry) {
    struct socket_table* table = get_socket_table();
    if (!table) {
        LOGGER_ERROR("socket_table is NULL");
        return;
    }
    pthread_rwlock_wrlock(&table->rwlock);
    struct socket_key key;
    memset(&key, 0, sizeof(struct socket_key));
    if (entry->protocol == IPPROTO_UDP) {
        key.protocol = entry->protocol;
        key.local_ip = entry->udp.local_ip;
        key.local_port = entry->udp.local_port;
        key.remote_ip = 0;
        key.remote_port = 0;
    } else if (entry->protocol == IPPROTO_TCP) {
        key.protocol = entry->protocol;
        key.local_ip = entry->tcp.local_ip;
        key.local_port = entry->tcp.local_port;
        key.remote_ip = entry->tcp.remote_ip;
        key.remote_port = entry->tcp.remote_port;
    }
    rte_hash_add_key_data(table->socket_hash_table, &key, entry);
    pthread_rwlock_unlock(&table->rwlock);
}

// 删除socket实体
void del_socket_entry(struct socket_entry* entry) {
    struct socket_table* table = get_socket_table();
    if (!table) {
        LOGGER_ERROR("socket_table is NULL");
        return;
    }
    int32_t fd_key = entry->fd;
    struct socket_key socket_key;
    if (entry->protocol == IPPROTO_UDP) {
        socket_key.protocol = entry->protocol;
        socket_key.local_ip = entry->udp.local_ip;
        socket_key.local_port = entry->udp.local_port;
        socket_key.remote_ip = 0;
        socket_key.remote_port = 0;
    } else if (entry->protocol == IPPROTO_TCP) {
        socket_key.protocol = entry->protocol;
        socket_key.local_ip = entry->tcp.local_ip;
        socket_key.local_port = entry->tcp.local_port;
        socket_key.remote_ip = entry->tcp.remote_ip;
        socket_key.remote_port = entry->tcp.remote_port;
    }
    pthread_rwlock_wrlock(&table->rwlock);
    rte_hash_del_key(table->fd_hash_table, &fd_key);
    rte_hash_del_key(table->socket_hash_table, &socket_key);

    // 回收文件描述符
    table->fd_bitmap[fd_key / 8] &= ~(1 << (fd_key % 8));

    pthread_rwlock_unlock(&table->rwlock);
}

// 从位图中获取一个空闲的文件描述符
static int get_free_fd_from_bitmap(void) {
    struct socket_table* table = get_socket_table();
    pthread_rwlock_wrlock(&table->rwlock);
    for (int i = 0; i < MAX_FD_COUNT / 8; ++i) {
        if (table->fd_bitmap[i] != 0xFF) {
            for (int j = 0; j < 8; ++j) {
                if (!(table->fd_bitmap[i] & (1 << j))) {
                    table->fd_bitmap[i] |= (1 << j);
                    pthread_rwlock_unlock(&table->rwlock);
                    return i * 8 + j;
                }
            }
        }
    }
    pthread_rwlock_unlock(&table->rwlock);
    return -1;
}

// 释放文件描述符
static void free_fd_to_bitmap(int fd) {
    struct socket_table* table = get_socket_table();
    pthread_rwlock_wrlock(&table->rwlock);
    socket_table.fd_bitmap[fd / 8] &= ~(1 << (fd % 8));
    pthread_rwlock_unlock(&table->rwlock);
}

int dpip_socket(int domain
                , int type
                , __attribute__((unused)) int protocol) {
    if (domain != AF_INET) {
        LOGGER_ERROR("only support AF_INET");
        return -1;
    }
    int fd = get_free_fd_from_bitmap();
    if (fd == -1) {
        LOGGER_ERROR("no free fd");
        return -1;
    }
    if (type == SOCK_DGRAM) {
        struct socket_entry* entry = (struct socket_entry*)rte_malloc("socket_entry", sizeof(struct socket_entry), 0);
        if (!entry) {
            LOGGER_ERROR("rte_malloc socket_entry error");
            free_fd_to_bitmap(fd);
            return -1;
        }
        memset(entry, 0, sizeof(struct socket_entry));
        entry->protocol = IPPROTO_UDP;
        entry->fd = fd;
        pthread_cond_init(&entry->notfull, NULL);
        pthread_cond_init(&entry->notempty, NULL);
        pthread_mutex_init(&entry->mutex, NULL);

        struct udp_entry* udp = &entry->udp;
        udp->local_ip = 0;
        udp->local_port = 0;
        // 给ring命名
        char ring_name[32];
        static int udp_ring_id = 0;
        snprintf(ring_name, sizeof(ring_name), "udp_recv_ring_id_%d", udp_ring_id);
        udp->recv_ring = rte_ring_create(ring_name, UDP_RECV_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!udp->recv_ring) {
            LOGGER_ERROR("rte_ring_create %s error", ring_name);
            rte_free(entry);
            free_fd_to_bitmap(fd);
            return -1;
        }
        snprintf(ring_name, sizeof(ring_name), "udp_send_ring_id_%d", udp_ring_id++);
        udp->send_ring = rte_ring_create(ring_name, UDP_SEND_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!udp->send_ring) {
            LOGGER_ERROR("rte_ring_create %s error", ring_name);
            rte_ring_free(udp->recv_ring);
            rte_free(entry);
            free_fd_to_bitmap(fd);
            return -1;
        }
        add_socket_entry_fdkey(entry);
    } else if (type == SOCK_STREAM) {
        struct socket_entry* entry = (struct socket_entry*)rte_malloc("socket_entry", sizeof(struct socket_entry), 0);
        if (!entry) {
            LOGGER_ERROR("rte_malloc socket_entry error");
            free_fd_to_bitmap(fd);
            return -1;
        }
        memset(entry, 0, sizeof(struct socket_entry));
        entry->protocol = IPPROTO_TCP;
        entry->fd = fd;
        pthread_cond_init(&entry->notfull, NULL);
        pthread_cond_init(&entry->notempty, NULL);
        pthread_mutex_init(&entry->mutex, NULL);

        struct tcp_entry* tcp = &entry->tcp;
        tcp->local_ip = 0;
        tcp->local_port = 0;
        tcp->remote_ip = 0;
        tcp->remote_port = 0;
        tcp->status = DPIP_TCP_CLOSED;
        pthread_cond_init(&tcp->accept_queue_not_empty, NULL);
        tcp->syn_queue = NULL;
        tcp->accept_queue = NULL;
        tcp->syn_queue_length = DPIP_TCP_SYN_QUEUE_MAX_LENGTH;
        tcp->backlog = 0;
        tcp->current_syn_queue_length = 0;
        tcp->current_accept_queue_length = 0;
        add_socket_entry_fdkey(entry);
    }
    return fd;
}

int dpip_bind(int sockfd
            , const struct sockaddr* addr
            , __attribute__((unused)) socklen_t addrlen) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol == IPPROTO_UDP) {
        const struct sockaddr_in* in_addr = (const struct sockaddr_in*)addr;
        entry->udp.local_ip = in_addr->sin_addr.s_addr;
        entry->udp.local_port = in_addr->sin_port;
    } else if (entry->protocol == IPPROTO_TCP) {
        const struct sockaddr_in* in_addr = (const struct sockaddr_in*)addr;
        entry->tcp.local_ip = in_addr->sin_addr.s_addr;
        entry->tcp.local_port = in_addr->sin_port;
    }
    pthread_mutex_unlock(&entry->mutex);
    add_socket_entry_socketkey(entry);
    return 0;
}

ssize_t dpip_sendto(int sockfd
                    , const void* buf
                    , size_t len
                    , __attribute__((unused)) int flags
                    , const struct sockaddr* dest_addr
                    , __attribute__((unused)) socklen_t addrlen) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol != IPPROTO_UDP) {
        LOGGER_WARN("dpip_sendto only support UDP protocol");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    const struct sockaddr_in* in_addr = (const struct sockaddr_in*)dest_addr;
    uint32_t dst_ip = in_addr->sin_addr.s_addr;
    uint16_t dst_port = in_addr->sin_port;
    struct udp_datagram* datagram = (struct udp_datagram*)rte_malloc("udp_datagram", sizeof(struct udp_datagram), 0);
    if (!datagram) {
        LOGGER_WARN("rte_malloc udp_datagram error");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    datagram->src_ip = entry->udp.local_ip;
    datagram->dst_ip = dst_ip;
    datagram->src_port = entry->udp.local_port;
    datagram->dst_port = dst_port;
    datagram->length = len;
    datagram->data = (uint8_t*)rte_malloc("udp_data", len, 0);
    if (!datagram->data) {
        LOGGER_WARN("rte_malloc udp_data error");
        rte_free(datagram);
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    rte_memcpy(datagram->data, buf, len);
    while (rte_ring_mp_enqueue(entry->udp.send_ring, datagram) != 0) {
        pthread_cond_wait(&entry->notfull, &entry->mutex);
    }
    pthread_mutex_unlock(&entry->mutex);
    return len;
}

ssize_t dpip_recvfrom(int sockfd
                    , void* buf
                    , size_t len
                    , __attribute__((unused)) int flags
                    , struct sockaddr* src_addr
                    , __attribute__((unused)) socklen_t* addrlen) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }

    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol != IPPROTO_UDP) {
        LOGGER_WARN("dpip_recvfrom only support UDP protocol");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    struct udp_datagram* datagram = NULL;
    while (rte_ring_mc_dequeue(entry->udp.recv_ring, (void**)&datagram) != 0) {
        pthread_cond_wait(&entry->notempty, &entry->mutex);
    }
    pthread_mutex_unlock(&entry->mutex);
    if (src_addr) {
        struct sockaddr_in* in_addr = (struct sockaddr_in*)src_addr;
        in_addr->sin_family = AF_INET;
        in_addr->sin_addr.s_addr = datagram->src_ip;
        in_addr->sin_port = datagram->src_port;
    }
    if (len > datagram->length) {
        len = datagram->length;
        rte_memcpy(buf, datagram->data, len);
    }
    rte_free(datagram->data);
    rte_free(datagram);
    return len;
}

int dpip_close(int sockfd) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol == IPPROTO_UDP) {
        rte_ring_free(entry->udp.recv_ring);
        rte_ring_free(entry->udp.send_ring);

        del_socket_entry(entry);
        rte_free(entry);
        pthread_mutex_unlock(&entry->mutex);
        return 0;
    } 
    
    if (entry->protocol == IPPROTO_TCP) {
        if (entry->tcp.status == DPIP_TCP_ESTABLISHED) {
            entry->tcp.status = DPIP_TCP_FIN_WAIT_1;
        } else if (entry->tcp.status == DPIP_TCP_CLOSE_WAIT) {
            entry->tcp.status = DPIP_TCP_LAST_ACK;
            entry->tcp.nead_send_fin = 1;
        } else if (entry->tcp.status == DPIP_TCP_LISTEN) {
            // 释放半连接队列
            struct socket_entry* syn_entry = entry->tcp.syn_queue;
            while (syn_entry) {
                struct socket_entry* next = syn_entry->next;
                rte_free(syn_entry);
                syn_entry = next;
            }
            struct socket_entry* accept_entry = entry->tcp.accept_queue;
            while (accept_entry) {
                struct socket_entry* next = accept_entry->next;
                rte_free(accept_entry);
                accept_entry = next;
            }
        }
        pthread_mutex_unlock(&entry->mutex);
        return 0;
    }
    pthread_mutex_unlock(&entry->mutex);
    return -1;
}

int dpip_listen(int sockfd
                , int backlog) {
    if (backlog <= 0) {
        LOGGER_WARN("backlog must be greater than 0");
        return -1;
    }
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_listen only support TCP protocol");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    if (entry->tcp.status != DPIP_TCP_CLOSED) {
        LOGGER_WARN("socket status is not DPIP_TCP_CLOSED");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    entry->tcp.status = DPIP_TCP_LISTEN;
    entry->tcp.backlog = backlog;
    pthread_mutex_unlock(&entry->mutex);
    return 0;
}

int dpip_accept(int sockfd
                , struct sockaddr* addr
                , __attribute__((unused)) socklen_t* addrlen) {
    struct socket_entry* listen_sock_entry = get_socket_entry_by_fd(sockfd);
    if (!listen_sock_entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&listen_sock_entry->mutex);
    if (listen_sock_entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_accept only support TCP protocol");
        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return -1;
    }
    if (listen_sock_entry->tcp.status != DPIP_TCP_LISTEN) {
        LOGGER_WARN("socket status is not DPIP_TCP_LISTEN");
        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return -1;
    }
    struct socket_entry* accept_sock_entry = NULL;
    while (!accept_sock_entry) {
        if (listen_sock_entry->tcp.accept_queue) {
            accept_sock_entry = listen_sock_entry->tcp.accept_queue;
            listen_sock_entry->tcp.accept_queue = accept_sock_entry->next;
            if (accept_sock_entry->next) {
                accept_sock_entry->next->prev = NULL;
            }
            --listen_sock_entry->tcp.current_accept_queue_length;
        } else {
            pthread_cond_wait(&listen_sock_entry->tcp.accept_queue_not_empty, &listen_sock_entry->mutex);
        }
    }
    pthread_mutex_unlock(&listen_sock_entry->mutex);
    int fd = get_free_fd_from_bitmap();
    if (fd == -1) {
        LOGGER_WARN("no free fd");
        rte_free(accept_sock_entry);
        return -1;
    }
    pthread_mutex_lock(&accept_sock_entry->mutex);
    accept_sock_entry->fd = fd;
    pthread_mutex_unlock(&accept_sock_entry->mutex);
    add_socket_entry(accept_sock_entry);
    if (addr) {
        struct sockaddr_in* in_addr = (struct sockaddr_in*)addr;
        in_addr->sin_family = AF_INET;
        in_addr->sin_addr.s_addr = accept_sock_entry->tcp.remote_ip;
        in_addr->sin_port = accept_sock_entry->tcp.remote_port;
    };
    return accept_sock_entry->fd;
}

ssize_t dpip_recv(int sockfd
                , void* buf
                , size_t len
                , __attribute__((unused)) int flags) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_recv only support TCP protocol");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    if (entry->tcp.status != DPIP_TCP_ESTABLISHED) {
        LOGGER_WARN("socket status is not DPIP_TCP_ESTABLISHED");
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    while (entry->tcp.recv_info.size == 0 && entry->tcp.status != DPIP_TCP_CLOSE_WAIT) {
        pthread_cond_wait(&entry->notempty, &entry->mutex);
    }
    // 如果连接已经关闭，直接返回0
    if (entry->tcp.status == DPIP_TCP_CLOSE_WAIT && entry->tcp.recv_info.size == 0) {
        pthread_mutex_unlock(&entry->mutex);
        return 0;
    }
    len = (len > entry->tcp.recv_info.size) ? entry->tcp.recv_info.size : len;
    for (size_t i = 0; i < len; ++i) {
        ((uint8_t*)buf)[i] = entry->tcp.recv_info.buf[entry->tcp.recv_info.read_index];
        entry->tcp.recv_info.read_index = (entry->tcp.recv_info.read_index + 1) % entry->tcp.recv_info.capacity;
    }
    entry->tcp.recv_info.size -= len;
    pthread_mutex_unlock(&entry->mutex);
    return len;
}

ssize_t dpip_send(int sockfd
                , const void* buf
                , size_t len
                , __attribute__((unused)) int flags) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
    if (entry->protocol != IPPROTO_TCP) {
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    if (entry->tcp.status != DPIP_TCP_ESTABLISHED) {
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    while (entry->tcp.send_info.size == entry->tcp.send_info.capacity && entry->tcp.status == DPIP_TCP_ESTABLISHED) {
        pthread_cond_wait(&entry->notfull, &entry->mutex);
    }
    if (entry->tcp.status != DPIP_TCP_ESTABLISHED) {
        pthread_mutex_unlock(&entry->mutex);
        return -1;
    }
    len = (len > entry->tcp.send_info.capacity - entry->tcp.send_info.size) ? entry->tcp.send_info.capacity - entry->tcp.send_info.size : len;
    for (size_t i = 0; i < len; ++i) {
        entry->tcp.send_info.buf[entry->tcp.send_info.write_index] = ((const uint8_t*)buf)[i];
        entry->tcp.send_info.write_index = (entry->tcp.send_info.write_index + 1) % entry->tcp.send_info.capacity;
    }
    entry->tcp.send_info.size += len;
    pthread_mutex_unlock(&entry->mutex);
    return len;
}