#include "dpip_socket.h"
#include "dpip_logger.h"

#include <rte_malloc.h>
#include <rte_tcp.h>

#include <arpa/inet.h>

static struct socket_table socket_table = { 0 };            // socket表

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
    new_syn_entry->tcp.seq = TCP_MAX_SEQ;

    pthread_cond_init(&new_syn_entry->notfull, NULL);
    pthread_cond_init(&new_syn_entry->notempty, NULL);
    pthread_mutex_init(&new_syn_entry->mutex, NULL);

    char ring_name[32] = { 0 };
    static uint32_t ring_id = 0;
    snprintf(ring_name, 32, "tcp_sys_recv_ring_%d", ring_id);
    new_syn_entry->tcp.recv_ring = rte_ring_create(ring_name, TCP_RECV_RING_SIZE, 0, RING_F_SC_DEQ | RING_F_SP_ENQ);
    if (!new_syn_entry->tcp.recv_ring) {
        LOGGER_WARN("rte_ring_create tcp_sys_recv_ring error");
        rte_free(new_syn_entry);

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }
    snprintf(ring_name, 32, "tcp_sys_send_ring_%d", ring_id++);
    new_syn_entry->tcp.send_ring = rte_ring_create(ring_name, TCP_SEND_RING_SIZE, 0, RING_F_SC_DEQ | RING_F_SP_ENQ);
    if (!new_syn_entry->tcp.send_ring) {
        LOGGER_WARN("rte_ring_create tcp_sys_send_ring error");
        rte_ring_free(new_syn_entry->tcp.recv_ring);
        rte_free(new_syn_entry);

        pthread_mutex_unlock(&listen_sock_entry->mutex);
        return NULL;
    }

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
    pthread_rwlock_rdlock(&socket_table.rwlock);
    struct socket_entry* entry = socket_table.udp_entry_head;
    while (entry) {
        if (entry->fd == fd) {
            pthread_rwlock_unlock(&socket_table.rwlock);
            return entry;
        }
        entry = entry->next;
    }
    entry = socket_table.tcp_entry_head;
    while (entry) {
        if (entry->fd == fd) {
            pthread_rwlock_unlock(&socket_table.rwlock);
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
    if (protocol == IPPROTO_UDP) {
        struct socket_entry* entry = socket_table.udp_entry_head;
        while (entry) {
            if (entry->udp.local_ip == local_ip
                && entry->udp.local_port == local_port) {
                pthread_rwlock_unlock(&socket_table.rwlock);
                return entry;
            }
            entry = entry->next;
        }
    } else if (protocol == IPPROTO_TCP) {
        // ESTABLISHED、 SYN_SENT、SYN_RECEIVED、FIN_WAIT_1、FIN_WAIT_2、CLOSING、CLOSED、LAST_ACK、TIME_WAIT
        struct socket_entry* entry = socket_table.tcp_entry_head;
        while (entry) {
            if (entry->tcp.local_ip == local_ip
                && entry->tcp.local_port == local_port
                && entry->tcp.remote_ip == remote_ip
                && entry->tcp.remote_port == remote_port) {
                pthread_rwlock_unlock(&socket_table.rwlock);
                return entry;
            }
            entry = entry->next;
        }
        // LISTEN
        entry = socket_table.tcp_entry_head;
        while (entry) {
            if (entry->tcp.local_ip == local_ip
                && entry->tcp.local_port == local_port
                && entry->tcp.status == DPIP_TCP_LISTEN) {
                pthread_rwlock_unlock(&socket_table.rwlock);
                return entry;
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(&socket_table.rwlock);
    return NULL;
}

// 获取socket表
struct socket_table* get_socket_table(void) {
    return &socket_table;
}

// 添加socket实体
void add_socket_entry(struct socket_entry* entry) {
    pthread_rwlock_wrlock(&socket_table.rwlock);
    if (entry->protocol == IPPROTO_UDP) {
        entry->next = socket_table.udp_entry_head;
        if (socket_table.udp_entry_head) {
            socket_table.udp_entry_head->prev = entry;
        }
        socket_table.udp_entry_head = entry;
    } else if (entry->protocol == IPPROTO_TCP) {
        entry->next = socket_table.tcp_entry_head;
        if (socket_table.tcp_entry_head) {
            socket_table.tcp_entry_head->prev = entry;
        }
        socket_table.tcp_entry_head = entry;
    }
    pthread_rwlock_unlock(&socket_table.rwlock);
}

// 删除socket实体
void del_socket_entry(struct socket_entry* entry) {
    pthread_rwlock_wrlock(&socket_table.rwlock);
    if (entry->protocol == IPPROTO_UDP) {
        if (entry->prev) {
            entry->prev->next = entry->next;
        } else {
            socket_table.udp_entry_head = entry->next;
        }
        if (entry->next) {
            entry->next->prev = entry->prev;
        }
    } else if (entry->protocol == IPPROTO_TCP) {
        if (entry->prev) {
            entry->prev->next = entry->next;
        } else {
            socket_table.tcp_entry_head = entry->next;
        }
        if (entry->next) {
            entry->next->prev = entry->prev;
        }
    }
    // 回收文件描述符
    int fd = entry->fd;
    socket_table.fd_bitmap[fd / 8] &= ~(1 << (fd % 8));

    pthread_rwlock_unlock(&socket_table.rwlock);
}

// 从位图中获取一个空闲的文件描述符
static int get_free_fd_from_bitmap(void) {
    pthread_rwlock_wrlock(&socket_table.rwlock);
    for (int i = 0; i < MAX_FD_COUNT / 8; ++i) {
        if (socket_table.fd_bitmap[i] != 0xFF) {
            for (int j = 0; j < 8; ++j) {
                if (!(socket_table.fd_bitmap[i] & (1 << j))) {
                    socket_table.fd_bitmap[i] |= (1 << j);
                    pthread_rwlock_unlock(&socket_table.rwlock);
                    return i * 8 + j;
                }
            }
        }
    }
    pthread_rwlock_unlock(&socket_table.rwlock);
    return -1;
}

// 释放文件描述符
static void free_fd_to_bitmap(int fd) {
    pthread_rwlock_wrlock(&socket_table.rwlock);
    socket_table.fd_bitmap[fd / 8] &= ~(1 << (fd % 8));
    pthread_rwlock_unlock(&socket_table.rwlock);
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
        add_socket_entry(entry);
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
        pthread_cond_init(&tcp->accept_queue_not_empty, NULL);
        tcp->syn_queue = NULL;
        tcp->accept_queue = NULL;
        tcp->syn_queue_length = DPIP_TCP_SYN_QUEUE_MAX_LENGTH;
        tcp->backlog = 0;
        tcp->current_syn_queue_length = 0;
        tcp->current_accept_queue_length = 0;
        // 给ring命名
        char ring_name[32];
        static int tcp_ring_id = 0;
        snprintf(ring_name, sizeof(ring_name), "tcp_socket_recv_ring_id_%d", tcp_ring_id);
        tcp->recv_ring = rte_ring_create(ring_name, 2, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!tcp->recv_ring) {
            LOGGER_ERROR("rte_ring_create %s error", ring_name);
            rte_free(entry);
            free_fd_to_bitmap(fd);
            return -1;
        }
        snprintf(ring_name, sizeof(ring_name), "tcp_socket_send_ring_id_%d", tcp_ring_id++);
        tcp->send_ring = rte_ring_create(ring_name, 2, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!tcp->send_ring) {
            LOGGER_ERROR("rte_ring_create %s error", ring_name);
            rte_ring_free(tcp->recv_ring);
            rte_free(entry);
            free_fd_to_bitmap(fd);
            return -1;
        }
        add_socket_entry(entry);
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
    if (entry->protocol == IPPROTO_UDP) {
        const struct sockaddr_in* in_addr = (const struct sockaddr_in*)addr;
        entry->udp.local_ip = in_addr->sin_addr.s_addr;
        entry->udp.local_port = in_addr->sin_port;
    } else if (entry->protocol == IPPROTO_TCP) {
        const struct sockaddr_in* in_addr = (const struct sockaddr_in*)addr;
        entry->tcp.local_ip = in_addr->sin_addr.s_addr;
        entry->tcp.local_port = in_addr->sin_port;
    }
    return 0;
}

int dpip_sendto(int sockfd
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
    if (entry->protocol != IPPROTO_UDP) {
        LOGGER_WARN("dpip_sendto only support UDP protocol");
        return -1;
    }
    const struct sockaddr_in* in_addr = (const struct sockaddr_in*)dest_addr;
    uint32_t dst_ip = in_addr->sin_addr.s_addr;
    uint16_t dst_port = in_addr->sin_port;
    struct udp_datagram* datagram = (struct udp_datagram*)rte_malloc("udp_datagram", sizeof(struct udp_datagram), 0);
    if (!datagram) {
        LOGGER_WARN("rte_malloc udp_datagram error");
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
        return -1;
    }
    rte_memcpy(datagram->data, buf, len);
    pthread_mutex_lock(&entry->mutex);
    while (rte_ring_mp_enqueue(entry->udp.send_ring, datagram) != 0) {
        pthread_cond_wait(&entry->notfull, &entry->mutex);
    }
    pthread_mutex_unlock(&entry->mutex);
    return len;
}

int dpip_recvfrom(int sockfd
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

    if (entry->protocol != IPPROTO_UDP) {
        LOGGER_WARN("dpip_recvfrom only support UDP protocol");
        return -1;
    }
    struct udp_datagram* datagram = NULL;
    pthread_mutex_lock(&entry->mutex);
    while (rte_ring_mc_dequeue(entry->udp.recv_ring, (void**)&datagram) != 0) {
        pthread_cond_wait(&entry->notempty, &entry->mutex);
    }
    pthread_mutex_unlock(&entry->mutex);
    struct sockaddr_in* in_addr = (struct sockaddr_in*)src_addr;
    in_addr->sin_family = AF_INET;
    in_addr->sin_addr.s_addr = datagram->src_ip;
    in_addr->sin_port = datagram->src_port;
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
    if (entry->protocol == IPPROTO_UDP) {
        rte_ring_free(entry->udp.recv_ring);
        rte_ring_free(entry->udp.send_ring);
    }
    del_socket_entry(entry);
    rte_free(entry);
    return 0;
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
    if (entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_listen only support TCP protocol");
        return -1;
    }
    pthread_mutex_lock(&entry->mutex);
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
    if (listen_sock_entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_accept only support TCP protocol");
        return -1;
    }
    pthread_mutex_lock(&listen_sock_entry->mutex);
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
    accept_sock_entry->fd = get_free_fd_from_bitmap();
    if (accept_sock_entry->fd == -1) {
        LOGGER_WARN("no free fd");
        rte_free(accept_sock_entry);
        return -1;
    }
    add_socket_entry(accept_sock_entry);
    struct sockaddr_in* in_addr = (struct sockaddr_in*)addr;
    in_addr->sin_family = AF_INET;
    in_addr->sin_addr.s_addr = accept_sock_entry->tcp.remote_ip;
    in_addr->sin_port = accept_sock_entry->tcp.remote_port;
    return accept_sock_entry->fd;
}

int dpip_recv(int sockfd
            , void* buf
            , size_t len
            , __attribute__((unused)) int flags) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    if (entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_recv only support TCP protocol");
        return -1;
    }
    struct tcp_segment* segment = NULL;
    pthread_mutex_lock(&entry->mutex);
    while (rte_ring_mc_dequeue(entry->tcp.recv_ring, (void**)&segment) != 0 && entry->tcp.status == DPIP_TCP_ESTABLISHED) {
        pthread_cond_wait(&entry->notempty, &entry->mutex);
    }
    // 如果连接已经关闭，直接返回0
    if (entry->tcp.status != DPIP_TCP_ESTABLISHED) {
        pthread_mutex_unlock(&entry->mutex);
        return 0;
    }
    pthread_mutex_unlock(&entry->mutex);
    if (len > segment->length) {
        len = segment->length;
        rte_memcpy(buf, segment->data, len);
        rte_free(segment->data);
        rte_free(segment);
    } else {
        rte_memcpy(buf, segment->data, len);
        // 移动数据
        rte_memcpy(segment->data, (uint8_t*)segment->data + len, segment->length - len);
        segment->length -= len;

        pthread_cond_signal(&entry->notfull);
        rte_ring_mp_enqueue(entry->tcp.recv_ring, segment);
    }
    return len;
}

int dpip_send(int sockfd
            , const void* buf
            , size_t len
            , __attribute__((unused)) int flags) {
    struct socket_entry* entry = get_socket_entry_by_fd(sockfd);
    if (!entry) {
        LOGGER_WARN("socket entry not found");
        return -1;
    }
    if (entry->protocol != IPPROTO_TCP) {
        LOGGER_WARN("dpip_send only support TCP protocol");
        return -1;
    }
    struct tcp_segment* segment = (struct tcp_segment*)rte_malloc("tcp_segment", sizeof(struct tcp_segment), 0);
    if (!segment) {
        LOGGER_WARN("rte_malloc tcp_segment error");
        return -1;
    }
    segment->src_ip = entry->tcp.local_ip;
    segment->dst_ip = entry->tcp.remote_ip;
    segment->src_port = entry->tcp.local_port;
    segment->dst_port = entry->tcp.remote_port;
    segment->seq = entry->tcp.seq;
    segment->ack = entry->tcp.ack;
    segment->data_off = 0x50;
    segment->flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    segment->rx_win = entry->tcp.rx_win;
    segment->tcp_urp = 0;
    segment->data = (uint8_t*)rte_malloc("tcp_data", len, 0);
    if (!segment->data) {
        LOGGER_WARN("rte_malloc tcp_data error");
        rte_free(segment);
        return -1;
    }
    rte_memcpy(segment->data, buf, len);
    segment->length = len;
    pthread_mutex_lock(&entry->mutex);
    while (rte_ring_mp_enqueue(entry->tcp.send_ring, segment) != 0) {
        pthread_cond_wait(&entry->notfull, &entry->mutex);
    }
    pthread_mutex_unlock(&entry->mutex);
    return len;
}