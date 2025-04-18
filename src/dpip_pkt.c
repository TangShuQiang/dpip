#include "dpip_pkt.h"
#include "dpip_logger.h"
#include "dpip_nic.h"
#include "dpip_config.h"
#include "dpip_socket.h"

#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_arp.h>
#include <rte_udp.h>
#include <rte_malloc.h>
#include <rte_hash.h>

#include <arpa/inet.h>

void encode_ether_hdr(uint8_t* pkt_ptr
                    , uint8_t* dst_mac
                    , uint8_t* src_mac
                    , uint16_t ether_type) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    rte_ether_addr_copy((struct rte_ether_addr*)dst_mac, &eth_hdr->d_addr);
    rte_ether_addr_copy((struct rte_ether_addr*)src_mac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
}

void encode_ipv4_hdr(uint8_t* pkt_pkt
                    , uint32_t dst_ip
                    , uint32_t src_ip
                    , uint8_t proto
                    , uint16_t length) {
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)pkt_pkt;
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(length);
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = proto;
    ip_hdr->src_addr = src_ip;
    ip_hdr->dst_addr = dst_ip;

    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
}

void encode_icmp_hdr(uint8_t* pkt_ptr
                    , uint8_t type
                    , uint8_t code
                    , uint16_t ident
                    , uint16_t seqnb) {
    struct rte_icmp_hdr* icmp_hdr = (struct rte_icmp_hdr*)pkt_ptr;
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_ident = ident;
    icmp_hdr->icmp_seq_nb = seqnb;

    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = rte_ipv4_cksum((struct rte_ipv4_hdr*)icmp_hdr);
}

void encode_arp_hdr(uint8_t* pkt_ptr
                    , uint16_t opcode
                    , uint8_t* dst_mac
                    , uint8_t* src_mac
                    , uint32_t tip
                    , uint32_t sip) {
    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)pkt_ptr;
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = sizeof(uint32_t);
    arp_hdr->arp_opcode = rte_cpu_to_be_16(opcode);

    rte_ether_addr_copy((struct rte_ether_addr*)src_mac, &arp_hdr->arp_data.arp_sha);
    if (opcode == RTE_ARP_OP_REQUEST) {
        uint8_t zeroMac[RTE_ETHER_ADDR_LEN] = {0};
        rte_ether_addr_copy((struct rte_ether_addr*)zeroMac, &arp_hdr->arp_data.arp_tha);
    } else if (opcode == RTE_ARP_OP_REPLY) {
        rte_ether_addr_copy((struct rte_ether_addr*)dst_mac, &arp_hdr->arp_data.arp_tha);
    }

    arp_hdr->arp_data.arp_sip = sip;
    arp_hdr->arp_data.arp_tip = tip;
}

void encode_udp_hdr(uint8_t* pkt_ptr
                    , uint16_t src_port
                    , uint16_t dst_port
                    , uint8_t* data
                    , uint16_t length) {
    
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)pkt_ptr;
    struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)(ip_hdr + 1);

    udp_hdr->src_port = src_port;
    udp_hdr->dst_port = dst_port;
    udp_hdr->dgram_len = rte_cpu_to_be_16(length + sizeof(struct rte_udp_hdr));
    
    rte_memcpy(udp_hdr + 1, data, length);

    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
}

void encode_tcp_hdr(uint8_t* pkt_ptr
                    , uint16_t src_port
                    , uint16_t dst_port
                    , uint32_t seq
                    , uint32_t ack
                    , uint8_t flags
                    , uint16_t rx_win
                    , uint8_t* data
                    , uint16_t length) {
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)pkt_ptr;
    struct rte_tcp_hdr* tcp_hdr = (struct rte_tcp_hdr*)(ip_hdr + 1);

    tcp_hdr->src_port = src_port;
    tcp_hdr->dst_port = dst_port;
    tcp_hdr->sent_seq = rte_cpu_to_be_32(seq);
    tcp_hdr->recv_ack = rte_cpu_to_be_32(ack);
    tcp_hdr->data_off = 0x50;
    tcp_hdr->tcp_flags = flags;
    tcp_hdr->rx_win = rte_cpu_to_be_16(rx_win);

    rte_memcpy(tcp_hdr + 1, data, length);

    tcp_hdr->cksum = 0;
    tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);
}

struct rte_mbuf* get_icmp_pkt(struct rte_mempool* mbuf_pool
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t tip
                            , uint32_t sip
                            , uint16_t id
                            , uint16_t seqnb) {
    unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
    
    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool); 
    if (!mbuf) {
        LOGGER_WARN("rte_pktmbuf_alloc icmp buf error");
        return NULL;
    }
    mbuf->data_len = total_length;
    mbuf->pkt_len = total_length;

    uint8_t* pkt_ptr = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_ether_hdr(pkt_ptr, dst_mac, src_mac, RTE_ETHER_TYPE_IPV4);

    pkt_ptr += sizeof(struct rte_ether_hdr);
    encode_ipv4_hdr(pkt_ptr, tip, sip, IPPROTO_ICMP, total_length - sizeof(struct rte_ether_hdr));

    pkt_ptr += sizeof(struct rte_ipv4_hdr);
    encode_icmp_hdr(pkt_ptr, RTE_IP_ICMP_ECHO_REPLY, 0, id, seqnb);

    return mbuf;
}

struct rte_mbuf* get_arp_pkt(struct rte_mempool* mbuf_pool
                            , uint16_t opcode
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t tip
                            , uint32_t sip) {
    unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        LOGGER_WARN("rte_pktmbuf_alloc arp buf error");
        return NULL;
    }
    mbuf->data_len = total_length;
    mbuf->pkt_len = total_length;

    uint8_t* pkt_ptr = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_ether_hdr(pkt_ptr, dst_mac, src_mac, RTE_ETHER_TYPE_ARP);

    pkt_ptr += sizeof(struct rte_ether_hdr);
    encode_arp_hdr(pkt_ptr, opcode, dst_mac, src_mac, tip, sip);

    return mbuf;
}

struct rte_mbuf* get_udp_pkt(struct rte_mempool* mbuf_pool
                            , uint8_t* data
                            , uint16_t length
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t dst_ip
                            , uint32_t src_ip
                            , uint16_t dst_port
                            , uint16_t src_port) {
    unsigned total_length = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        LOGGER_WARN("rte_pktmbuf_alloc udp buf error");
        return NULL;
    }
    mbuf->data_len = total_length;
    mbuf->pkt_len = total_length;

    uint8_t* pkt_ptr = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_ether_hdr(pkt_ptr, dst_mac, src_mac, RTE_ETHER_TYPE_IPV4);

    pkt_ptr += sizeof(struct rte_ether_hdr);
    encode_ipv4_hdr(pkt_ptr, dst_ip, src_ip, IPPROTO_UDP, total_length - sizeof(struct rte_ether_hdr));

    encode_udp_hdr(pkt_ptr, src_port, dst_port, data, length);

    return mbuf;
}

struct rte_mbuf* get_tcp_pkt(struct rte_mempool* mbuf_pool
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t dst_ip
                            , uint32_t src_ip
                            , uint16_t dst_port
                            , uint16_t src_port
                            , uint32_t seq
                            , uint32_t ack
                            , uint8_t flags
                            , uint16_t rx_win
                            , uint8_t* data
                            , uint16_t length) {
    // 默认 TCP的可选字段为空
    unsigned total_length = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        LOGGER_WARN("rte_pktmbuf_alloc tcp buf error");
        return NULL;
    }
    mbuf->data_len = total_length;
    mbuf->pkt_len = total_length;

    uint8_t* pkt_ptr = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_ether_hdr(pkt_ptr, dst_mac, src_mac, RTE_ETHER_TYPE_IPV4);

    pkt_ptr += sizeof(struct rte_ether_hdr);
    encode_ipv4_hdr(pkt_ptr, dst_ip, src_ip, IPPROTO_TCP, total_length - sizeof(struct rte_ether_hdr));

    encode_tcp_hdr(pkt_ptr, src_port, dst_port, seq, ack, flags, rx_win, data, length);
    return mbuf;
}

void pkt_process_tcp_send_fin(struct dpip_nic* nic
                            , struct socket_entry* tcp_sock_entry) {
    struct arp_entry* arp_entry = get_mac_by_ip(&nic->arp_table, tcp_sock_entry->tcp.remote_ip);
    if (!arp_entry) {
        uint8_t broadcast_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        struct rte_mbuf* arp_pkt = get_arp_pkt(nic->pkt_send_pool
                                                , RTE_ARP_OP_REQUEST
                                                , broadcast_mac
                                                , nic->local_mac
                                                , tcp_sock_entry->tcp.remote_ip
                                                , tcp_sock_entry->tcp.local_ip);
        rte_ring_mp_enqueue(nic->out_pkt_ring, arp_pkt);
    } else {
        struct rte_mbuf* tcp_fin_pkt = get_tcp_pkt(nic->pkt_send_pool
                                                    , arp_entry->mac
                                                    , nic->local_mac
                                                    , tcp_sock_entry->tcp.remote_ip
                                                    , tcp_sock_entry->tcp.local_ip
                                                    , tcp_sock_entry->tcp.remote_port
                                                    , tcp_sock_entry->tcp.local_port
                                                    , tcp_sock_entry->tcp.send_next
                                                    , tcp_sock_entry->tcp.recv_next
                                                    , RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG
                                                    , tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.size
                                                    , NULL
                                                    , 0);
        rte_ring_mp_enqueue(nic->out_pkt_ring, tcp_fin_pkt);
    }
}

void pkt_process_tcp_send_ack(struct dpip_nic* nic
                            , struct socket_entry* tcp_sock_entry) {
    struct arp_entry* arp_entry = get_mac_by_ip(&nic->arp_table, tcp_sock_entry->tcp.remote_ip);
    if (!arp_entry) {
        uint8_t broadcast_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        struct rte_mbuf* arp_pkt = get_arp_pkt(nic->pkt_send_pool
                                                , RTE_ARP_OP_REQUEST
                                                , broadcast_mac
                                                , nic->local_mac
                                                , tcp_sock_entry->tcp.remote_ip
                                                , tcp_sock_entry->tcp.local_ip);
        rte_ring_mp_enqueue(nic->out_pkt_ring, arp_pkt);
    } else {
        struct rte_mbuf* tcp_ack_pkt = get_tcp_pkt(nic->pkt_send_pool
                                                    , arp_entry->mac
                                                    , nic->local_mac
                                                    , tcp_sock_entry->tcp.remote_ip
                                                    , tcp_sock_entry->tcp.local_ip
                                                    , tcp_sock_entry->tcp.remote_port
                                                    , tcp_sock_entry->tcp.local_port
                                                    , tcp_sock_entry->tcp.send_next
                                                    , tcp_sock_entry->tcp.recv_next
                                                    , RTE_TCP_ACK_FLAG
                                                    , tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.size
                                                    , NULL
                                                    , 0);
        rte_ring_mp_enqueue(nic->out_pkt_ring, tcp_ack_pkt);
    }
}

void pkt_process_tcp_on_established(struct dpip_nic* nic
                                    , struct socket_entry* tcp_sock_entry
                                    , uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_tcp_hdr* tcp_hdr = (struct rte_tcp_hdr*)(ip_hdr + 1);

    if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG){
        LOGGER_WARN("established status, but receive SYN flag");
        return;
    }

    uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
    uint32_t ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);

    pthread_mutex_lock(&tcp_sock_entry->mutex);
    if (ack > tcp_sock_entry->tcp.send_una) {
        // 收到新的ack，更新发送窗口
        tcp_sock_entry->tcp.send_info.unackedlen -= ack - tcp_sock_entry->tcp.send_una;
        tcp_sock_entry->tcp.send_info.read_index = (tcp_sock_entry->tcp.send_info.read_index + ack - tcp_sock_entry->tcp.send_una) % tcp_sock_entry->tcp.send_info.capacity;
        tcp_sock_entry->tcp.send_info.size -= ack - tcp_sock_entry->tcp.send_una;

        tcp_sock_entry->tcp.send_una = ack;
        tcp_sock_entry->tcp.dup_ack_count = 0;
    } else if (ack == tcp_sock_entry->tcp.send_una) {
        // 重复确认
        if (tcp_sock_entry->tcp.send_una < tcp_sock_entry->tcp.send_next) {
            ++tcp_sock_entry->tcp.dup_ack_count;
        }
    }
    pthread_mutex_unlock(&tcp_sock_entry->mutex);

    // 接收数据包
    uint8_t payload_offset = (tcp_hdr->data_off >> 4) * 4;
    uint16_t data_length = rte_be_to_cpu_16(ip_hdr->total_length) - sizeof(struct rte_ipv4_hdr) - payload_offset;

    // 数据包长度大于0, 则接收数据包
    if (data_length > 0) {
        // 顺序接收数据包
        pthread_mutex_lock(&tcp_sock_entry->mutex);
        if (seq == tcp_sock_entry->tcp.recv_next) {
            uint32_t write_size = (data_length > tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.size)
                                    ? tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.size : data_length;
            if (write_size + tcp_sock_entry->tcp.recv_info.write_index > tcp_sock_entry->tcp.recv_info.capacity) {
                uint32_t first_size = tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.write_index;
                rte_memcpy(tcp_sock_entry->tcp.recv_info.buf + tcp_sock_entry->tcp.recv_info.write_index
                            , (uint8_t*)(tcp_hdr) + payload_offset
                            , first_size);
                rte_memcpy(tcp_sock_entry->tcp.recv_info.buf
                            , (uint8_t*)(tcp_hdr) + payload_offset + first_size
                            , write_size - first_size);
            } else {
                rte_memcpy(tcp_sock_entry->tcp.recv_info.buf + tcp_sock_entry->tcp.recv_info.write_index
                            , (uint8_t*)(tcp_hdr) + payload_offset
                            , write_size);
            }
            tcp_sock_entry->tcp.recv_info.size += write_size;
            tcp_sock_entry->tcp.recv_info.write_index = (tcp_sock_entry->tcp.recv_info.write_index + write_size) % tcp_sock_entry->tcp.recv_info.capacity;
            tcp_sock_entry->tcp.recv_next += write_size;
            // 查看后面的数据包是否已经接收到
            while (tcp_sock_entry->tcp.recv_info.size > 0 && tcp_sock_entry->tcp.recv_info.buf_flag[tcp_sock_entry->tcp.recv_info.write_index] > 0) {
                tcp_sock_entry->tcp.recv_info.size -= 1;
                tcp_sock_entry->tcp.recv_info.write_index = (tcp_sock_entry->tcp.recv_info.write_index + 1) % tcp_sock_entry->tcp.recv_info.capacity;
                tcp_sock_entry->tcp.recv_next += 1;
                // 数据包接收完毕
                if (tcp_sock_entry->tcp.recv_info.buf_flag[tcp_sock_entry->tcp.recv_info.write_index] == 2) {
                    tcp_sock_entry->tcp.status = DPIP_TCP_CLOSE_WAIT;
                }
                tcp_sock_entry->tcp.recv_info.buf_flag[tcp_sock_entry->tcp.recv_info.write_index] = 0;
            }
            pthread_cond_signal(&tcp_sock_entry->notempty);
            pthread_mutex_unlock(&tcp_sock_entry->mutex);
        } else {// 乱序接收数据包
            uint32_t offset = seq - tcp_sock_entry->tcp.recv_next;
            uint32_t write_size = (data_length > tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.size - offset)
                                    ? tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.size - offset : data_length;
            if (write_size + offset + tcp_sock_entry->tcp.recv_info.write_index > tcp_sock_entry->tcp.recv_info.capacity) {
                uint32_t first_size = tcp_sock_entry->tcp.recv_info.capacity - tcp_sock_entry->tcp.recv_info.write_index;
                rte_memcpy(tcp_sock_entry->tcp.recv_info.buf + tcp_sock_entry->tcp.recv_info.write_index + offset
                            , (uint8_t*)(tcp_hdr) + payload_offset
                            , first_size);
                rte_memcpy(tcp_sock_entry->tcp.recv_info.buf
                            , (uint8_t*)(tcp_hdr) + payload_offset + first_size
                            , write_size - first_size);
                // 将buf_flag中的标志位设置为1
                memset(tcp_sock_entry->tcp.recv_info.buf_flag + tcp_sock_entry->tcp.recv_info.write_index + offset, 1, first_size);
                memset(tcp_sock_entry->tcp.recv_info.buf_flag, 1, write_size - first_size);
            } else {
                rte_memcpy(tcp_sock_entry->tcp.recv_info.buf + tcp_sock_entry->tcp.recv_info.write_index + offset
                            , (uint8_t*)(tcp_hdr) + payload_offset
                            , write_size);
                // 将buf_flag中的标志位设置为1
                memset(tcp_sock_entry->tcp.recv_info.buf_flag + tcp_sock_entry->tcp.recv_info.write_index + offset, 1, write_size);
            }
            if ((tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) 
                && offset + data_length + 1 + tcp_sock_entry->tcp.recv_info.size <= tcp_sock_entry->tcp.recv_info.capacity) {
                tcp_sock_entry->tcp.recv_info.buf_flag[(tcp_sock_entry->tcp.recv_info.write_index + offset + data_length) % tcp_sock_entry->tcp.recv_info.capacity] = 2;
            }

            pthread_mutex_unlock(&tcp_sock_entry->mutex);
        }
    }

    // 收到FIN数据包，且数据包已经接收完毕
    if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG && seq == tcp_sock_entry->tcp.recv_next) {
        // 对端关闭连接
        tcp_sock_entry->tcp.recv_next += 1;
        tcp_sock_entry->tcp.status = DPIP_TCP_CLOSE_WAIT;
    }

    if (data_length > 0) {
        pkt_process_tcp_send_ack(nic, tcp_sock_entry);
    }

    if (tcp_sock_entry->tcp.dup_ack_count >= TCP_DUP_ACK_COUNT) {
        tcp_sock_entry->tcp.send_next = tcp_sock_entry->tcp.send_una;       // 快速重传,发送序列号重置

        tcp_sock_entry->tcp.send_info.unackedlen = 0;
        tcp_sock_entry->tcp.dup_ack_count = 0;
    }

    if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
        pthread_cond_signal(&tcp_sock_entry->notempty);
    }
}

void pkt_process_tcp_on_listen(struct dpip_nic* nic
                                , struct socket_entry* listen_sock_entry
                                , uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_tcp_hdr* tcp_hdr = (struct rte_tcp_hdr*)(ip_hdr + 1);

    // LOGGER_DEBUG("tcp flags: %d", tcp_hdr->tcp_flags);

    // 判断是否为SYN数据包: SYN=1, ACK=0, 第一次握手
    if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) {
        struct socket_entry* syn_sock_entry = get_syn_by_ip_port(listen_sock_entry
                                                                , ip_hdr->dst_addr
                                                                , tcp_hdr->dst_port
                                                                , ip_hdr->src_addr
                                                                , tcp_hdr->src_port);
        // 已经存在全连接，或者 连接队列已满
        if (!syn_sock_entry) {
            return;
        }
        // 第一次握手
        if (syn_sock_entry->tcp.send_next == TCP_MAX_SEQ) {
            time_t now = time(NULL);
            srand(now);
            syn_sock_entry->tcp.send_next = rand() % TCP_MAX_SEQ;
            syn_sock_entry->tcp.send_una = syn_sock_entry->tcp.send_next;
            syn_sock_entry->tcp.recv_next = rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1;

            syn_sock_entry->tcp.rx_win = rte_be_to_cpu_16(tcp_hdr->rx_win);
            syn_sock_entry->tcp.dup_ack_count = 0;
        }  else {
            // 重复的SYN数据包
            if (rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1 == syn_sock_entry->tcp.recv_next) {
                syn_sock_entry->tcp.send_next -= 1; // 需要重发第二次握手，序列号减1
            } else {
                return;
            }
        }

        if (syn_sock_entry->tcp.dup_ack_count % TCP_DUP_ACK_COUNT == 0) {
            struct rte_mbuf* tcp_pkt = get_tcp_pkt(nic->pkt_send_pool
                                                , eth_hdr->s_addr.addr_bytes
                                                , eth_hdr->d_addr.addr_bytes
                                                , ip_hdr->src_addr
                                                , ip_hdr->dst_addr
                                                , tcp_hdr->src_port
                                                , tcp_hdr->dst_port
                                                , syn_sock_entry->tcp.send_next
                                                , syn_sock_entry->tcp.recv_next
                                                , RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG
                                                , syn_sock_entry->tcp.recv_info.capacity - syn_sock_entry->tcp.recv_info.size
                                                , NULL
                                                , 0);
            rte_ring_mp_enqueue(nic->out_pkt_ring, tcp_pkt);

            syn_sock_entry->tcp.send_next += 1;
        }
        return;
    } 
    // 判断是否为ACK数据包
    if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {
        struct socket_entry* accept_sock_entry = get_accept_by_ip_port(listen_sock_entry
                                                                        , ip_hdr->dst_addr
                                                                        , tcp_hdr->dst_port
                                                                        , ip_hdr->src_addr
                                                                        , tcp_hdr->src_port);
        if (!accept_sock_entry) {
            return;
        }
        // 第三次握手，半连接转为全连接
        if (!(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) && accept_sock_entry->tcp.status == DPIP_TCP_SYN_RECEIVED) {
            pthread_mutex_lock(&listen_sock_entry->mutex);
            accept_sock_entry->tcp.status = DPIP_TCP_ESTABLISHED;
            accept_sock_entry->tcp.send_una = rte_be_to_cpu_32(tcp_hdr->recv_ack);
            
            // 将半连接从队列中移除
            if (accept_sock_entry->prev) {
                accept_sock_entry->prev->next = accept_sock_entry->next;
            } else {
                listen_sock_entry->tcp.syn_queue = accept_sock_entry->next;
            }
            if (accept_sock_entry->next) {
                accept_sock_entry->next->prev = accept_sock_entry->prev;
            }
            --listen_sock_entry->tcp.current_syn_queue_length;
            if (listen_sock_entry->tcp.current_accept_queue_length == listen_sock_entry->tcp.backlog) {
                rte_free(accept_sock_entry);    // 全连接队列已满，释放连接
                pthread_mutex_unlock(&listen_sock_entry->mutex);
                return;
            }
            // 将全连接加入到队列中
            accept_sock_entry->next = listen_sock_entry->tcp.accept_queue;
            if (listen_sock_entry->tcp.accept_queue) {
                listen_sock_entry->tcp.accept_queue->prev = accept_sock_entry;
            }
            listen_sock_entry->tcp.accept_queue = accept_sock_entry;
            ++listen_sock_entry->tcp.current_accept_queue_length;
            pthread_cond_signal(&listen_sock_entry->tcp.accept_queue_not_empty);
            pthread_mutex_unlock(&listen_sock_entry->mutex);
        } else if (accept_sock_entry->tcp.status == DPIP_TCP_ESTABLISHED) {
            // 接收数据包
            pkt_process_tcp_on_established(nic, accept_sock_entry, pkt_ptr);
        }
    }
}

void pkt_process_tcp_on_last_ack(struct socket_entry* tcp_sock_entry
                                , uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_tcp_hdr* tcp_hdr = (struct rte_tcp_hdr*)(ip_hdr + 1);

    // 全连接队列中的连接不调用close，不会进入LAST_ACK状态
    // 只处理ACK数据包
    uint32_t ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);
    if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG && ack == tcp_sock_entry->tcp.send_next) {
        tcp_sock_entry->tcp.status = DPIP_TCP_CLOSED;

        // 释放连接
        rte_free(tcp_sock_entry->tcp.recv_info.buf_flag);
        rte_free(tcp_sock_entry->tcp.recv_info.buf);
        rte_free(tcp_sock_entry->tcp.send_info.buf);
        del_socket_entry(tcp_sock_entry);
        rte_free(tcp_sock_entry);
    }
}

void pkt_process_tcp_on_close_wait(struct dpip_nic* nic
                                , struct socket_entry* tcp_sock_entry
                                , uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_tcp_hdr* tcp_hdr = (struct rte_tcp_hdr*)(ip_hdr + 1);

    // 第二次挥手失败，收到重新发送的FIN包（第一次挥手）
    uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
    if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG && seq == tcp_sock_entry->tcp.recv_next) {
        pkt_process_tcp_send_ack(nic, tcp_sock_entry);
    }
}

// 处理ICMP数据包
void pkt_process_icmp(struct dpip_nic* nic, uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_icmp_hdr* icmp_hdr = (struct rte_icmp_hdr*)(ip_hdr + 1);

    // 判断是否为ICMP回显请求
    if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip, INET_ADDRSTRLEN);
        LOGGER_DEBUG("<=========recv ICMP========>src: %s, dst: %s", src_ip, dst_ip);

        struct rte_mbuf* icmp_buf = get_icmp_pkt(nic->pkt_send_pool
                                                , eth_hdr->s_addr.addr_bytes
                                                , nic->local_mac
                                                , ip_hdr->src_addr
                                                , ip_hdr->dst_addr
                                                , icmp_hdr->icmp_ident
                                                , icmp_hdr->icmp_seq_nb);
        if (icmp_buf) {
            rte_ring_mp_enqueue(nic->out_pkt_ring, icmp_buf);
        }
    }
}

// 处理UDP数据包
void pkt_process_udp(__attribute__((unused)) struct dpip_nic* nic, uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)(ip_hdr + 1);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip, INET_ADDRSTRLEN);
    LOGGER_DEBUG("<=========recv UDP========>src: %s:%d, dst: %s:%d, %s", src_ip, ntohs(udp_hdr->src_port), dst_ip, ntohs(udp_hdr->dst_port), (char*)(udp_hdr + 1));

    // 检查校验和
    uint16_t cksum = udp_hdr->dgram_cksum;
    udp_hdr->dgram_cksum = 0;
    if (cksum != rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr)) {
        LOGGER_WARN("udp checksum error");
        return;
    }

    struct socket_entry* sock_entry = get_socket_entry_by_ip_port_protocol(IPPROTO_UDP
                                                                        , ip_hdr->dst_addr
                                                                        , udp_hdr->dst_port
                                                                        , 0
                                                                        , 0);
    if (!sock_entry) {
        // LOGGER_WARN("udp socket not found");
        return;
    }
    struct udp_datagram* datagram = (struct udp_datagram*) rte_malloc("udp_datagram", sizeof(struct udp_datagram), 0);
    if (!datagram) {
        LOGGER_WARN("rte_malloc udp_datagram error");
        return;
    }
    datagram->src_ip = ip_hdr->src_addr;
    datagram->dst_ip = ip_hdr->dst_addr;
    datagram->src_port = udp_hdr->src_port;
    datagram->dst_port = udp_hdr->dst_port;

    datagram->length = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
    datagram->data = (uint8_t*) rte_malloc("udp_data", datagram->length, 0);
    if (!datagram->data) {
        LOGGER_WARN("rte_malloc udp_data error");
        rte_free(datagram);
        return;
    }
    rte_memcpy(datagram->data, udp_hdr + 1, datagram->length);

    rte_ring_mp_enqueue(sock_entry->udp.recv_ring, datagram);
    pthread_cond_signal(&sock_entry->notempty);
}

// 处理TCP数据包
void pkt_process_tcp(__attribute__((unused)) struct dpip_nic* nic, uint8_t* pkt_ptr){
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    struct rte_tcp_hdr* tcp_hdr = (struct rte_tcp_hdr*)(ip_hdr + 1);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip, INET_ADDRSTRLEN);
    LOGGER_DEBUG("<=========recv TCP========>src: %s:%d, dst: %s:%d", src_ip, ntohs(tcp_hdr->src_port), dst_ip, ntohs(tcp_hdr->dst_port));

    // 检查校验和
    uint16_t cksum = tcp_hdr->cksum;
    tcp_hdr->cksum = 0;
    if (cksum != rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr)) {
        LOGGER_WARN("tcp checksum error");
        return;
    }

    // 根据五元组查找socket实体，找到 已经建立连接的socket实体 或者 监听状态的socket实体
    struct socket_entry* tcp_sock_entry = get_socket_entry_by_ip_port_protocol(IPPROTO_TCP
                                                                                , ip_hdr->dst_addr
                                                                                , tcp_hdr->dst_port
                                                                                , ip_hdr->src_addr
                                                                                , tcp_hdr->src_port);
    if (!tcp_sock_entry) {
        // LOGGER_WARN("tcp socket not found");
        return;
    }
    switch (tcp_sock_entry->tcp.status) {
        case DPIP_TCP_CLOSED: {
            break;
        }
        case DPIP_TCP_LISTEN: {
            pkt_process_tcp_on_listen(nic, tcp_sock_entry, pkt_ptr);
            break;
        }
        case DPIP_TCP_SYN_SENT: {
            break;
        }
        case DPIP_TCP_SYN_RECEIVED: {
            break;
        }
        case DPIP_TCP_ESTABLISHED: {
            pkt_process_tcp_on_established(nic, tcp_sock_entry, pkt_ptr);
            break;
        }
        case DPIP_TCP_FIN_WAIT_1: {
            break;
        }
        case DPIP_TCP_FIN_WAIT_2: {
            break;
        }
        case DPIP_TCP_CLOSE_WAIT: {
            pkt_process_tcp_on_close_wait(nic, tcp_sock_entry, pkt_ptr);
            break;
        }
        case DPIP_TCP_CLOSING: {
            break;
        }
        case DPIP_TCP_LAST_ACK: {
            pkt_process_tcp_on_last_ack(tcp_sock_entry, pkt_ptr);
            break;
        }
        case DPIP_TCP_TIME_WAIT: {
            break;
        }
        default:
            break;
    }
}

// 处理IPv4数据包
void pkt_process_ipv4(struct dpip_nic* nic, uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);

    // // 判断目的IP地址是否是广播地址或者本地IP地址
    // if (ip_hdr->dst_addr == nic->broadcast_ip || ip_hdr->dst_addr == nic->local_ip) {

    // 判断目的IP地址是否是本地IP地址
    if (ip_hdr->dst_addr == nic->local_ip) {

        // 更新arp表
        update_arp_entry(&nic->arp_table, ip_hdr->src_addr, eth_hdr->s_addr.addr_bytes);

        switch (ip_hdr->next_proto_id) {
            // 判断是否为ICMP数据包
            case IPPROTO_ICMP: {
                pkt_process_icmp(nic, pkt_ptr);
                break;
            }// ICMP数据包

            case IPPROTO_UDP: {
                pkt_process_udp(nic, pkt_ptr);
                break;
            }// UDP数据包

            case IPPROTO_TCP: {
                pkt_process_tcp(nic, pkt_ptr);
                break;
            }// TCP数据包

            default:
                break;
        }

    }
}

// 处理ARP数据包
void pkt_process_arp(struct dpip_nic* nic, uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)(eth_hdr + 1);

    // 判断ARP的目的IP地址是否是本地IP地址
    if (arp_hdr->arp_data.arp_tip == nic->local_ip) {

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_tip, dst_ip, INET_ADDRSTRLEN);
        // LOGGER_DEBUG("<=========recv ARP========>src: %s, dst: %s, arp_opcode: %d", src_ip, dst_ip, rte_be_to_cpu_16(arp_hdr->arp_opcode));

        if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {

            struct rte_mbuf* arp_buf = get_arp_pkt(nic->pkt_send_pool
                                                , RTE_ARP_OP_REPLY
                                                , arp_hdr->arp_data.arp_sha.addr_bytes
                                                , nic->local_mac
                                                , arp_hdr->arp_data.arp_sip
                                                , nic->local_ip);
            if (arp_buf) {
                rte_ring_mp_enqueue(nic->out_pkt_ring, arp_buf);
            }
        } else if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REPLY) {
            update_arp_entry(&nic->arp_table, arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_sha.addr_bytes);
        }
        // dump_arp_table();
    }
}

// 处理socket实体中是否有数据包要发送
void process_socket_entries(struct dpip_nic* nic) {
    struct socket_table* sock_table = get_socket_table();
    if (!sock_table) {
        LOGGER_WARN("sock_table is NULL");
        return;
    }
    uint8_t broadcast_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    pthread_rwlock_rdlock(&sock_table->rwlock);

    // 遍历socket_hash_table，处理socket实体中是否有数据包要发送
    struct socket_key* key = NULL;
    struct socket_entry* entry = NULL;
    uint32_t next = 0;
    while (rte_hash_iterate(sock_table->socket_hash_table, (const void**)&key, (void**)&entry, &next) >= 0) {
        if (entry->protocol == IPPROTO_UDP) {
            struct udp_datagram* datagram = NULL;
            if (rte_ring_mc_dequeue(entry->udp.send_ring, (void**)&datagram) == 0) {

                pthread_cond_signal(&entry->notfull);

                struct arp_entry* arp_entry = get_mac_by_ip(&nic->arp_table, datagram->dst_ip);
                if (!arp_entry) {
                    struct rte_mbuf* arp_buf = get_arp_pkt(nic->pkt_send_pool
                                                        , RTE_ARP_OP_REQUEST
                                                        , broadcast_mac
                                                        , nic->local_mac
                                                        , datagram->dst_ip
                                                        , datagram->src_ip);
                    rte_ring_mp_enqueue(nic->out_pkt_ring, arp_buf);
                    // 将数据包重新放入发送队列
                    rte_ring_mp_enqueue(entry->udp.send_ring, datagram);
                } else {
                    struct rte_mbuf* udp_buf = get_udp_pkt(nic->pkt_send_pool
                                                        , datagram->data
                                                        , datagram->length
                                                        , arp_entry->mac
                                                        , nic->local_mac
                                                        , datagram->dst_ip
                                                        , datagram->src_ip
                                                        , datagram->dst_port
                                                        , datagram->src_port);
                    rte_ring_mp_enqueue(nic->out_pkt_ring, udp_buf);
                    rte_free(datagram->data);
                    rte_free(datagram);
                }
            }
        } else if (entry->protocol == IPPROTO_TCP) {
            pthread_mutex_lock(&entry->mutex);
            if (!(entry->tcp.status == DPIP_TCP_LISTEN || entry->tcp.status == DPIP_TCP_CLOSED)) {
                if (entry->tcp.send_info.unackedlen < entry->tcp.send_info.size && entry->tcp.send_info.unackedlen < entry->tcp.rx_win) {
                    uint32_t send_size = (entry->tcp.send_info.size > entry->tcp.rx_win ? entry->tcp.rx_win : entry->tcp.send_info.size) 
                                            - entry->tcp.send_info.unackedlen;
                    send_size = (send_size > DEFAULT_MSS) ? DEFAULT_MSS : send_size;
                    struct arp_entry* arp_entry = get_mac_by_ip(&nic->arp_table, entry->tcp.remote_ip);
                    if (!arp_entry) {
                        struct rte_mbuf* arp_buf = get_arp_pkt(nic->pkt_send_pool
                                                            , RTE_ARP_OP_REQUEST
                                                            , broadcast_mac
                                                            , nic->local_mac
                                                            , entry->tcp.remote_ip
                                                            , entry->tcp.local_ip);
                        rte_ring_mp_enqueue(nic->out_pkt_ring, arp_buf);
                        pthread_mutex_unlock(&entry->mutex);
                        continue;
                    }

                    uint8_t* data = (uint8_t*) rte_malloc("tcp_data", send_size, 0);
                    if (!data) {
                        LOGGER_WARN("rte_malloc tcp_data error");
                        pthread_mutex_unlock(&entry->mutex);
                        continue;
                    }
                    if (entry->tcp.send_info.read_index + entry->tcp.send_info.unackedlen + send_size > entry->tcp.send_info.capacity) {
                        uint32_t first_size = entry->tcp.send_info.capacity - entry->tcp.send_info.read_index - entry->tcp.send_info.unackedlen;
                        rte_memcpy(data, entry->tcp.send_info.buf + entry->tcp.send_info.read_index + entry->tcp.send_info.unackedlen, first_size);
                        rte_memcpy(data + first_size, entry->tcp.send_info.buf, send_size - first_size);
                    } else {
                        rte_memcpy(data, entry->tcp.send_info.buf + entry->tcp.send_info.read_index + entry->tcp.send_info.unackedlen, send_size);
                    }
                    entry->tcp.send_info.unackedlen += send_size;

                    struct rte_mbuf* tcp_buf = get_tcp_pkt(nic->pkt_send_pool
                                                        , arp_entry->mac
                                                        , nic->local_mac
                                                        , entry->tcp.remote_ip
                                                        , entry->tcp.local_ip
                                                        , entry->tcp.remote_port
                                                        , entry->tcp.local_port
                                                        , entry->tcp.send_next
                                                        , entry->tcp.recv_next
                                                        , RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG
                                                        , entry->tcp.recv_info.capacity - entry->tcp.recv_info.size
                                                        , data
                                                        , send_size);
                    rte_free(data);
                    rte_ring_mp_enqueue(nic->out_pkt_ring, tcp_buf);
                    entry->tcp.send_next += send_size;
                }
                if (entry->tcp.nead_send_fin == 1) {
                    struct arp_entry* arp_entry = get_mac_by_ip(&nic->arp_table, entry->tcp.remote_ip);
                    if (!arp_entry) {
                        struct rte_mbuf* arp_buf = get_arp_pkt(nic->pkt_send_pool
                                                            , RTE_ARP_OP_REQUEST
                                                            , broadcast_mac
                                                            , nic->local_mac
                                                            , entry->tcp.remote_ip
                                                            , entry->tcp.local_ip);
                        rte_ring_mp_enqueue(nic->out_pkt_ring, arp_buf);
                        pthread_mutex_unlock(&entry->mutex);
                        continue;
                    }
                    entry->tcp.nead_send_fin = 0;
                    struct rte_mbuf* tcp_fin_pkt = get_tcp_pkt(nic->pkt_send_pool
                                                            , arp_entry->mac
                                                            , nic->local_mac
                                                            , entry->tcp.remote_ip
                                                            , entry->tcp.local_ip
                                                            , entry->tcp.remote_port
                                                            , entry->tcp.local_port
                                                            , entry->tcp.send_next
                                                            , entry->tcp.recv_next
                                                            , RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG
                                                            , entry->tcp.recv_info.capacity - entry->tcp.recv_info.size
                                                            , NULL
                                                            , 0);
                    ++entry->tcp.send_next;
                    rte_ring_mp_enqueue(nic->out_pkt_ring, tcp_fin_pkt);
                }
            }             
            pthread_mutex_unlock(&entry->mutex);
        } // end if
    } // end while
    pthread_rwlock_unlock(&sock_table->rwlock);
}

// ARP请求定时器回调函数
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer* tim, void* arg) {
    struct dpip_nic* nic = (struct dpip_nic*)arg;

    uint8_t broadcast_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    for (int i = 1; i < 254; ++i) {
        uint32_t tip = (nic->local_ip & 0x00FFFFFF) | (i << 24);
        struct rte_mbuf* arp_pkt = get_arp_pkt(nic->pkt_send_pool, RTE_ARP_OP_REQUEST, broadcast_mac, nic->local_mac, tip, nic->local_ip);
        rte_ring_mp_enqueue(nic->out_pkt_ring, arp_pkt);
    }
}

// 子线程函数：从网卡接收数据包放到接收队列，从发送队列取出数据包发送到网卡
int pkt_recv_send(void* arg) {
    struct dpip_nic* nic = (struct dpip_nic*)arg;
    LOGGER_DEBUG("port_id=%d pkt_recv_send running", nic->port_id);

    while (1) {
        struct rte_mbuf* mbufs[BURST_SIZE];
        // 从网卡接收数据包
        unsigned rx_num = rte_eth_rx_burst(nic->port_id, 0, mbufs, BURST_SIZE);
        if (rx_num > 0) {
            // 将接收到的数据包放入接收队列
            rte_ring_mp_enqueue_bulk(nic->in_pkt_ring, (void**)mbufs, rx_num, NULL);
        }

        struct rte_mbuf* tx_mbufs[BURST_SIZE];
        // 从发送队列中取出数据包
        unsigned tx_num = rte_ring_mc_dequeue_burst(nic->out_pkt_ring, (void**)tx_mbufs, BURST_SIZE, NULL);
        if (tx_num > 0) {
            // 发送数据包到网卡
            rte_eth_tx_burst(nic->port_id, 0, tx_mbufs, tx_num);
            for (unsigned i = 0; i < tx_num; ++i) {
                rte_pktmbuf_free(tx_mbufs[i]);
            }
        }
    }
    return 0;
}

// 子线程函数：处理接收到的数据包
int pkt_process(void* arg) {
    struct dpip_nic* nic = (struct dpip_nic*)arg;
    LOGGER_DEBUG("port_id=%d pkt_process running", nic->port_id);

    rte_timer_subsystem_init();         // 初始化定时器子系统   
    struct rte_timer timer;             // 定时器
    rte_timer_init(&timer);             // 初始化定时器
    uint64_t hz = rte_get_timer_hz();   // 获取默认计时器一秒钟的循环数
    unsigned lcord_id = rte_lcore_id(); // 获取执行单元的应用程序线程 ID
    rte_timer_reset(&timer, hz, PERIODICAL, lcord_id, arp_request_timer_cb, nic); // 重置定时器
    uint64_t prev_tsc = 0;              // 前一个时间戳
    uint64_t cur_tsc;                   // 当前时间戳
    uint64_t diff_tsc;                  // 时间戳差值

    while (1) {
        struct rte_mbuf* mbufs[BURST_SIZE];
        unsigned rx_num = rte_ring_mc_dequeue_burst(nic->in_pkt_ring, (void**)mbufs, BURST_SIZE, NULL);

        for (unsigned i = 0; i < rx_num; ++i) {
            struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

            if (rte_is_broadcast_ether_addr(&eth_hdr->d_addr) || rte_is_same_ether_addr(&eth_hdr->d_addr, (struct rte_ether_addr*)nic->local_mac)) {
                switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
                    case RTE_ETHER_TYPE_IPV4: {
                        pkt_process_ipv4(nic, (uint8_t*)eth_hdr);
                        break;
                    }

                    case RTE_ETHER_TYPE_ARP: {
                        pkt_process_arp(nic, (uint8_t*)eth_hdr);
                        break;
                    }

                    default:
                        break;
                }
            }
            rte_pktmbuf_free(mbufs[i]);
        } // end for

        // 处理socket实体中是否有数据要发送
        process_socket_entries(nic);

        cur_tsc = rte_rdtsc();          // 获取当前时间戳
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
            LOGGER_DEBUG("rte_timer_manage");
            rte_timer_manage();         // 处理定时器任务
            prev_tsc = cur_tsc;
        }

    } // end while
    return 0;
}