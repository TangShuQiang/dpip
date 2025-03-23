#ifndef __DPIP_PKT_H__
#define __DPIP_PKT_H__

#include "dpip_nic.h"
#include "dpip_socket.h"

#include <rte_ether.h>
#include <rte_timer.h>

/*
    编码数据包以太网头部
*/
void encode_ether_hdr(uint8_t* pkt_ptr
                    , uint8_t* dst_mac
                    , uint8_t* src_mac
                    , uint16_t ether_type);

/*
    编码IPV4头部
*/
void encode_ipv4_hdr(uint8_t* pkt_pkt
                    , uint32_t dst_ip
                    , uint32_t src_ip
                    , uint8_t proto
                    , uint16_t length);

/*
    编码ICMP头部
*/
void encode_icmp_hdr(uint8_t* pkt_ptr
                    , uint8_t type
                    , uint8_t code
                    , uint16_t ident
                    , uint16_t seqnb);

/*
    编码ARP头部
*/
void encode_arp_hdr(uint8_t* pkt_ptr
                    , uint16_t opcode
                    , uint8_t* dst_mac
                    , uint8_t* src_mac
                    , uint32_t tip
                    , uint32_t sip);

/*
    编码UDP头部
*/
void encode_udp_hdr(uint8_t* pkt_ptr
                    , uint16_t src_port
                    , uint16_t dst_port
                    , uint8_t* data
                    , uint16_t length);

/*
    编码TCP头部
*/
void encode_tcp_hdr(uint8_t* pkt_ptr
                    , uint16_t src_port
                    , uint16_t dst_port
                    , uint32_t seq
                    , uint32_t ack
                    , uint8_t flags
                    , uint16_t rx_win
                    , uint8_t* data
                    , uint16_t length);

/*
    获得ICMP数据包
*/
struct rte_mbuf* get_icmp_pkt(struct rte_mempool* mbuf_pool
                                , uint8_t* dst_mac
                                , uint8_t* src_mac
                                , uint32_t tip
                                , uint32_t sip
                                , uint16_t id
                                , uint16_t seqnb);

/*
    获得ARP数据包
*/
struct rte_mbuf* get_arp_pkt(struct rte_mempool* mbuf_pool
                            , uint16_t opcode
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t tip
                            , uint32_t sip);

/*
    获得UDP数据包
*/
struct rte_mbuf* get_udp_pkt(struct rte_mempool* mbuf_pool
                            , uint8_t* data
                            , uint16_t length               // 数据长度
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t dst_ip
                            , uint32_t src_ip
                            , uint16_t dst_port
                            , uint16_t src_port);

/*
    获得TCP数据包
*/
struct rte_mbuf* get_tcp_pkt(struct rte_mempool* mbuf_pool  
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , struct tcp_segment* segment);

/*
    发送ACK确认数据包
*/
void pkt_process_tcp_send_ack(struct socket_entry* tcp_sock_entry
                            , uint8_t* pkt_ptr);

/*
    发送FIN数据包
*/
void pkt_process_tcp_send_fin(struct socket_entry* tcp_sock_entry
                            , uint8_t* pkt_ptr);

/*
    处理 ESTABLISHED 状态下（DPIP_TCP_ESTABLISHED） 的TCP数据包
*/
void pkt_process_tcp_on_established(struct socket_entry* tcp_sock_entry
                                    , uint8_t* pkt_ptr);

/*
    处理 监听状态下（DPIP_TCP_LISTEN） 的TCP数据包
*/
void pkt_process_tcp_on_listen(struct socket_entry* tcp_sock_entry
                                , uint8_t* pkt_ptr);

/*
    处理 LAST_ACK 状态下（DPIP_TCP_LAST_ACK） 的TCP数据包
*/
void pkt_process_tcp_on_last_ack(struct socket_entry* tcp_sock_entry
                                , __attribute__((unused)) uint8_t* pkt_ptr);

/*
    处理ICMP数据包
*/
void pkt_process_icmp(struct dpip_nic* nic
                    , uint8_t* pkt_ptr);

/*
    处理UDP数据包
*/
void pkt_process_udp(__attribute__((unused)) struct dpip_nic* nic
                    , uint8_t* pkt_ptr);

/*
    处理TCP数据包
*/
void pkt_process_tcp(__attribute__((unused)) struct dpip_nic* nic
                    , uint8_t* pkt_ptr);

/*
    处理IPv4数据包
*/
void pkt_process_ipv4(struct dpip_nic* nic
                    , uint8_t* pkt_ptr);

/*
    处理ARP数据包
*/
void pkt_process_arp(struct dpip_nic* nic
                    , uint8_t* pkt_ptr);

/*
    处理socket实体中是否有数据要发送
*/
void process_socket_entries(struct dpip_nic* nic);

/*
    ARP请求定时器回调函数
*/
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer* tim
                        , void* arg);

/*
    子线程函数：从网卡接收数据包放到接收队列，从发送队列取出数据包发送到网卡
*/ 
int pkt_recv_send(void* arg);

/*
    子线程函数：处理接收队列中的数据包
*/
int pkt_process(void* arg);

#endif