#ifndef __DPIP_PKT_H__
#define __DPIP_PKT_H__

#include <rte_ether.h>


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
                    , uint8_t proto);

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

#endif