#include "dpip_pkt.h"
#include "dpip_logger.h"

#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_arp.h>

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
                    , uint8_t proto) {
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)pkt_pkt;
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
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

struct rte_mbuf* get_icmp_pkt(struct rte_mempool* mbuf_pool
                            , uint8_t* dst_mac
                            , uint8_t* src_mac
                            , uint32_t tip
                            , uint32_t sip
                            , uint16_t id
                            , uint16_t seqnb) {
    unsigned total_length = sizeof(struct rte_ether_hdr) +sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
    
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
    encode_ipv4_hdr(pkt_ptr, tip, sip, IPPROTO_ICMP);
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