#ifndef __DPIP_NIC_H__
#define __DPIP_NIC_H__

#include "dpip_arptable.h"

#include <rte_ether.h>
#include <rte_ethdev.h>

struct dpip_nic
{
    uint16_t port_id;                                     // 网卡端口ID
    struct rte_mempool* pkt_recv_pool;                    // mbuf池: 用于存储接收数据包
    struct rte_mempool* pkt_send_pool;                    // mbuf池: 用于存储发送数据包

    uint8_t local_mac[RTE_ETHER_ADDR_LEN];                // 本地MAC地址
    struct arp_table arp_table;                           // ARP表

    uint32_t local_ip;                                    // 本地IP地址
    uint32_t broadcast_ip;                                // 广播IP地址
    
    struct rte_ring* in_pkt_ring;                         // 接收数据包环形队列
    struct rte_ring* out_pkt_ring;                        // 发送数据包环形队列
};

// 初始化网卡
int dpip_nic_init(struct dpip_nic* nic, uint16_t port_id, uint32_t local_ip);

#endif