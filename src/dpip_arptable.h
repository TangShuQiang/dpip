#ifndef __DPIP_ARPTABLE_H__
#define __DPIP_ARPTABLE_H__

#include <rte_ether.h>

#define ARP_ENTRY_STATUS_DYNAMIC    0
#define ARP_ENTRY_STATUS_STATIC     1

// ARP表项
struct arp_entry
{
    uint32_t ip;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    uint8_t type;

    struct arp_entry* next;
    struct arp_entry* prev;
};

// ARP表
struct arp_table
{
    struct arp_entry* head;

    // 读写锁
    pthread_rwlock_t rwlock;
};

// 初始化ARP表
void arp_table_init(struct arp_table* table);

// 通过IP地址获取ARP表项
struct arp_entry* get_mac_by_ip(struct arp_table* table, uint32_t ip);

// 更新ARP表项
void update_arp_entry(struct arp_table* table, uint32_t ip, uint8_t* mac);

// 打印ARP表
void dump_arp_table(struct arp_table* table);

#endif