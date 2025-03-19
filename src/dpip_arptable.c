#include "dpip_arptable.h"
#include "dpip_logger.h"

#include <rte_malloc.h>

#include <arpa/inet.h>

static struct arp_table arp_table = { 0 };            // ARP表

// 通过IP地址获取ARP表项
struct arp_entry* get_mac_by_ip(uint32_t ip) {
    pthread_rwlock_rdlock(&arp_table.rwlock);
    struct arp_entry* entry = arp_table.head;
    while (entry) {
        if (entry->ip == ip) {
            return entry;
        }
        entry = entry->next;
    }
    pthread_rwlock_unlock(&arp_table.rwlock);
    return NULL;
}

// 更新ARP表项
void update_arp_entry(uint32_t ip, uint8_t* mac) {
    pthread_rwlock_wrlock(&arp_table.rwlock);
    struct arp_entry* entry = arp_table.head;
    while (entry) {
        if (entry->ip == ip) {
            rte_ether_addr_copy((struct rte_ether_addr*)mac, (struct rte_ether_addr*)entry->mac);
            return;
        }
        entry = entry->next;
    }
    entry = (struct arp_entry*)rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
    if (entry) {
        entry->ip = ip;
        rte_ether_addr_copy((struct rte_ether_addr*)mac, (struct rte_ether_addr*)entry->mac);
        entry->prev = NULL;
        entry->next = arp_table.head;
        if (arp_table.head) {
            arp_table.head->prev = entry;
        }
        arp_table.head = entry;
        ++arp_table.count;
    }
    pthread_rwlock_unlock(&arp_table.rwlock);
}

// 打印ARP表
void dump_arp_table(void) {
    pthread_rwlock_rdlock(&arp_table.rwlock);
    for (struct arp_entry* entry = arp_table.head; entry; entry = entry->next) {
        struct in_addr addr;
        addr.s_addr = entry->ip;
        LOGGER_DEBUG("ip=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X", inet_ntoa(addr), entry->mac[0], entry->mac[1], entry->mac[2], entry->mac[3], entry->mac[4], entry->mac[5]);
    }
    pthread_rwlock_unlock(&arp_table.rwlock);
}