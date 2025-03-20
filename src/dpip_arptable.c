#include "dpip_arptable.h"
#include "dpip_logger.h"

#include <rte_malloc.h>

#include <arpa/inet.h>

// 初始化ARP表
void arp_table_init(struct arp_table* table) {
    if (!table) {
        LOGGER_ERROR("arptable is NULL");
        return;
    }
    table->head = NULL;
    pthread_rwlock_init(&table->rwlock, NULL);
}

// 通过IP地址获取ARP表项
struct arp_entry* get_mac_by_ip(struct arp_table* table, uint32_t ip) {
    if (!table) {
        LOGGER_ERROR("arptable is NULL");
        return NULL;
    }
    pthread_rwlock_rdlock(&table->rwlock);
    struct arp_entry* entry = table->head;
    while (entry) {
        if (entry->ip == ip) {
            return entry;
        }
        entry = entry->next;
    }
    pthread_rwlock_unlock(&table->rwlock);
    return NULL;
}

// 更新ARP表项
void update_arp_entry(struct arp_table* table, uint32_t ip, uint8_t* mac) {
    if (!table) {
        LOGGER_ERROR("arptable is NULL");
        return;
    }
    pthread_rwlock_wrlock(&table->rwlock);
    struct arp_entry* entry = table->head;
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
        entry->next = table->head;
        if (table->head) {
            table->head->prev = entry;
        }
        table->head = entry;
    }
    pthread_rwlock_unlock(&table->rwlock);
}

// 打印ARP表
void dump_arp_table(struct arp_table* table) {
    if (!table) {
        LOGGER_ERROR("arptable is NULL");
        return;
    }
    pthread_rwlock_rdlock(&table->rwlock);
    for (struct arp_entry* entry = table->head; entry; entry = entry->next) {
        struct in_addr addr;
        addr.s_addr = entry->ip;
        LOGGER_DEBUG("ip=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X", inet_ntoa(addr), entry->mac[0], entry->mac[1], entry->mac[2], entry->mac[3], entry->mac[4], entry->mac[5]);
    }
    pthread_rwlock_unlock(&table->rwlock);
}