#include "dpip_logger.h"
#include "dpip_pkt.h"
#include "dpip_arptable.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_timer.h>

#include <arpa/inet.h>

#define NUM_MBUFS (4096 - 1)                // mbuf池大小
#define BURST_SIZE 32                       // 数据包接收数量
#define RING_SIZE 1024                      // 环形队列大小
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))   // IPV4地址构造

// 2000000000 = 1s
#define TIMER_RESOLUTION_CYCLES 2000000000ULL * 60 * 5     // 5min

int gDpdkPortId = 0;                        // 网卡端口ID

struct rte_ring* gInPktRing = NULL;         // 接收数据包环形队列
struct rte_ring* gOutPktRing = NULL;        // 发送数据包环形队列

uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];        // 源MAC地址

uint8_t gBroadcastMac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // 广播MAC地址
uint8_t gZerorMac[RTE_ETHER_ADDR_LEN] = { 0, 0, 0, 0, 0, 0 };                       // 零MAC地址

uint32_t gLocalIp = MAKE_IPV4_ADDR(114, 213, 212, 113);                            // 本地IP地址

uint32_t gBroadcaseIp = MAKE_IPV4_ADDR(114, 213, 212, 255);                        // 广播IP地址

const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 处理ICMP数据包
static void pkt_process_icmp(struct rte_mempool* mbuf_pool, uint8_t* pkt_ptr) {
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

        struct rte_mbuf* icmp_buf = get_icmp_pkt(mbuf_pool
                                                , eth_hdr->s_addr.addr_bytes
                                                , gSrcMac
                                                , ip_hdr->src_addr
                                                , gLocalIp
                                                , icmp_hdr->icmp_ident
                                                , icmp_hdr->icmp_seq_nb);
        if (icmp_buf) {
            rte_ring_mp_enqueue(gOutPktRing, icmp_buf);
        }
    }
}

// 处理IPV4数据包
static void pkt_process_ipv4(struct rte_mempool* mbuf_pool, uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);

    // 判断目的IP地址是否是广播地址或者本地IP地址
    if (ip_hdr->dst_addr == gBroadcaseIp || ip_hdr->dst_addr == gLocalIp) {

        switch (ip_hdr->next_proto_id) {
            // 判断是否为ICMP数据包
            case IPPROTO_ICMP: {
                pkt_process_icmp(mbuf_pool, pkt_ptr);
                break;
            }// ICMP数据包

            default:
                break;
        }

    }
}

// 处理ARP数据包
static void pkt_process_arp(struct rte_mempool* mbuf_pool, uint8_t* pkt_ptr) {
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*)pkt_ptr;
    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)(eth_hdr + 1);

    // 判断ARP的目的IP地址是否是本地IP地址
    if (arp_hdr->arp_data.arp_tip == gLocalIp) {

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_tip, dst_ip, INET_ADDRSTRLEN);
        LOGGER_DEBUG("<=========recv ARP========>src: %s, dst: %s, arp_opcode: %d", src_ip, dst_ip, rte_be_to_cpu_16(arp_hdr->arp_opcode));

        if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {

            struct rte_mbuf* arp_buf = get_arp_pkt(mbuf_pool
                                                , RTE_ARP_OP_REPLY
                                                , arp_hdr->arp_data.arp_sha.addr_bytes
                                                , gSrcMac
                                                , arp_hdr->arp_data.arp_sip
                                                , gLocalIp);
            if (arp_buf) {
                rte_ring_mp_enqueue(gOutPktRing, arp_buf);
            }
        } else if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REPLY) {
            update_arp_entry(arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_sha.addr_bytes);
        }
        // dump_arp_table();
    }
}

// 数据包处理函数
static int pkt_process(void* arg) {
    struct rte_mempool* mbuf_pool = (struct rte_mempool*)arg;

    LOGGER_DEBUG("pkt_process running");

    while (1) {
        struct rte_mbuf* mbufs[BURST_SIZE];
        unsigned rx_num = rte_ring_mc_dequeue_burst(gInPktRing, (void**)mbufs, BURST_SIZE, NULL);

        for (unsigned i = 0; i < rx_num; ++i) {
            struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

            // 判断目的MAC地址是否是广播地址或者本地MAC地址
            if (rte_is_broadcast_ether_addr(&eth_hdr->d_addr) || rte_is_same_ether_addr(&eth_hdr->d_addr, (struct rte_ether_addr*)gSrcMac)) {

                switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
                    // 判断是否为IPV4数据包
                    case RTE_ETHER_TYPE_IPV4: {
                        pkt_process_ipv4(mbuf_pool, (uint8_t*)eth_hdr);
                        break;
                    }// IPV4数据包

                    // 判断是否为ARP数据包
                    case RTE_ETHER_TYPE_ARP: {
                        pkt_process_arp(mbuf_pool, (uint8_t*)eth_hdr);
                        break;
                    }  // ARP数据包

                    default:
                        break;
                }
            }

            rte_pktmbuf_free(mbufs[i]);
        } // for
    } // while
    return 0;
}

// ARP请求定时器回调函数
static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer* tim, void* arg) {
    struct rte_mempool* mbuf_pool = (struct rte_mempool*)arg;

    for (int i = 1; i < 254; ++i) {
        uint32_t tip = (gLocalIp & 0x00FFFFFF) | (i << 24);
        struct rte_mbuf* arp_pkt = get_arp_pkt(mbuf_pool, RTE_ARP_OP_REQUEST, gBroadcastMac, gSrcMac, tip, gLocalIp);
        rte_ring_mp_enqueue(gOutPktRing, arp_pkt);
    }
}

int main(int argc, char* argv[]) {
    /*
        初始化DPDK
    */
    if (rte_eal_init(argc, argv) < 0) {
        LOGGER_ERROR("rte_eal_init error");
        return -1;
    }

    /*
       获取系统端口数量
   */
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        LOGGER_ERROR("nb_sys_ports == 0");
        return -1;
    }
    LOGGER_DEBUG("nb_sys_ports=%d", nb_sys_ports);

    /*
       创建mbuf池
   */
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        LOGGER_ERROR("rte_pktmbuf_pool_create error");
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    /*
        获取端口信息
    */
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;

    /*
        配置端口
    */
    if (rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf)) {
        LOGGER_ERROR("rte_eth_dev_configure error");
        return -1;
    }

    /*
        配置接收队列
    */
    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
        LOGGER_ERROR("rte_eth_rx_queue_setup error");
        return -1;
    }

    /*
        发送队列配置
    */
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;

    /*
        配置发送队列
    */
    if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
        LOGGER_ERROR("rte_eth_tx_queue_setup error");
        return -1;
    }

    /*
        启动端口
    */
    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        LOGGER_ERROR("rte_eth_dev_start error");
        return -1;
    }

    // 获取源MAC地址
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)gSrcMac);

    /*
        创建接收和发送数据包环形队列
    */
    gInPktRing = rte_ring_create("in_pkt_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!gInPktRing) {
        LOGGER_ERROR("rte_ring_create in_pkt_ring error");
        return -1;
    }
    gOutPktRing = rte_ring_create("out_pkt_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!gOutPktRing) {
        LOGGER_ERROR("rte_ring_create out_pkt_ring error");
        return -1;
    }

    rte_timer_subsystem_init();         // 初始化定时器子系统   
    struct rte_timer timer;             // 定时器
    rte_timer_init(&timer);             // 初始化定时器
    uint64_t hz = rte_get_timer_hz();   // 获取默认计时器一秒钟的循环数
    unsigned lcord_id = rte_lcore_id(); // 获取执行单元的应用程序线程 ID
    rte_timer_reset(&timer, hz, PERIODICAL, lcord_id, arp_request_timer_cb, mbuf_pool); // 重置定时器
    uint64_t prev_tsc = 0;              // 前一个时间戳
    uint64_t cur_tsc;                   // 当前时间戳
    uint64_t diff_tsc;                  // 时间戳差值

    lcord_id = rte_get_next_lcore(lcord_id, 1, 1);

    /*
        启动线程执行数据包处理函数
    */
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcord_id);

    LOGGER_DEBUG("main running");

    while (1) {

        struct rte_mbuf* rx_mbufs[BURST_SIZE];

        /*
          接收数据包：
       */
        unsigned rx_num = rte_eth_rx_burst(gDpdkPortId, 0, rx_mbufs, BURST_SIZE);
        if (rx_num > 0) {
            // 将接收到的数据包放入接收队列
            rte_ring_mp_enqueue_bulk(gInPktRing, (void**)rx_mbufs, rx_num, NULL);
        }

        struct rte_mbuf* tx_mbufs[BURST_SIZE];
        // 从发送队列中取出数据包发送
        unsigned tx_num = rte_ring_mc_dequeue_burst(gOutPktRing, (void**)tx_mbufs, BURST_SIZE, NULL);
        if (tx_num > 0) {
            rte_eth_tx_burst(gDpdkPortId, 0, tx_mbufs, tx_num);
            for (unsigned i = 0; i < tx_num; ++i) {
                rte_pktmbuf_free(tx_mbufs[i]);
            }
        }

        cur_tsc = rte_rdtsc();          // 获取当前时间戳
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
            LOGGER_DEBUG("rte_timer_manage");
            rte_timer_manage();         // 处理定时器任务
            prev_tsc = cur_tsc;
        }
    }

}