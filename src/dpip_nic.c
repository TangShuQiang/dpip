#include "dpip_nic.h"
#include "dpip_config.h"
#include "dpip_logger.h"


const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 初始化网卡
int dpip_nic_init(struct dpip_nic* nic, uint16_t port_id, uint32_t local_ip) {
    if (!nic) {
        LOGGER_ERROR("nic is NULL");
        return -1;
    }

    // 网卡端口ID
    nic->port_id = port_id;

    // 接收队列数量
    nic->local_ip = local_ip;

    // 设置广播IP地址
    nic->broadcast_ip = (nic->local_ip | 0xFF000000);

    // 获取源MAC地址
    rte_eth_macaddr_get(nic->port_id, (struct rte_ether_addr*)nic->local_mac);

    // 初始化ARP表
    arp_table_init(&nic->arp_table);

    // 创建接收数据包mbuf池
    nic->pkt_recv_pool = rte_pktmbuf_pool_create("pkt_recv_pool"
        , NUM_MBUFS
        , 0
        , 0
        , RTE_MBUF_DEFAULT_BUF_SIZE
        , rte_socket_id());
    if (!nic->pkt_recv_pool) {
        LOGGER_ERROR("rte_pktmbuf_pool_create pkt_recv_pool error");
        return -1;
    }

    // 创建发送数据包mbuf池
    nic->pkt_send_pool = rte_pktmbuf_pool_create("pkt_send_pool"
        , NUM_MBUFS
        , 0
        , 0
        , RTE_MBUF_DEFAULT_BUF_SIZE
        , rte_socket_id());
    if (!nic->pkt_send_pool) {
        LOGGER_ERROR("rte_pktmbuf_pool_create pkt_send_pool error");
        rte_mempool_free(nic->pkt_recv_pool);
        return -1;
    }

    // 获取端口信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(nic->port_id, &dev_info);

    // 配置端口
    if (rte_eth_dev_configure(nic->port_id, 1, 1, &port_conf_default)) {
        LOGGER_ERROR("rte_eth_dev_configure error");
        rte_mempool_free(nic->pkt_recv_pool);
        rte_mempool_free(nic->pkt_send_pool);
        return -1;
    }

    // 配置接收队列
    if (rte_eth_rx_queue_setup(nic->port_id, 0, NUM_RX_DESC, rte_eth_dev_socket_id(nic->port_id), NULL, nic->pkt_recv_pool) < 0) {
        LOGGER_ERROR("rte_eth_rx_queue_setup error");
        rte_mempool_free(nic->pkt_recv_pool);
        rte_mempool_free(nic->pkt_send_pool);
        return -1;
    }

    // 发送队列配置
    if (rte_eth_tx_queue_setup(nic->port_id, 0, NUM_TX_DESC, rte_eth_dev_socket_id(nic->port_id), NULL) < 0) {
        LOGGER_ERROR("rte_eth_tx_queue_setup error");
        rte_mempool_free(nic->pkt_recv_pool);
        rte_mempool_free(nic->pkt_send_pool);
        return -1;
    }

    // 启动端口
    if (rte_eth_dev_start(nic->port_id) < 0) {
        LOGGER_ERROR("rte_eth_dev_start error");
        rte_mempool_free(nic->pkt_recv_pool);
        rte_mempool_free(nic->pkt_send_pool);
        return -1;
    }

    // 创建接收和发送数据包环形队列
    char ring_name[32];
    static int ring_id = 0;
    snprintf(ring_name, sizeof(ring_name), "in_pkt_ring_id_%d", ring_id);
    nic->in_pkt_ring = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!nic->in_pkt_ring) {
        LOGGER_ERROR("rte_ring_create %s error", ring_name);
        rte_mempool_free(nic->pkt_recv_pool);
        rte_mempool_free(nic->pkt_send_pool);
        return -1;
    }
    snprintf(ring_name, sizeof(ring_name), "out_pkt_ring_id_%d", ring_id++);
    nic->out_pkt_ring = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!nic->out_pkt_ring) {
        LOGGER_ERROR("rte_ring_create %s error", ring_name);
        rte_mempool_free(nic->pkt_recv_pool);
        rte_mempool_free(nic->pkt_send_pool);
        return -1;
    }

    return 0;
}