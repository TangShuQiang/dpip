#include "dpip_logger.h"
#include "dpip_pkt.h"
#include "dpip_arptable.h"
#include "dpip_socket.h"
#include "dpip_nic.h"
#include "dpip_config.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

const uint32_t IPv4_ADDR[] = {
    MAKE_IPV4_ADDR(114, 213, 212, 113),
};

int main(int argc, char* argv[]) {
    // 初始化DPDK环境
    if (rte_eal_init(argc, argv) < 0) {
        LOGGER_ERROR("rte_eal_init error");
        return -1;
    }

    // 获取系统端口数量
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        LOGGER_ERROR("nb_sys_ports == 0");
        return -1;
    }
    LOGGER_DEBUG("nb_sys_ports=%d", nb_sys_ports);

    struct dpip_nic* nic = (struct dpip_nic*)rte_malloc("dpip_nic", sizeof(struct dpip_nic) * nb_sys_ports, 0);
    if (!nic) {
        LOGGER_ERROR("rte_malloc dpip_nic error");
        return -1;
    }
    memset(nic, 0, sizeof(struct dpip_nic) * nb_sys_ports);

    unsigned lcord_id = rte_lcore_id(); // 获取执行单元的应用程序线程 ID

    for (uint16_t port_id = 0; port_id < nb_sys_ports; ++port_id) {
        if (dpip_nic_init(&nic[port_id], port_id, IPv4_ADDR[port_id])) {
            LOGGER_ERROR("dpip_nic_init port_id=%d error", port_id);
            return -1;
        }

        lcord_id = rte_get_next_lcore(lcord_id, 1, 0);
        rte_eal_remote_launch(pkt_recv_send, &nic[port_id], lcord_id);

        lcord_id = rte_get_next_lcore(lcord_id, 1, 1);
        rte_eal_remote_launch(pkt_process, &nic[port_id], lcord_id);
    }
    LOGGER_DEBUG("dpip_nic_init success");

    rte_eal_mp_wait_lcore();
}