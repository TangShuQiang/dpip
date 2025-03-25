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

#include <arpa/inet.h>

const uint32_t IPv4_ADDR[] = {
    MAKE_IPV4_ADDR(114, 213, 212, 113),
};

const uint32_t IPv4_MASK[] = {
    MAKE_IPV4_ADDR(255, 255, 255, 0),
};

#if 0
// UDP server
static void run_udp_server(void) {
    LOGGER_DEBUG("run_udp_server");

    int sockfd = dpip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        LOGGER_ERROR("dpip_socket error");
        return;
    }
    LOGGER_DEBUG("sockfd=%d", sockfd);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = MAKE_IPV4_ADDR(114, 213, 212, 113);
    addr.sin_port = htons(8080);

    if (dpip_bind(sockfd, (const struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGGER_ERROR("dpip_bind error");
        return;
    }

    LOGGER_DEBUG("dpip_bind success");

    char buf[1024] = {0};
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int len = dpip_recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &addrlen);
        if (len < 0) {
            LOGGER_ERROR("dpip_recvfrom error");
            break;
        }
        LOGGER_DEBUG("recvfrom %s:%d %s", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buf);

        len = dpip_sendto(sockfd, buf, len, 0, (struct sockaddr*)&client_addr, addrlen);
        if (len < 0) {
            LOGGER_ERROR("dpip_sendto error");
            break;
        }
    }
}
#endif

// TCP serve
static void run_tcp_server(void) {
    LOGGER_DEBUG("run_tcp_server");

    int sockfd = dpip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        LOGGER_ERROR("dpip_socket error");
        return;
    }
    LOGGER_DEBUG("sockfd=%d", sockfd);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = MAKE_IPV4_ADDR(114, 213, 212, 113);
    addr.sin_port = htons(8080);

    if (dpip_bind(sockfd, (const struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGGER_ERROR("dpip_bind error");
        return;
    }

    LOGGER_DEBUG("dpip_bind success");

    if (dpip_listen(sockfd, 5) < 0) {
        LOGGER_ERROR("dpip_listen error");
        return;
    }

    LOGGER_DEBUG("dpip_listen success");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int fd = dpip_accept(sockfd, (struct sockaddr*)&client_addr, &addrlen);
        if (fd < 0) {
            LOGGER_ERROR("dpip_accept error");
            return;
        }
        LOGGER_DEBUG("dpip_accept success, fd=%d, %s:%d", fd, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        while (1) {

            char buf[1024] = {0};
            int len = dpip_recv(fd, buf, sizeof(buf), 0);
            if (len < 0) {
                LOGGER_ERROR("dpip_recv error");
                break;
            } else if (len == 0) {
                LOGGER_DEBUG("client is closed");
                dpip_close(fd);
                break;
            }
            LOGGER_DEBUG("recv %s", buf);

            len = dpip_send(fd, buf, len, 0);
            if (len < 0) {
                LOGGER_ERROR("dpip_send error");
                break;
            }
            LOGGER_DEBUG("send len=%d", len);
        }
    }
}

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
        if (dpip_nic_init(&nic[port_id], port_id, IPv4_ADDR[port_id], IPv4_MASK[port_id])) {
            LOGGER_ERROR("dpip_nic_init port_id=%d error", port_id);
            return -1;
        }

        lcord_id = rte_get_next_lcore(lcord_id, 1, 0);
        rte_eal_remote_launch(pkt_recv_send, &nic[port_id], lcord_id);

        lcord_id = rte_get_next_lcore(lcord_id, 1, 1);
        rte_eal_remote_launch(pkt_process, &nic[port_id], lcord_id);
    }
    LOGGER_DEBUG("dpip_nic_init success");

    // run_udp_server();

    run_tcp_server();

    rte_eal_mp_wait_lcore();
}