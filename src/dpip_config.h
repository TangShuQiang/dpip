#ifndef __DPIP_CONFIG_H__
#define __DPIP_CONFIG_H__

#define COLOR_DEBUG  "\033[0m"    // 默认颜色
#define COLOR_WARN   "\033[33m"   // 黄色
#define COLOR_ERROR  "\033[31m"   // 红色
#define COLOR_RESET  "\033[0m"    // 颜色重置

// 日志输出控制
#define LOG_TO_CONSOLE      1       // 1 = 允许输出到 stderr，0 = 关闭
#define LOG_TO_FILE         1       // 1 = 允许输出到日志文件，0 = 关闭
#define LOG_FILE_PATH       "log.txt"

// 日志级别控制
#define LOG_LEVEL_DEBUG     1       // 1 = 启用 debug 日志, 0 = 禁用
#define LOG_LEVEL_WARN      1       // 1 = 启用 warn 日志, 0 = 禁用
#define LOG_LEVEL_ERROR     1       // 1 = 启用 error 日志, 0 = 禁用

#define NUM_MBUFS 4096                // mbuf池大小
#define RING_SIZE 4096                // 环形队列大小
#define BURST_SIZE 32                 // 数据包接收数量

#define NUM_RX_DESC 1024               // 接收描述符数量
#define NUM_TX_DESC 1024               // 发送描述符数量

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))   // IPV4地址构造

// 2000000000 = 1s
#define TIMER_RESOLUTION_CYCLES 2000000000ULL * 60 * 5     // 5min

#define MAX_FD_COUNT            1024            // 最多文件描述符数量

#define UDP_RECV_RING_SIZE      1024            // UDP接收环形队列大小
#define UDP_SEND_RING_SIZE      1024            // UDP发送环形队列大小


#endif