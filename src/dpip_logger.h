#ifndef __DPIP_LOGGER_H__
#define __DPIP_LOGGER_H__

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

// 日志核心函数（线程安全）
void log_message(const char *color, const char *level, const char *file, const char *func, int line, const char *fmt, ...);

#if LOG_LEVEL_DEBUG
  #define LOGGER_DEBUG(fmt, ...)  log_message(COLOR_DEBUG,  "DEBUG",  __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#else
  #define LOGGER_DEBUG(fmt, ...)
#endif

#if LOG_LEVEL_WARN
  #define LOGGER_WARN(fmt, ...)  log_message(COLOR_WARN,  "WARN",  __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#else
  #define LOGGER_WARN(fmt, ...)
#endif

#if LOG_LEVEL_ERROR
  #define LOGGER_ERROR(fmt, ...) log_message(COLOR_ERROR, "ERROR", __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#else
  #define LOGGER_ERROR(fmt, ...)
#endif

#endif