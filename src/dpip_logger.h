#ifndef __DPIP_LOGGER_H__
#define __DPIP_LOGGER_H__

#include "dpip_config.h"

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