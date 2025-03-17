#include "logger.h"

#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

// 互斥锁
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char *color, const char *level, const char *file, const char *func, int line, const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);

    // 处理可变参数
    va_list args;
    va_start(args, fmt);

    va_list args_copy;
    va_copy(args_copy, args);  // 复制 va_list，避免参数解析错误

    // 输出到 stderr
    if (LOG_TO_CONSOLE) {
        fprintf(stderr, "%s[%s] %s:%s:%d ", color, level, file, func, line);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "%s\n", COLOR_RESET);
    }

    // 输出到日志文件
    if (LOG_TO_FILE) {
        FILE *log_file = fopen(LOG_FILE_PATH, "a");
        if (log_file) {
            fprintf(log_file, "[%s] %s:%s:%d ", level, file, func, line);
            vfprintf(log_file, fmt, args_copy);
            fprintf(log_file, "\n");
            fflush(log_file);
            fclose(log_file);
        } else {
            perror("Logger: Failed to open log file");
        }
    }
    va_end(args_copy);  // 释放 args_copy
    va_end(args);
    pthread_mutex_unlock(&log_mutex);
}