#include "dpip_logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>

// 互斥锁
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char* color, const char* level, const char* file, const char* func, int line, const char* fmt, ...) {
    pthread_mutex_lock(&log_mutex);

    // 处理可变参数
    va_list args;
    va_start(args, fmt);

    char* buf = NULL;
    int len = vasprintf(&buf, fmt, args);

    if (len != -1) {
        // 输出到 stderr
        if (LOG_TO_CONSOLE) {
            fprintf(stderr, "%s[%s] %s  %s  %d:%s%s\n", color, level, file, func, line, buf, COLOR_RESET);
        }

        // 输出到日志文件
        if (LOG_TO_FILE) {
            FILE* log_file = fopen(LOG_FILE_PATH, "a");
            if (log_file) {
                fprintf(log_file, "[%s] %s  %s  %d:%s\n", level, file, func, line, buf);
                fflush(log_file);
                fclose(log_file);
            } else {
                perror("Logger: Failed to open log file");
            }
        }
        free(buf);
    }
    va_end(args);
    pthread_mutex_unlock(&log_mutex);
}