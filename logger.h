#ifndef LOGGER_H
#define LOGGER_H
#include <stdio.h>
#include <pthread.h>
#include <time.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

void logger_init(LogLevel level);
void logger_log(LogLevel level, const char *fmt, ...);
void logger_shutdown(void);

#endif
