#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>


static LogLevel current_level = LOG_INFO;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char* level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

void logger_init(LogLevel level) {
    current_level = level;
    logger_log(LOG_INFO, "Logger initialized with level %s", level_strings[level]);
}

void logger_log(LogLevel level, const char *format, ...) {
    if (level < current_level) {
        return;
    }

    pthread_mutex_lock(&log_mutex);

    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    char time_buffer[26];
    strftime(time_buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stdout, "[%s] [%s] ", time_buffer, level_strings[level]);

    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);

    fprintf(stdout, "\n");
    fflush(stdout);

    pthread_mutex_unlock(&log_mutex);
}

void logger_shutdown(void) {
    logger_log(LOG_INFO, "Logger shutting down");
    pthread_mutex_destroy(&log_mutex);
}