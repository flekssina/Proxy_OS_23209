#ifndef PROXY_H
#define PROXY_H

#include "thread_pool.h"
#include <stdbool.h>

typedef struct {
    int port;
    int max_threads;
    int server_fd;
    thread_pool_t *pool;
    volatile bool running;
} proxy_config_t;

int proxy_init(proxy_config_t *config);
int proxy_run(proxy_config_t *config);
void proxy_shutdown(proxy_config_t *config);

#endif