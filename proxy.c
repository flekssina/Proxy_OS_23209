#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>

#include "proxy.h"
#include "http_handler.h"
#include "logger.h"

int proxy_init(proxy_config_t *config) {
    logger_log(LOG_INFO, "Initializing proxy on port %d with %d threads", config->port, config->max_threads);
    config->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (config->server_fd < 0) {
        logger_log(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(config->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger_log(LOG_ERROR, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(config->server_fd);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config->port);  
    if (bind(config->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        logger_log(LOG_ERROR, "Failed to bind to port %d: %s", config->port, strerror(errno));
        close(config->server_fd);
        return -1;
    }
    
    if (listen(config->server_fd, 128) < 0) {
        logger_log(LOG_ERROR, "Failed to listen: %s", strerror(errno));
        close(config->server_fd);
        return -1;
    }
    
    config->pool = thread_pool_create(config->max_threads);
    if (config->pool == NULL) {
        logger_log(LOG_ERROR, "Failed to create thread pool");
        close(config->server_fd);
        return -1;
    }
    config->running = true;
    logger_log(LOG_INFO, "Proxy initialized successfully");
    return 0;
}

int proxy_run(proxy_config_t *config) {
    logger_log(LOG_INFO, "Proxy started, listening on port %d", config->port);
    
    while (config->running) {
        struct pollfd pfd;
        pfd.fd = config->server_fd;
        pfd.events = POLLIN;
        
        int poll_ret = poll(&pfd, 1, 1000);
        
        if (poll_ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger_log(LOG_ERROR, "Poll error: %s", strerror(errno));
            break;
        } else if (poll_ret == 0) {
            continue;
        }
        
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(config->server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            logger_log(LOG_ERROR, "Accept failed: %s", strerror(errno));
            continue;
        }
        
        logger_log(LOG_DEBUG, "Accepted new client connection (fd=%d)", client_fd);
        
        client_context_t *ctx = malloc(sizeof(client_context_t));
        if (ctx == NULL) {
            logger_log(LOG_ERROR, "Failed to allocate client context");
            close(client_fd);
            continue;
        }
        
        ctx->client_fd = client_fd;
        
        if (thread_pool_add_task(config->pool, handle_client, ctx) != 0) {
            logger_log(LOG_ERROR, "Failed to add task to thread pool");
            close(client_fd);
            free(ctx);
        }
    }
    logger_log(LOG_INFO,"Proxy main loop exited");
    return 0;
}

void proxy_shutdown(proxy_config_t *config) {
    logger_log(LOG_INFO, "Received shutdown signal");
    
    config->running = false;
    
    if (config->server_fd >= 0) {
        close(config->server_fd);
        config->server_fd = -1;
        logger_log(LOG_DEBUG,"Server socket closed");
    }
    
    if (config->pool != NULL) {
        thread_pool_destroy(config->pool);
        config->pool = NULL;
    }
    logger_log(LOG_INFO, "Proxy finished");
}