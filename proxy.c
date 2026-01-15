#include "proxy.h"
#include "http_handler.h"
#include "logger.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <dirent.h>

static int reserv_fd = -1;

static int cnt_open_fd(void) {
    int count = 0;
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                count++;
            }
        }
        closedir(dir);
    }
    return count;
}

static int get_fd_limit(void) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        return rlim.rlim_cur;
    }
    return -1;
}

int proxy_init(proxy_config_t *config) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            logger_log(LOG_WARN, "Failed to increase fd limit: %s", strerror(errno));
        }
    }

    reserv_fd = open("/dev/null", O_RDONLY);
    if (reserv_fd < 0) {
        logger_log(LOG_WARN, "Failed to open reserv fd");
    }

    cache_config_t cache_config;
    cache_config.max_size = config->cache_max_size;
    cache_config.ttl = config->cache_ttl;

    config->cache = cache_init(&cache_config);
    if (config->cache == NULL) {
        logger_log(LOG_ERROR, "Failed to initialize cache");
        return -1;
    }

    logger_log(LOG_INFO, "Initializing proxy on port %d with %d threads", config->port, config->max_threads);

    config->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (config->server_fd < 0) {
        logger_log(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        cache_destroy(config->cache);
        return -1;
    }

    int opt = 1;
    if (setsockopt(config->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger_log(LOG_WARN, "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config->port);

    if (bind(config->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        logger_log(LOG_ERROR, "Failed to bind to port %d: %s", config->port, strerror(errno));
        close(config->server_fd);
        cache_destroy(config->cache);
        return -1;
    }

    if (listen(config->server_fd, 1024) < 0) {
        logger_log(LOG_ERROR, "Failed to listen: %s", strerror(errno));
        close(config->server_fd);
        cache_destroy(config->cache);
        return -1;
    }

    config->pool = thread_pool_create(config->max_threads);
    if (config->pool == NULL) {
        logger_log(LOG_ERROR, "Failed to create thread pool");
        close(config->server_fd);
        cache_destroy(config->cache);
        return -1;
    }

    config->running = true;
    logger_log(LOG_INFO, "Proxy initialized successfully");

    return 0;
}

int proxy_run(proxy_config_t *config) {
    logger_log(LOG_INFO, "Proxy started");
    int accept_count = 0;

    while (config->running) {
        if (++accept_count % 100 == 0) {
            int open_fds = cnt_open_fd();
            int fd_limit = get_fd_limit();

            if (fd_limit > 0 && (float)open_fds / fd_limit > 0.9) {
                logger_log(LOG_WARN, "fd usage > 90%% (%d / %d)", open_fds, fd_limit);
            }
        }

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

            if (errno == EMFILE || errno == ENFILE) {
                logger_log(LOG_ERROR, "fd limit reached");

                if (reserv_fd >= 0) {
                    close(reserv_fd);
                    reserv_fd = -1;

                    client_fd = accept(config->server_fd, (struct sockaddr*)&client_addr, &client_len);
                    if (client_fd >= 0) {
                        const char *error_response =
                            "HTTP/1.0 503 Service Unavailable\r\n"
                            "Content-Type: text/plain\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "503 Service Unavailable\n";
                        send(client_fd, error_response, strlen(error_response), 0);
                        close(client_fd);
                    }
                    reserv_fd = open("/dev/null", O_RDONLY);
                }

                struct pollfd wait_pfd;
                wait_pfd.fd = config->server_fd;
                wait_pfd.events = POLLIN;
                poll(&wait_pfd, 1, 1000);
                continue;
            }

            logger_log(LOG_ERROR, "Accept failed: %s", strerror(errno));
            continue;
        }

        client_context_t *ctx = malloc(sizeof(client_context_t));
        if (ctx == NULL) {
            logger_log(LOG_ERROR, "Failed to allocate client context");
            close(client_fd);
            continue;
        }

        ctx->client_fd = client_fd;
        ctx->cache = config->cache;

        if (thread_pool_add_task(config->pool, handle_client, ctx) != 0) {
            logger_log(LOG_ERROR, "Failed to add task to thread pool");
            close(client_fd);
            free(ctx);
        }
    }

    logger_log(LOG_INFO, "Proxy stopped");
    return 0;
}

void proxy_shutdown(proxy_config_t *config) {
    logger_log(LOG_INFO, "Shutting down proxy");

    config->running = false;

    if (config->server_fd >= 0) {
        close(config->server_fd);
        config->server_fd = -1;
    }

    if (config->pool != NULL) {
        thread_pool_destroy(config->pool);
        config->pool = NULL;
    }

    if (config->cache != NULL) {
        cache_destroy(config->cache);
        config->cache = NULL;
    }

    if (reserv_fd >= 0) {
        close(reserv_fd);
        reserv_fd = -1;
    }

    logger_log(LOG_INFO, "Proxy shutdown complete");
}