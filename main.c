#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include "proxy.h"
#include "logger.h"

static proxy_config_t *global_config = NULL;

static void signal_handler(int signo) {
    (void)signo;
    if (global_config != NULL) {
        proxy_shutdown(global_config);
    }
}

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -p, --port PORT\n");
    printf("  -t, --max-client-threads N\n");
    printf("  -s, --cache-max-size SIZE\n");
    printf("  -l, --cache-ttl SECONDS\n");
    printf("  -h, --help\n");
    printf("\nExample:\n");
    printf("./http_proxy --port 9000 --max-client-threads 100 --cache-max-size 104857600\n");
}

int main(int argc, char *argv[]) {
    proxy_config_t config = {
        .port = 8080,
        .max_threads = 4,
        .server_fd = -1,
        .pool = NULL,
        .running = false,
        .cache = NULL,
        .cache_max_size = 10 * 1024 * 1024,
        .cache_ttl = 5
    };

    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"max-client-threads", required_argument, 0, 't'},
        {"cache-max-size", required_argument, 0, 's'},
        {"cache-ttl", required_argument, 0, 'l'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:s:l:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                config.port = atoi(optarg);
                if (config.port <= 0 || config.port > 65535) {
                    fprintf(stderr, "Error: Invalid port\n");
                    return EXIT_FAILURE;
                }
                break;
            case 't':
                config.max_threads = atoi(optarg);
                if (config.max_threads <= 0) {
                    fprintf(stderr, "Error: Invalid thread count\n");
                    return EXIT_FAILURE;
                }
                break;
            case 's':
                config.cache_max_size = strtoull(optarg, NULL, 10);
                if (config.cache_max_size == 0) {
                    fprintf(stderr, "Error: Invalid cache size\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'l':
                config.cache_ttl = atoi(optarg);
                if (config.cache_ttl <= 0) {
                    fprintf(stderr, "Error: Invalid TTL\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    logger_init(LOG_INFO);
    global_config = &config;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (proxy_init(&config) != 0) {
        logger_log(LOG_ERROR, "Initialization failed");
        logger_shutdown();
        return EXIT_FAILURE;
    }

    if (proxy_run(&config) != 0) {
        logger_log(LOG_ERROR, "Runtime error");
        proxy_shutdown(&config);
        logger_shutdown();
        return EXIT_FAILURE;
    }

    logger_shutdown();
    return EXIT_SUCCESS;
}