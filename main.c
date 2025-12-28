#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

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
    printf("usage: %s [options]\n", program_name);
    printf("\n");
    printf("options:\n");
    printf("  --port PORT              \n");
    printf("  --max-client-threads N   \n");
    printf("  --help                   \n");
    printf("\n");
    printf("examples:\n");
    printf(" ./http_proxy --port 8080 --max-client-threads 100\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    proxy_config_t config;
    config.port = 8080;
    config.max_threads = 4;
    config.server_fd = -1;
    config.pool = NULL;
    config.running = false;
    
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"max-client-threads", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0; 
    while ((opt = getopt_long(argc, argv, "p:t:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                config.port = atoi(optarg);
                if (config.port <= 0 || config.port > 65535) {
                    fprintf(stderr, "Invalid port number\n");
                    return EXIT_FAILURE;
                }
                break;
            case 't':
                config.max_threads = atoi(optarg);
                if (config.max_threads <= 0) {
                    fprintf(stderr, "Invalid thread count\n");
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
        logger_log(LOG_ERROR,"Failed to initialize proxy");
        logger_shutdown();
        return EXIT_FAILURE;
    }
    
    if (proxy_run(&config) != 0) {
        logger_log(LOG_ERROR, "Proxy encountered an error");
        proxy_shutdown(&config);
        logger_shutdown();
        return EXIT_FAILURE;
    }
    logger_shutdown();
    return EXIT_SUCCESS;
}