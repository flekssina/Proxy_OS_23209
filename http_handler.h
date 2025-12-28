#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <stddef.h>

#define BUFFER_SIZE 8192
#define MAX_HEADERS 100
#define MAX_REDIRECTS 5

typedef struct {
    int client_fd;
} client_context_t;

void handle_client(void *arg);
int parse_url(const char *url, char *host, int *port, char *path);
int connect_server(const char *host, int port);
int forward_request(int server_fd, const char *method, const char *path, const char *host, int minor_version);
int forward_response(int server_fd, int client_fd);

#endif