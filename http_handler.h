#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H
#include <stddef.h>
#include "cache.h"
#define BUFFER_SIZE (64 * 1024)
#define MAX_HEADERS 100
#define MAX_REDIRECTS 5
#define MAX_URL_LEN 4096

typedef struct {
    char method[16];
    char url[MAX_URL_LEN];
    char host[256];
    int port;
    char path[MAX_URL_LEN];
    int minor_version;

    struct {
        char name[256];
        char value[1024];
    } headers[MAX_HEADERS];
    int num_headers;

    size_t headers_len;
} http_request_t;

typedef struct {
    int status_code;
    int minor_version;
    char status_msg[256];

    struct {
        char name[256];
        char value[1024];
    } headers[MAX_HEADERS];
    int num_headers;

    size_t content_length;
    size_t headers_len;
} http_response_t;

typedef struct {
    int client_fd;
    cache_t *cache;
} client_context_t;

void handle_client(void *arg);
int parse_url(const char *url, char *host, int *port, char *path);
int connect_server(const char *host, int port);
int http_parse_request(const char *buf, size_t len, http_request_t *req);
int http_parse_response(const char *buf, size_t len, http_response_t *resp);
int http_build_request(const http_request_t *req, char *buf, size_t buf_size);
const char* http_response_get_header(const http_response_t *resp, const char *name);


#endif