#include "http_handler.h"
#include "logger.h"
#include "picohttpparser.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <strings.h>

int http_parse_request(const char *buf, size_t len, http_request_t *req) {
    const char *method, *path;
    size_t method_len, path_len;
    int minor_version;
    struct phr_header headers[MAX_HEADERS];
    size_t num_headers = MAX_HEADERS;

    int pret = phr_parse_request(buf, len, &method, &method_len, &path, &path_len,&minor_version, headers, &num_headers, 0);

    if (pret == -1) {
        return -1;
    }
    if (pret == -2) {
        return -2;
    }

    memset(req, 0, sizeof(*req));

    size_t copy_len = (method_len < sizeof(req->method) - 1) ? method_len : (sizeof(req->method) - 1);
    memcpy(req->method, method, copy_len);
    req->method[copy_len] = '\0';

    copy_len = (path_len < sizeof(req->url) - 1) ? path_len : (sizeof(req->url) - 1);
    memcpy(req->url, path, copy_len);
    req->url[copy_len] = '\0';

    req->minor_version = minor_version;
    req->headers_len = pret;

    if (strncmp(req->url, "http://", 7) == 0) {
        const char *host_start = req->url + 7;
        const char *host_end = strchr(host_start, '/');
        const char *port_start = strchr(host_start, ':');

        if (port_start && (!host_end || port_start < host_end)) {
            size_t host_len = (size_t)(port_start - host_start);
            if (host_len >= sizeof(req->host)) {
                host_len = sizeof(req->host) - 1;
            }
            memcpy(req->host, host_start, host_len);
            req->host[host_len] = '\0';
            req->port = atoi(port_start + 1);
        } else {
            size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
            if (host_len >= sizeof(req->host)) {
                host_len = sizeof(req->host) - 1;
            }
            memcpy(req->host, host_start, host_len);
            req->host[host_len] = '\0';
            req->port = 80;
        }

        if (host_end) {
            size_t path_len = strlen(host_end);
            if (path_len >= sizeof(req->path)) {
                path_len = sizeof(req->path) - 1;
            }
            memcpy(req->path, host_end, path_len);
            req->path[path_len] = '\0';
        } else {
            strcpy(req->path, "/");
        }
    } else {
        size_t path_len = strlen(req->url);
        if (path_len >= sizeof(req->path)) {
            path_len = sizeof(req->path) - 1;
        }
        memcpy(req->path, req->url, path_len);
        req->path[path_len] = '\0';
        req->port = 80;
    }

    req->num_headers = (num_headers < MAX_HEADERS) ? (int)num_headers : MAX_HEADERS;

    for (size_t i = 0; i < (size_t)req->num_headers; i++) {
        copy_len = (headers[i].name_len < sizeof(req->headers[i].name) - 1) ? headers[i].name_len : (sizeof(req->headers[i].name) - 1);
        memcpy(req->headers[i].name, headers[i].name, copy_len);
        req->headers[i].name[copy_len] = '\0';

        copy_len = (headers[i].value_len < sizeof(req->headers[i].value) - 1) ? headers[i].value_len : (sizeof(req->headers[i].value) - 1);
        memcpy(req->headers[i].value, headers[i].value, copy_len);
        req->headers[i].value[copy_len] = '\0';

        if (strcasecmp(req->headers[i].name, "Host") == 0 && req->host[0] == '\0') {
            size_t host_len = strlen(req->headers[i].value);
            if (host_len >= sizeof(req->host)) {
                host_len = sizeof(req->host) - 1;
            }
            memcpy(req->host, req->headers[i].value, host_len);
            req->host[host_len] = '\0';
        }
    }

    return pret;
}
int http_parse_response(const char *buf, size_t len, http_response_t *resp) {
    int minor_version, status;
    const char *msg;
    size_t msg_len;
    struct phr_header headers[MAX_HEADERS];
    size_t num_headers = MAX_HEADERS;

    int pret = phr_parse_response(buf, len, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

    if (pret == -1) {
        return -1;
    }
    if (pret == -2) {
        return -2;
    }

    memset(resp, 0, sizeof(*resp));

    resp->minor_version = minor_version;
    resp->status_code = status;
    resp->headers_len = pret;

    size_t copy_len = (msg_len < sizeof(resp->status_msg) - 1) ? msg_len : (sizeof(resp->status_msg) - 1);
    memcpy(resp->status_msg, msg, copy_len);
    resp->status_msg[copy_len] = '\0';

    resp->num_headers = (num_headers < MAX_HEADERS) ? (int)num_headers : MAX_HEADERS;

    for (size_t i = 0; i < (size_t)resp->num_headers; i++) {
        copy_len = (headers[i].name_len < sizeof(resp->headers[i].name) - 1) ? headers[i].name_len : (sizeof(resp->headers[i].name) - 1);
        memcpy(resp->headers[i].name, headers[i].name, copy_len);
        resp->headers[i].name[copy_len] = '\0';

        copy_len = (headers[i].value_len < sizeof(resp->headers[i].value) - 1) ? headers[i].value_len : (sizeof(resp->headers[i].value) - 1);
        memcpy(resp->headers[i].value, headers[i].value, copy_len);
        resp->headers[i].value[copy_len] = '\0';

        if (strcasecmp(resp->headers[i].name, "Content-Length") == 0) {
            resp->content_length = strtoull(resp->headers[i].value, NULL, 10);
        }
    }

    return pret;
}

int http_build_request(const http_request_t *req, char *buf, size_t buf_size) {
    int len = snprintf(buf, buf_size,
                      "%s %s HTTP/1.0\r\n"
                      "Host: %s\r\n"
                      "Connection: close\r\n",
                      req->method, req->path, req->host);

    if (len < 0 || (size_t)len >= buf_size) return -1;

    for (int i = 0; i < req->num_headers; i++) {
        if (strcasecmp(req->headers[i].name, "Host") == 0) {
            continue;
        }
        if (strcasecmp(req->headers[i].name, "Connection") == 0) {
            continue;
        }
        if (strcasecmp(req->headers[i].name, "Proxy-Connection") == 0) {
            continue;
        }

        int added = snprintf(buf + len, buf_size - len, "%s: %s\r\n", req->headers[i].name, req->headers[i].value);
        if (added < 0 || (size_t)(len + added) >= buf_size) return -1;
        len += added;
    }

    if ((size_t)(len + 2) >= buf_size) {
        return -1;
    }
    buf[len++] = '\r';
    buf[len++] = '\n';
    buf[len] = '\0';

    return len;
}

const char* http_response_get_header(const http_response_t *resp, const char *name) {
    for (int i = 0; i < resp->num_headers; i++) {
        if (strcasecmp(resp->headers[i].name, name) == 0) {
            return resp->headers[i].value;
        }
    }
    return NULL;
}

int parse_url(const char *url, char *host, int *port, char *path) {
    const char *start = url;

    if (strncmp(url, "http://", 7) == 0) {
        start = url + 7;
    }

    const char *slash = strchr(start, '/');
    const char *colon = strchr(start, ':');

    if (colon != NULL && (slash == NULL || colon < slash)) {
        size_t host_len = colon - start;
        if (host_len >= 256) {
            host_len = 255;
        }
        memcpy(host, start, host_len);
        host[host_len] = '\0';

        *port = atoi(colon + 1);

        if (slash != NULL) {
            size_t path_len = strlen(slash);
            if (path_len >= 2048) {
                path_len = 2047;
            }
            memcpy(path, slash, path_len);
            path[path_len] = '\0';
        } else {
            strcpy(path, "/");
        }
    } else {
        size_t host_len;
        if (slash != NULL) {
            host_len = slash - start;
        } else {
            host_len = strlen(start);
        }

        if (host_len >= 256) {
            host_len = 255;
        }
        memcpy(host, start, host_len);
        host[host_len] = '\0';
        *port = 80;

        if (slash != NULL) {
            size_t path_len = strlen(slash);
            if (path_len >= 2048) path_len = 2047;
            memcpy(path, slash, path_len);
            path[path_len] = '\0';
        } else {
            strcpy(path, "/");
        }
    }

    return 0;
}
int connect_server(const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        logger_log(LOG_ERROR, "getaddrinfo(%s): %s", host, gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            if (errno == EMFILE || errno == ENFILE) {
                logger_log(LOG_ERROR, "Cannot create socket: fd limit reached");
                freeaddrinfo(res);
                return -1;
            }
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0) {
        logger_log(LOG_ERROR, "Failed to connect to %s:%d", host, port);
    }
    return fd;
}

static int send_cached_response(int client_fd, cache_entry_t *entry) {
    pthread_mutex_lock(&entry->entry_mutex);

    int wait_iterations = 0;
    while (entry->headers == NULL && entry->state == CACHE_LOADING && entry->downloading) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 120;

        int rc = pthread_cond_timedwait(&entry->data_available, &entry->entry_mutex, &ts);
        if (rc == ETIMEDOUT) {
            logger_log(LOG_ERROR, "Timeout waiting for headers after %d iterations", wait_iterations);
            pthread_mutex_unlock(&entry->entry_mutex);
            return -1;
        }
        wait_iterations++;
    }

    if (entry->state == CACHE_ERROR) {
        logger_log(LOG_ERROR, "Entry in ERROR state");
        pthread_mutex_unlock(&entry->entry_mutex);
        return -1;
    }

    if (entry->headers && entry->headers_len > 0) {
        ssize_t total_sent = 0;
        while (total_sent < (ssize_t)entry->headers_len) {
            ssize_t sent = send(client_fd, entry->headers + total_sent, entry->headers_len - total_sent, 0);
            if (sent <= 0) {
                if (sent < 0) {
                    logger_log(LOG_ERROR, "Failed to send headers: %s", strerror(errno));
                } else {
                    logger_log(LOG_ERROR, "Client closed connection while sending headers");
                }
                pthread_mutex_unlock(&entry->entry_mutex);
                return -1;
            }
            total_sent += sent;
        }
    } else {
        logger_log(LOG_WARN, "No headers to send!");
    }
    pthread_mutex_unlock(&entry->entry_mutex);

    size_t offset = 0;
    char buf[BUFFER_SIZE];

    while (1) {
        size_t read = cache_read(entry, offset, buf, sizeof(buf));

        if (read > 0) {
            ssize_t total_sent = 0;
            while (total_sent < (ssize_t)read) {
                ssize_t sent = send(client_fd, buf + total_sent, read - total_sent, 0);
                if (sent <= 0) {
                    if (sent < 0 && errno != EPIPE && errno != ECONNRESET) {
                        logger_log(LOG_ERROR, "Failed to send body: %s", strerror(errno));
                    }
                    return -1;
                }
                total_sent += sent;
            }
            offset += read;
        } else {
            pthread_mutex_lock(&entry->entry_mutex);
            int is_complete = (entry->state == CACHE_COMPLETE);
            int is_error = (entry->state == CACHE_ERROR);
            size_t total_size = entry->total_size;
            pthread_mutex_unlock(&entry->entry_mutex);

            if (is_error) {
                logger_log(LOG_ERROR, "Entry switched to ERROR while sending");
                return -1;
            }

            if (is_complete && offset >= total_size) {
                break;
            }

            int result = cache_wait(entry, offset, 30000);

            if (result == -1) {
                logger_log(LOG_ERROR, "Error while waiting for data");
                return -1;
            } else if (result == 1) {
                break;
            }
        }
    }

    return 0;
}
static int send_error_response(int client_fd, int status, const char *msg) {
    char buf[512];
    int len = snprintf(buf, sizeof(buf),
                      "HTTP/1.0 %d %s\r\n"
                      "Content-Type: text/plain\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "%d %s\n",
                      status, msg, status, msg);

    send(client_fd, buf, len, 0);
    return 0;
}

static int download_and_stream_to_client(cache_t *cache, cache_entry_t *entry, const http_request_t *original_req, int client_fd) {
    http_request_t req = *original_req;
    int redirect_count = 0;
    bool client_disconnected = false;

    while (redirect_count < MAX_REDIRECTS) {
        int server_fd = connect_server(req.host, req.port);
        if (server_fd < 0) {
            return -1;
        }

        char request_buf[BUFFER_SIZE * 2];
        int req_len = http_build_request(&req, request_buf, sizeof(request_buf));
        if (req_len < 0) {
            close(server_fd);
            return -1;
        }

        if (send(server_fd, request_buf, req_len, 0) != req_len) {
            close(server_fd);
            return -1;
        }

        char recv_buf[BUFFER_SIZE];
        char header_buf[BUFFER_SIZE * 2];
        size_t header_buf_len = 0;
        int headers_parsed = 0;
        http_response_t resp;
        memset(&resp, 0, sizeof(resp));
        size_t body_received = 0;
        size_t body_sent_to_client = 0;

        while (!headers_parsed) {
            struct pollfd pfd = {server_fd, POLLIN, 0};
            int ret = poll(&pfd, 1, 120000);

            if (ret <= 0) {
                close(server_fd);
                return -1;
            }

            ssize_t n = recv(server_fd, recv_buf, sizeof(recv_buf), 0);
            if (n <= 0) {
                close(server_fd);
                return -1;
            }

            size_t copy_len = (size_t)n;
            if (header_buf_len + copy_len > sizeof(header_buf)) {
                copy_len = sizeof(header_buf) - header_buf_len;
            }
            memcpy(header_buf + header_buf_len, recv_buf, copy_len);
            header_buf_len += copy_len;

            int parsed = http_parse_response(header_buf, header_buf_len, &resp);
            if (parsed == -1) {
                close(server_fd);
                return -1;
            }
            if (parsed > 0) {
                headers_parsed = 1;
                if (resp.status_code >= 300 && resp.status_code < 400) {
                    const char *location = http_response_get_header(&resp, "Location");
                    if (location && redirect_count < MAX_REDIRECTS) {
                        logger_log(LOG_INFO, "Redirect %d -> %s", resp.status_code, location);
                        parse_url(location, req.host, &req.port, req.path);
                        snprintf(req.url, sizeof(req.url), "%s", location);
                        close(server_fd);
                        redirect_count++;
                        goto next_redirect;
                    }
                }

                if (resp.status_code == 200) {
                    if (resp.content_length > 0 && (size_t)resp.content_length > cache->max_size) {
                        logger_log(LOG_ERROR,"File size %zu bytes exceeds max cache size %zu bytes, rejecting request",(size_t)resp.content_length, cache->max_size);
                        close(server_fd);
                        return -1;
                    }

                    cache_set_header(entry, header_buf, parsed, resp.status_code, resp.content_length);

                    const char *content_type = http_response_get_header(&resp, "Content-Type");
                    if (content_type) {
                        pthread_mutex_lock(&entry->entry_mutex);
                        entry->mime_type = strdup(content_type);
                        pthread_mutex_unlock(&entry->entry_mutex);
                    }

                    if (!client_disconnected) {
                        ssize_t sent_total = 0;
                        while (sent_total < (ssize_t)parsed) {
                            ssize_t sent = send(client_fd, header_buf + sent_total,parsed - sent_total, 0);
                            if (sent <= 0) {
                                if (errno == EPIPE || errno == ECONNRESET) {
                                    logger_log(LOG_DEBUG, "Client disconnected(headers)");
                                    client_disconnected = true;
                                    break;
                                }
                                close(server_fd);
                                cache_error(entry);
                                return -1;
                            }
                            sent_total += sent;
                        }
                        if (!client_disconnected) {
                            body_sent_to_client += sent_total;
                        }
                    }

                    size_t offset = parsed;
                    if (offset < header_buf_len) {
                        size_t body_in_header_buf = header_buf_len - offset;

                        if (!client_disconnected) {
                            ssize_t sent_total = 0;
                            while (sent_total < (ssize_t)body_in_header_buf) {
                                ssize_t sent = send(client_fd, header_buf + offset + sent_total, body_in_header_buf - sent_total, 0);
                                if (sent <= 0) {
                                    if (errno == EPIPE || errno == ECONNRESET) {
                                        logger_log(LOG_DEBUG, "client disconnected(initial body)");
                                        client_disconnected = true;
                                        break;
                                    }
                                    close(server_fd);
                                    cache_error(entry);
                                    return -1;
                                }
                                sent_total += sent;
                            }
                            if (!client_disconnected) {
                                body_sent_to_client += sent_total;
                            }
                        }

                        cache_append(cache, entry, header_buf + offset, body_in_header_buf);
                        body_received += body_in_header_buf;
                    }
                } else {
                    logger_log(LOG_WARN, "Not caching response with status %d", resp.status_code);
                    close(server_fd);
                    return -1;
                }

                break;
            }
        }

        if (resp.status_code == 200) {
            while (1) {
                struct pollfd pfd = {server_fd, POLLIN, 0};
                int ret = poll(&pfd, 1, 30000);

                if (ret < 0) {
                    close(server_fd);
                    cache_error(entry);
                    return -1;
                } else if (ret == 0) {
                    break;
                }

                ssize_t n = recv(server_fd, recv_buf, sizeof(recv_buf), 0);
                if (n < 0) {
                    close(server_fd);
                    cache_error(entry);
                    return -1;
                } else if (n == 0) {
                    break;
                }

                if (!client_disconnected) {
                    ssize_t sent_total = 0;
                    while (sent_total < n) {
                        ssize_t sent = send(client_fd, recv_buf + sent_total, n - sent_total, 0);
                        if (sent <= 0) {
                            if (errno == EPIPE || errno == ECONNRESET) {
                                logger_log(LOG_DEBUG, "Client disconnected after %zu bytes",body_sent_to_client);
                                client_disconnected = true;
                                break;
                            }
                            close(server_fd);
                            cache_error(entry);
                            return -1;
                        }
                        sent_total += sent;
                    }
                    if (!client_disconnected) {
                        body_sent_to_client += sent_total;
                    }
                }

                if (cache_append(cache, entry, recv_buf, n) != 0) {
                    logger_log(LOG_ERROR, "Failed to append data to cache");
                    close(server_fd);
                    cache_error(entry);
                    return -1;
                }
                body_received += n;

                if (resp.content_length > 0 && body_received >= resp.content_length) {
                    break;
                }
            }

            close(server_fd);
            cache_complete(entry);

            logger_log(LOG_DEBUG, "Download complete: %zu bytes", body_received);
            return 0;
        }

next_redirect:
        continue;
    }

    logger_log(LOG_ERROR, "Too many redirects");
    return -1;
}
void handle_client(void *arg) {
    client_context_t *ctx = (client_context_t*)arg;
    int client_fd = ctx->client_fd;
    cache_t *cache = ctx->cache;
    free(ctx);

    char buffer[BUFFER_SIZE * 2];
    size_t buffer_len = 0;

    while (buffer_len < sizeof(buffer) - 1) {
        struct pollfd pfd;
        pfd.fd = client_fd;
        pfd.events = POLLIN;

        int poll_ret = poll(&pfd, 1, 10000);
        if (poll_ret <= 0) {
            logger_log(LOG_ERROR,"poll timeout or error while reading client request");
            close(client_fd);
            return;
        }

        ssize_t n = recv(client_fd, buffer + buffer_len, sizeof(buffer) - buffer_len - 1, 0);
        if (n <= 0) {
            logger_log(LOG_ERROR, "Error reading from client");
            close(client_fd);
            return;
        }

        buffer_len += n;
        buffer[buffer_len] = '\0';

        http_request_t req;
        int parsed = http_parse_request(buffer, buffer_len, &req);

        if (parsed > 0) {
            logger_log(LOG_INFO, "Request: %s %s HTTP/1.%d", req.method, req.url, req.minor_version);

            if (strcmp(req.method, "GET") != 0) {
                send_error_response(client_fd, 501, "Not Implemented");
                close(client_fd);
                return;
            }

            if (req.host[0] == '\0') {
                send_error_response(client_fd, 400, "Bad Request");
                close(client_fd);
                return;
            }

            cache_entry_t *entry = cache_get(cache, req.url);

            if (!entry) {
                logger_log(LOG_ERROR, "Failed to get/create cache entry");
                send_error_response(client_fd, 503, "Service Unavailable");
                close(client_fd);
                return;
            }

            pthread_mutex_lock(&entry->entry_mutex);

            bool downloader = false;
            if (entry->downloading == 1 && entry->headers == NULL && entry->state == CACHE_LOADING && entry->ref_count == 1) {
                downloader = true;
            } else {
                logger_log(LOG_DEBUG, "Waiting for concurrent download: %s", req.url);
            }

            pthread_mutex_unlock(&entry->entry_mutex);

            if (downloader) {
                logger_log(LOG_INFO, "Downloading to cache: %s", req.url);

                int result = download_and_stream_to_client(cache, entry, &req, client_fd);

                cache_unref(entry);
                close(client_fd);

                if (result < 0) {
                    logger_log(LOG_ERROR, "Failed to download and stream");
                    cache_error(entry);
                } else {
                    logger_log(LOG_DEBUG, "Download and stream completed successfully");
                }

                return;
            }

            int send_result = send_cached_response(client_fd, entry);
            if (send_result < 0) {
                logger_log(LOG_ERROR, "Failed to send cached response");
            }

            cache_unref(entry);
            close(client_fd);
            logger_log(LOG_DEBUG, "Client connection closed");
            return;

        } else if (parsed == -1) {
            logger_log(LOG_ERROR, "Parse error");
            send_error_response(client_fd, 400, "Bad Request");
            close(client_fd);
            return;
        }
    }

    logger_log(LOG_ERROR, "Request too large");
    send_error_response(client_fd, 413, "Request Entity Too Large");
    close(client_fd);
}