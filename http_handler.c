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
#include "http_handler.h"
#include "logger.h"
#include "picohttpparser.h"

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
            strncpy(path, slash, 2047);
            path[2047] = '\0';
        } else {
            strcpy(path, "/");
        }
    } 
    else {
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
            strncpy(path, slash, 2047);
            path[2047] = '\0';
        } else {
            strcpy(path, "/");
        }
    }
    return 0;
}

int connect_server(const char *host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        logger_log(LOG_ERROR,"Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    server = gethostbyname(host);
    if (server == NULL) {
        logger_log(LOG_ERROR, "Failed to resolve host %s", host);
        close(sockfd);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        logger_log(LOG_ERROR, "Failed to connect to %s:%d: %s", host, port, strerror(errno));
        close(sockfd);
        return -1;
    } 
    logger_log(LOG_DEBUG,"Connected to %s:%d", host, port);
    return sockfd;
}

int forward_request(int server_fd, const char *method, const char *path,const char *host, int minor_version) {
    char request[BUFFER_SIZE];
    int len = snprintf(request, sizeof(request),
                      "%s %s HTTP/1.%d\r\n"
                      "Host: %s\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      method, path, minor_version, host);
    
    if (len < 0 || len >= (int)sizeof(request)) {
        logger_log(LOG_ERROR, "Request too large");
        return -1;
    }
    
    ssize_t sent = 0;
    while (sent < len) {
        ssize_t n = send(server_fd, request + sent, len - sent, 0);
        if (n <= 0) {
            logger_log(LOG_ERROR, "Failed to send request to server: %s", strerror(errno));
            return -1;
        }
        sent += n;
    }
    logger_log(LOG_DEBUG, "Forwarded request to server: %s %s", method, path);
    return 0;
}

int forward_response(int server_fd, int client_fd) {
    char buffer[BUFFER_SIZE];
    char headers_buffer[BUFFER_SIZE * 2];
    size_t headers_len = 0;
    int status = 0;
    int minor_version = 0;
    const char *msg;
    size_t msg_len;
    struct phr_header headers[MAX_HEADERS];
    size_t num_headers = MAX_HEADERS;
    int pret = -2;
    
    while (pret == -2) {
        struct pollfd pfd;
        pfd.fd = server_fd;
        pfd.events = POLLIN;
        
        int poll_ret = poll(&pfd, 1, 30000);
        if (poll_ret <= 0) {
            logger_log(LOG_ERROR, "Poll timeout or error while reading response headers");
            return -1;
        }
        
        ssize_t n = recv(server_fd, headers_buffer + headers_len, sizeof(headers_buffer) - headers_len - 1, 0);
        if (n <= 0) {
            logger_log(LOG_ERROR, "Connection closed while reading response headers");
            return -1;
        }
        headers_len += n;
        headers_buffer[headers_len] = '\0';
        num_headers = MAX_HEADERS;
        pret = phr_parse_response(headers_buffer, headers_len, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);
    }
    
    if (pret < 0) {
        logger_log(LOG_ERROR, "Failed to parse response headers");
        return -1;
    }
    
    logger_log(LOG_INFO, "Response status: %d", status);
    size_t sent = 0;
    while (sent < headers_len) {
        size_t n = send(client_fd, headers_buffer + sent, headers_len - sent, 0);
        if (n <= 0) {
            logger_log(LOG_ERROR, "Failed to send response headers to client");
            return -1;
        }
        sent += n;
    }
    
    while (1) {
        struct pollfd pfd;
        pfd.fd = server_fd;
        pfd.events = POLLIN;
        
        int poll_ret = poll(&pfd, 1, 30000);
        if (poll_ret < 0) {
            logger_log(LOG_ERROR, "Poll error: %s", strerror(errno));
            break;
        } else if (poll_ret == 0) {
            logger_log(LOG_WARN, "Poll timeout while reading response body");
            break;
        }
        ssize_t n = recv(server_fd, buffer, sizeof(buffer), 0);
        if (n < 0) {
            logger_log(LOG_ERROR, "Error reading from server: %s", strerror(errno));
            break;
        } 
        else if (n == 0) {
            logger_log(LOG_DEBUG, "Server closed connection");
            break;
        }
        
        sent = 0;
        while (sent < (size_t)n) {
            ssize_t s = send(client_fd, buffer + sent, n - sent, 0);
            if (s <= 0) {
                logger_log(LOG_ERROR, "Error sending to client: %s", strerror(errno));
                return -1;
            }
            sent += s;
        }
    }  
    return status;
}

void handle_client(void *arg) {
    client_context_t *ctx = (client_context_t*)arg;
    int client_fd = ctx->client_fd;
    free(ctx);
    
    char buffer[BUFFER_SIZE];
    size_t buffer_len = 0;
    
    while (buffer_len < sizeof(buffer) - 1) {
        struct pollfd pfd;
        pfd.fd = client_fd;
        pfd.events = POLLIN;
        
        int poll_ret = poll(&pfd, 1, 10000);
        if (poll_ret <= 0) {
            logger_log(LOG_ERROR, "Poll timeout or error while reading client request");
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
        const char *method, *path;
        size_t method_len, path_len;
        int minor_version;
        struct phr_header headers[MAX_HEADERS];
        size_t num_headers = MAX_HEADERS;
        
        int pret = phr_parse_request(buffer, buffer_len, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
        
        if (pret > 0) {
            char method_str[32], path_str[2048];
            snprintf(method_str, sizeof(method_str), "%.*s", (int)method_len, method);
            snprintf(path_str, sizeof(path_str), "%.*s", (int)path_len, path);
            
            logger_log(LOG_INFO, "Request: %s %s HTTP/1.%d", method_str, path_str, minor_version);
            
            char host[256], uri_path[2048];
            int port;
            if (parse_url(path_str, host, &port, uri_path) != 0) {
                logger_log(LOG_ERROR, "Failed to parse URL: %s", path_str);
                const char *error_response = "HTTP/1.0 400 Bad Request\r\n\r\n";
                send(client_fd, error_response, strlen(error_response), 0);
                close(client_fd);
                return;
            }
            
            int redirect_count = 0;
            int server_fd = -1;
            int status = 0;
            
            while (redirect_count < MAX_REDIRECTS) {
                server_fd = connect_server(host, port);
                if (server_fd < 0) {
                    const char *error_response = "HTTP/1.0 502 Bad Gateway\r\n\r\n";
                    send(client_fd, error_response, strlen(error_response), 0);
                    close(client_fd);
                    return;
                }
                
                if (forward_request(server_fd, method_str, uri_path, host, minor_version) != 0) {
                    close(server_fd);
                    close(client_fd);
                    return;
                }
            
                status = forward_response(server_fd, client_fd);
                close(server_fd);
                
                if (status < 300 || status >= 400) {
                    break;
                }
                logger_log(LOG_INFO,"Redirect detected (status %d), following...", status);
                redirect_count++;
                
                if (redirect_count >= MAX_REDIRECTS) {
                    logger_log(LOG_WARN, "Maximum redirects reached");
                    break;
                }
            }
            
            close(client_fd);
            logger_log(LOG_DEBUG, "Client connection closed");
            return;
        } 
        else if (pret == -1) {
            logger_log(LOG_ERROR,"Parse error");
            const char *error_response = "HTTP/1.0 400 Bad Request\r\n\r\n";
            send(client_fd, error_response, strlen(error_response), 0);
            close(client_fd);
            return;
        }
    }   
    logger_log(LOG_ERROR, "Request too large");
    const char *error_response = "HTTP/1.0 413 Request Entity Too Large\r\n\r\n";
    send(client_fd, error_response, strlen(error_response), 0);
    close(client_fd);
}