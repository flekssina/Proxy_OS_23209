#ifndef CACHE_H
#define CACHE_H
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#define CACHE_CHUNK_SIZE 8192
#define CACHE_LOW_WATERMARK 0.7

typedef enum {
    CACHE_LOADING,
    CACHE_COMPLETE,
    CACHE_ERROR
} cache_entry_state_t;

typedef struct cache_chunk {
    char data[CACHE_CHUNK_SIZE];
    size_t size;
    struct cache_chunk *next;
} cache_chunk_t;

typedef struct cache_entry {
    char *url;
    char *headers;
    size_t headers_len;
    char *mime_type;

    cache_chunk_t *chunks;
    cache_chunk_t *last_chunk;
    size_t total_size;
    size_t content_length;

    cache_entry_state_t state;
    int http_status;

    int ref_count;
    int downloading;

    time_t last_access;
    time_t created;

    pthread_mutex_t entry_mutex;
    pthread_cond_t data_available;

    struct cache_entry *lru_prev;
    struct cache_entry *lru_next;
} cache_entry_t;

typedef struct {
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    size_t current_size;
    size_t max_size;
    size_t entry_count;
    int ttl;

    pthread_mutex_t cache_mutex;
    pthread_cond_t gc_cond;
    pthread_t gc_thread;
    bool gc_running;
} cache_t;

typedef struct {
    size_t max_size;
    int ttl;
} cache_config_t;

cache_t* cache_init(cache_config_t *config);
void cache_destroy(cache_t *cache);
cache_entry_t* cache_get(cache_t *cache, const char *url);
void cache_unref(cache_entry_t *entry);
int cache_set_header(cache_entry_t *entry, const char *headers, size_t len, int status_code, size_t content_length);
int cache_append(cache_t *cache, cache_entry_t *entry,const char *data, size_t len);
void cache_complete(cache_entry_t *entry);
void cache_error(cache_entry_t *entry);
size_t cache_read(cache_entry_t *entry, size_t offset, char *buf, size_t buf_size);
int cache_wait(cache_entry_t *entry, size_t offset, int timeout_ms);


#endif