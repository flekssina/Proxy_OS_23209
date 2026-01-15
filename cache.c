#include "cache.h"
#include "logger.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

static void free_chunks(cache_chunk_t *chunk) {
    while (chunk) {
        cache_chunk_t *next = chunk->next;
        free(chunk);
        chunk = next;
    }
}

static void free_entry(cache_entry_t *entry) {
    if (!entry) {
        return;
    }

    pthread_mutex_destroy(&entry->entry_mutex);
    pthread_cond_destroy(&entry->data_available);
    free(entry->url);
    free(entry->headers);
    free(entry->mime_type);
    free_chunks(entry->chunks);
    free(entry);
}

static void remove_entry_from_list(cache_t *cache, cache_entry_t *entry) {
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        cache->lru_head = entry->lru_next;
    }

    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        cache->lru_tail = entry->lru_prev;
    }

    cache->entry_count--;
}

static void move_to_front(cache_t *cache, cache_entry_t *entry) {
    if (entry == cache->lru_head) {
        return;
    }
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    }
    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    }
    if (entry == cache->lru_tail) {
        cache->lru_tail = entry->lru_prev;
    }

    entry->lru_prev = NULL;
    entry->lru_next = cache->lru_head;
    if (cache->lru_head) {
        cache->lru_head->lru_prev = entry;
    }
    cache->lru_head = entry;
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
}

static void* gc_thread(void *arg) {
    cache_t *cache = (cache_t*)arg;

    while (cache->gc_running) {
        pthread_mutex_lock(&cache->cache_mutex);

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;

        pthread_cond_timedwait(&cache->gc_cond, &cache->cache_mutex, &ts);

        if (! cache->gc_running) {
            pthread_mutex_unlock(&cache->cache_mutex);
            break;
        }

        time_t now = time(NULL);
        cache_entry_t *entry = cache->lru_head;

        while (entry) {
            cache_entry_t *next = entry->lru_next;

            pthread_mutex_lock(&entry->entry_mutex);
            if (entry->state == CACHE_COMPLETE && (now - entry->created) >= cache->ttl) {
                entry->state = CACHE_ERROR;
                logger_log(LOG_DEBUG, "Cache entry invalidated by TTL:  %s", entry->url);
            }

            if (entry->state == CACHE_ERROR && entry->ref_count == 0 && ! entry->downloading) {
                size_t entry_size = sizeof(cache_entry_t) + strlen(entry->url) + 1 + entry->headers_len;
                cache_chunk_t *chunk = entry->chunks;
                while (chunk) {
                    entry_size += sizeof(cache_chunk_t);
                    chunk = chunk->next;
                }
                cache->current_size -= entry_size;
                remove_entry_from_list(cache, entry);

                pthread_mutex_unlock(&entry->entry_mutex);
                free_entry(entry);

                logger_log(LOG_DEBUG, "cache entry removed by gc");
                entry = next;
                continue;
            }

            pthread_mutex_unlock(&entry->entry_mutex);
            entry = next;
        }

       while (cache->current_size > cache->max_size * CACHE_LOW_WATERMARK && cache->lru_tail) {
            cache_entry_t *victim = cache->lru_tail;

            pthread_mutex_lock(&victim->entry_mutex);
            if (victim->ref_count > 0 || victim->downloading || victim->state == CACHE_LOADING) {
                pthread_mutex_unlock(&victim->entry_mutex);
                break;
            }

            size_t entry_size = sizeof(cache_entry_t) + strlen(victim->url) + 1 + victim->headers_len;
            cache_chunk_t *chunk = victim->chunks;
            while (chunk) {
                entry_size += sizeof(cache_chunk_t);
                chunk = chunk->next;
            }
            cache->current_size -= entry_size;
            remove_entry_from_list(cache, victim);

            pthread_mutex_unlock(&victim->entry_mutex);
            free_entry(victim);

            logger_log(LOG_INFO, "cache full");
        }

        pthread_mutex_unlock(&cache->cache_mutex);
    }

    return NULL;
}

cache_t* cache_init(cache_config_t *config) {
    cache_t *cache = calloc(1, sizeof(cache_t));
    if (!cache) {
        logger_log(LOG_ERROR, "Failed to allocate cache");
        return NULL;
    }

    if (config->max_size == 0) {
    logger_log(LOG_ERROR, "Cache max_size must be > 0");
    free(cache);
    return NULL;
    }
    if (config->ttl == 0) {
    logger_log(LOG_ERROR, "Cache ttl must be > 0");
    free(cache);
    return NULL;
    }
    cache->max_size = config->max_size;
    cache->ttl = config->ttl;
    cache->gc_running = true;


    pthread_mutex_init(&cache->cache_mutex, NULL);
    pthread_cond_init(&cache->gc_cond, NULL);

    if (pthread_create(&cache->gc_thread, NULL, gc_thread, cache) != 0) {
        logger_log(LOG_ERROR, "Failed to create gc thread");
        pthread_mutex_destroy(&cache->cache_mutex);
        pthread_cond_destroy(&cache->gc_cond);
        free(cache);
        return NULL;
    }

    logger_log(LOG_INFO, "Cache initialized: max_size=%zu, ttl=%d", cache->max_size, cache->ttl);
    return cache;
}

void cache_destroy(cache_t *cache) {
    if (!cache) {
        return;
    }

    pthread_mutex_lock(&cache->cache_mutex);
    cache->gc_running = false;
    pthread_cond_signal(&cache->gc_cond);
    pthread_mutex_unlock(&cache->cache_mutex);

    pthread_join(cache->gc_thread, NULL);

    pthread_mutex_lock(&cache->cache_mutex);

    cache_entry_t *entry = cache->lru_head;
    while (entry) {
        cache_entry_t *next = entry->lru_next;
        pthread_cond_broadcast(&entry->data_available);
        free_entry(entry);
        entry = next;
    }

    pthread_mutex_unlock(&cache->cache_mutex);
    pthread_mutex_destroy(&cache->cache_mutex);
    pthread_cond_destroy(&cache->gc_cond);
    free(cache);

    logger_log(LOG_INFO, "Cache destroyed");
}

cache_entry_t* cache_get(cache_t *cache, const char *url) {
    pthread_mutex_lock(&cache->cache_mutex);

    cache_entry_t *entry = cache->lru_head;
    while (entry) {
        if (strcmp(entry->url, url) == 0) {
            pthread_mutex_lock(&entry->entry_mutex);
            time_t now = time(NULL);

            if (entry->state == CACHE_COMPLETE && (now - entry->created) >= cache->ttl) {
                entry->state = CACHE_ERROR;

                if (entry->ref_count == 0 && ! entry->downloading) {
                    cache_chunk_t *chunk = entry->chunks;
                    while (chunk) {
                        cache_chunk_t *next = chunk->next;
                        free(chunk);
                        chunk = next;
                    }
                    entry->chunks = NULL;
                    entry->last_chunk = NULL;

                    free(entry->headers);
                    entry->headers = NULL;
                    entry->headers_len = 0;

                    free(entry->mime_type);
                    entry->mime_type = NULL;

                    entry->state = CACHE_LOADING;
                    entry->total_size = 0;
                    entry->ref_count = 1;
                    entry->downloading = 1;
                    entry->created = time(NULL);
                    entry->last_access = entry->created;

                    move_to_front(cache, entry);

                    pthread_mutex_unlock(&entry->entry_mutex);
                    pthread_mutex_unlock(&cache->cache_mutex);

                    return entry;
                }
                pthread_mutex_unlock(&entry->entry_mutex);
                pthread_mutex_unlock(&cache->cache_mutex);

                logger_log(LOG_DEBUG, "expired entry in use, creating new");

                pthread_mutex_lock(&cache->cache_mutex);
                entry = NULL;
                break;
            }

            if (entry->state == CACHE_ERROR) {
                pthread_mutex_unlock(&entry->entry_mutex);
                entry = entry->lru_next;
                continue;
            }

            entry->ref_count++;
            entry->last_access = now;
            move_to_front(cache, entry);

            pthread_mutex_unlock(&entry->entry_mutex);
            pthread_mutex_unlock(&cache->cache_mutex);
            return entry;
        }
        entry = entry->lru_next;
    }

    entry = calloc(1, sizeof(cache_entry_t));
    if (!entry) {
        pthread_mutex_unlock(&cache->cache_mutex);
        return NULL;
    }

    entry->url = strdup(url);
    if (!entry->url) {
        free(entry);
        pthread_mutex_unlock(&cache->cache_mutex);
        return NULL;
    }

    entry->state = CACHE_LOADING;
    entry->ref_count = 1;
    entry->downloading = 1;
    entry->created = time(NULL);
    entry->last_access = entry->created;

    pthread_mutex_init(&entry->entry_mutex, NULL);
    pthread_cond_init(&entry->data_available, NULL);

    entry->lru_next = cache->lru_head;
    if (cache->lru_head) {
        cache->lru_head->lru_prev = entry;
    }
    cache->lru_head = entry;
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
    cache->entry_count++;
    cache->current_size += sizeof(cache_entry_t) + strlen(url) + 1;

    if (cache->current_size > cache->max_size * CACHE_LOW_WATERMARK) {
        pthread_cond_signal(&cache->gc_cond);
    }

    pthread_mutex_unlock(&cache->cache_mutex);
    return entry;
}


void cache_unref(cache_entry_t *entry) {
    if (!entry) {
        return;
    }

    pthread_mutex_lock(&entry->entry_mutex);
    entry->ref_count--;
    pthread_mutex_unlock(&entry->entry_mutex);
}

int cache_set_header(cache_entry_t *entry, const char *headers, size_t len, int status_code, size_t content_length) {
    pthread_mutex_lock(&entry->entry_mutex);

    entry->headers = malloc(len + 1);
    if (!entry->headers) {
        pthread_mutex_unlock(&entry->entry_mutex);
        return -1;
    }

    memcpy(entry->headers, headers, len);
    entry->headers[len] = '\0';
    entry->headers_len = len;
    entry->http_status = status_code;
    entry->content_length = content_length;

    pthread_cond_broadcast(&entry->data_available);
    pthread_mutex_unlock(&entry->entry_mutex);

    return 0;
}

int cache_append(cache_t *cache, cache_entry_t *entry, const char *data, size_t len) {
    if (len == 0) {
        return 0;
    }

    size_t offset = 0;
    while (offset < len) {
        cache_chunk_t *chunk = entry->last_chunk;
        if (!chunk || chunk->size >= CACHE_CHUNK_SIZE) {
            cache_chunk_t *new_chunk = calloc(1, sizeof(cache_chunk_t));
            if (!new_chunk) return -1;

            pthread_mutex_lock(&entry->entry_mutex);
            if (entry->last_chunk) {
                entry->last_chunk->next = new_chunk;
            } else {
                entry->chunks = new_chunk;
            }
            entry->last_chunk = new_chunk;
            pthread_mutex_unlock(&entry->entry_mutex);

            chunk = new_chunk;

            pthread_mutex_lock(&cache->cache_mutex);
            cache->current_size += sizeof(cache_chunk_t);
            pthread_mutex_unlock(&cache->cache_mutex);
        }

        size_t space = CACHE_CHUNK_SIZE - chunk->size;
        size_t to_copy = (len - offset < space) ? (len - offset) : space;

        memcpy(chunk->data + chunk->size, data + offset, to_copy);
        chunk->size += to_copy;
        offset += to_copy;
    }

    pthread_mutex_lock(&entry->entry_mutex);
    entry->total_size += len;
    pthread_cond_broadcast(&entry->data_available);
    pthread_mutex_unlock(&entry->entry_mutex);

    return 0;
}

void cache_complete(cache_entry_t *entry) {
    pthread_mutex_lock(&entry->entry_mutex);
    entry->state = CACHE_COMPLETE;
    entry->downloading = 0;
    entry->created = time(NULL);
    pthread_cond_broadcast(&entry->data_available);
    pthread_mutex_unlock(&entry->entry_mutex);
    logger_log(LOG_INFO, "Cached: %s (%zu bytes)", entry->url, entry->total_size);
}

void cache_error(cache_entry_t *entry) {
    pthread_mutex_lock(&entry->entry_mutex);
    entry->state = CACHE_ERROR;
    entry->downloading = 0;
    pthread_cond_broadcast(&entry->data_available);
    pthread_mutex_unlock(&entry->entry_mutex);
}

size_t cache_read(cache_entry_t *entry, size_t offset, char *buf, size_t buf_size) {
    pthread_mutex_lock(&entry->entry_mutex);

    if (offset >= entry->total_size) {
        pthread_mutex_unlock(&entry->entry_mutex);
        return 0;
    }

    size_t chunk_idx = offset / CACHE_CHUNK_SIZE;
    size_t chunk_offset = offset % CACHE_CHUNK_SIZE;

    cache_chunk_t *chunk = entry->chunks;
    for (size_t i = 0; i < chunk_idx && chunk; i++) {
        chunk = chunk->next;
    }

    size_t total_read = 0;
    while (chunk && total_read < buf_size) {
        size_t available = chunk->size - chunk_offset;
        size_t to_read = (buf_size - total_read < available) ? (buf_size - total_read) : available;
        memcpy(buf + total_read, chunk->data + chunk_offset, to_read);
        total_read += to_read;
        chunk_offset = 0;
        chunk = chunk->next;
    }

    pthread_mutex_unlock(&entry->entry_mutex);
    return total_read;
}

int cache_wait(cache_entry_t *entry, size_t offset, int timeout_ms) {
    pthread_mutex_lock(&entry->entry_mutex);

    while (entry->total_size <= offset && entry->state == CACHE_LOADING && entry->downloading) {
        if(timeout_ms > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }

            int rc = pthread_cond_timedwait(&entry->data_available, &entry->entry_mutex, &ts);
            if (rc == ETIMEDOUT) {
                pthread_mutex_unlock(&entry->entry_mutex);
                return 0;
            }
        } else {
            pthread_cond_wait(&entry->data_available, &entry->entry_mutex);
        }
    }

    int result = 0;
    if (entry->state == CACHE_ERROR) {
        result = -1;
    } else if (entry->total_size <= offset && entry->state == CACHE_COMPLETE) {
        result = 1;
    }

    pthread_mutex_unlock(&entry->entry_mutex);
    return result;
}