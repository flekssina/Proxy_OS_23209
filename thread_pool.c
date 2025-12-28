#include "thread_pool.h"
#include "logger.h"
#include <stdlib.h>

static void* thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t*)arg;
    while (true) {
        pthread_mutex_lock(&pool->queue_mutex);
        while (pool->task_queue_head == NULL && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_cond, &pool->queue_mutex);
        }
        if (pool->shutdown && pool->task_queue_head == NULL) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }

        task_t *task = pool->task_queue_head;
        if (task != NULL) {
            pool->task_queue_head = task->next;
            if (pool->task_queue_head == NULL) {
                pool->task_queue_tail = NULL;
            }
        }
        pthread_mutex_unlock(&pool->queue_mutex);
        if (task != NULL) {
            task->function(task->arg);
            free(task);
        }
    }
    logger_log(LOG_DEBUG, "Worker thread exiting");
    return NULL;
}

thread_pool_t* thread_pool_create(int thread_count) {
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (pool == NULL) {
        logger_log(LOG_ERROR, "Failed to allocate thread pool");
        return NULL;
    }

    pool->threads = malloc(sizeof(pthread_t) * thread_count);
    if (pool->threads == NULL) {
        logger_log(LOG_ERROR, "Failed to allocate threads array");
        free(pool);
        return NULL;
    }

    pool->thread_count = thread_count;
    pool->task_queue_head = NULL;
    pool->task_queue_tail = NULL;
    pool->shutdown = false;
    if (pthread_mutex_init(&pool->queue_mutex, NULL) != 0) {
        logger_log(LOG_ERROR, "Failed to initialize queue mutex");
        free(pool->threads);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->queue_cond, NULL) != 0) {
        logger_log(LOG_ERROR, "Failed to initialize queue condition variable");
        pthread_mutex_destroy(&pool->queue_mutex);
        free(pool->threads);
        free(pool);
        return NULL;
    }
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_worker, pool) != 0) {
            logger_log(LOG_ERROR, "Failed to create worker thread %d", i);
            pool->thread_count = i;
            thread_pool_destroy(pool);
            return NULL;
        }
    }
    logger_log(LOG_INFO, "Thread pool created with %d threads", thread_count);
    return pool;
}

int thread_pool_add_task(thread_pool_t *pool, void (*function)(void*), void *arg) {
    if (pool == NULL || function == NULL) {
        return -1;
    }

    task_t *task = malloc(sizeof(task_t));
    if (task == NULL) {
        logger_log(LOG_ERROR, "Failed to allocate task");
        return -1;
    }
    task->function = function;
    task->arg = arg;
    task->next = NULL;
    pthread_mutex_lock(&pool->queue_mutex);
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->queue_mutex);
        free(task);
        return -1;
    }

    if (pool->task_queue_tail == NULL) {
        pool->task_queue_head = task;
        pool->task_queue_tail = task;
    } 
    else {
        pool->task_queue_tail->next = task;
        pool->task_queue_tail = task;
    }
    pthread_cond_signal(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);
    return 0;
}

void thread_pool_destroy(thread_pool_t *pool) {
    if (pool == NULL) {
        return;
    }

    logger_log(LOG_INFO, "Destroying thread pool");
    pthread_mutex_lock(&pool->queue_mutex);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);

    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    logger_log(LOG_INFO, "All worker threads have finished");
    while (pool->task_queue_head != NULL) {
        task_t *task = pool->task_queue_head;
        pool->task_queue_head = task->next;
        free(task);
    }
    pthread_mutex_destroy(&pool->queue_mutex);
    pthread_cond_destroy(&pool->queue_cond);
    free(pool->threads);
    free(pool);
    logger_log(LOG_DEBUG, "Thread pool destroyed");
}