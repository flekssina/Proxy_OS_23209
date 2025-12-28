#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include <stdbool.h>

typedef struct task {
    void (*function)(void *arg);
    void *arg;
    struct task *next;
} task_t;

typedef struct {
    pthread_t *threads;
    task_t *task_queue_head;
    task_t *task_queue_tail;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    int thread_count;
    bool shutdown;
} thread_pool_t;

thread_pool_t* thread_pool_create(int thread_count);
int thread_pool_add_task(thread_pool_t *pool, void (*function)(void*), void *arg);
void thread_pool_destroy(thread_pool_t *pool);

#endif