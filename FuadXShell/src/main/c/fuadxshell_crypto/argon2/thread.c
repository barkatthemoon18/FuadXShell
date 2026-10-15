#include "thread.h"

int argon2_thread_create(argon2_thread_handle_t *handle,
                         argon2_thread_func_t func, void *args) {
    if (NULL == handle || func == NULL) {
        return -1;
    }
    return pthread_create(handle, NULL, func, args);
}

int argon2_thread_join(argon2_thread_handle_t handle) {
    return pthread_join(handle, NULL);
}

void argon2_thread_exit(void) {
    pthread_exit(NULL);
}
