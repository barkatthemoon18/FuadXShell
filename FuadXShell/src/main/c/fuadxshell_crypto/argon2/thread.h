#ifndef ARGON2_THREAD_H
#define ARGON2_THREAD_H

#include <pthread.h>

typedef void *(*argon2_thread_func_t)(void *);
typedef pthread_t argon2_thread_handle_t;

/* Creates a thread
 * @param handle pointer to a thread handle, which is the output of this
 * function. Must not be NULL.
 * @param func A function pointer for the thread's entry point. Must not be
 * NULL.
 * @param args Pointer that is passed as an argument to @func. May be NULL.
 * @return 0 if @handle and @func are valid pointers and a thread is successfully
 * created.
 */
int argon2_thread_create(argon2_thread_handle_t *handle,
                         argon2_thread_func_t func, void *args);

/* Waits for a thread to terminate
 * @param handle Handle to a thread created with argon2_thread_create.
 * @return 0 if @handle is a valid handle, and joining completed successfully.
*/
int argon2_thread_join(argon2_thread_handle_t handle);

/* Terminate the current thread. Must be run inside a thread created by
 * argon2_thread_create.
*/
void argon2_thread_exit(void);

#endif /* ARGON2_THREAD_H */
