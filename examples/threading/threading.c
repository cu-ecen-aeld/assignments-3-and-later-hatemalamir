#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf(">> threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf(">> threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data* args = (struct thread_data *) thread_param;
    args->thread_complete_success = false;

    // First step, wait before obtaining mutex
    struct timespec ts;
    ts.tv_sec = args->wait_to_obtain_ms / 1000;
    ts.tv_nsec = (args->wait_to_obtain_ms % 1000) * 1000000;
    if(nanosleep(&ts, NULL) == 0) {
        // Second step, obtain mutex
        if(pthread_mutex_lock(args->mutex) == 0) {
            // Third step, wait before releasing mutex
            ts.tv_sec = args->wait_to_release_ms / 1000;
            ts.tv_nsec = (args->wait_to_release_ms % 1000) * 1000000;
            if(nanosleep(&ts, NULL) == 0) {
                // Finally, release mutex
                if(pthread_mutex_unlock(args->mutex) == 0)
                    // Only if all steps were completed successfully, the thread
                    // status is set to success.
                    args->thread_complete_success = true;
                else {
                    perror("pthread_mutex_unlock");
                    ERROR_LOG("Failed to RELEASE mutex!");
                }
            }
            else {
                perror("nanosleep");
                ERROR_LOG("Failed to wait AFTER obtaining mutex!");
            }
        }
        else {
            perror("pthread_mutex_lock");
            ERROR_LOG("Failed to OBTAIN mutex!");
        }
    }
    else {
        perror("nanosleep");
        ERROR_LOG("Failed to wait BEFORE obtaining mutex!");
    }

    DEBUG_LOG("Thread finished successfully! wait before: %d, wait_after: %d", args->wait_to_obtain_ms, args->wait_to_release_ms);

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data *thread_args = (struct thread_data *)malloc(sizeof(struct thread_data));
    if(thread_args == NULL)
        ERROR_LOG("Failed to allocate memory for thread_data!");
    else {
        thread_args->mutex = mutex;
        thread_args->wait_to_obtain_ms = wait_to_obtain_ms;
        thread_args->wait_to_release_ms = wait_to_release_ms;
        int rc = pthread_create(thread, NULL, threadfunc, thread_args);
        if(rc != 0) {
            perror("pthread_create");
            ERROR_LOG("Failed to create thread!");
        }
        else
            return true;
    }
    return false;
}

