/* Implementation of compatibility layer that maps basic WinAPI thread/mutex usage to pthreads under MinGW. */
#include "win_thread_compat.h"

#if (defined(__MINGW32__) || defined(__MINGW64__)) && !defined(__CYGWIN__)

#include <stdio.h>
#include <string.h>

struct compat_handle_s {
    int type; /* 0=mutex, 1=thread */
    union {
        pthread_mutex_t mutex;
        pthread_t thread;
    } u;
    int detached; /* for threads */
};

HANDLE CreateMutex(LPVOID lpMutexAttributes, int bInitialOwner, const char* lpName) {
    (void)lpMutexAttributes; (void)lpName;
    struct compat_handle_s *h = (struct compat_handle_s*)malloc(sizeof(struct compat_handle_s));
    if(!h) return NULL;
    h->type = 0;
    h->detached = 0;
    pthread_mutex_init(&h->u.mutex, NULL);
    if (bInitialOwner) pthread_mutex_lock(&h->u.mutex);
    return h;
}

int ReleaseMutex(HANDLE hMutex) {
    if (!hMutex) return -1;
    struct compat_handle_s *h = (struct compat_handle_s*)hMutex;
    if (h->type != 0) return -1;
    return pthread_mutex_unlock(&h->u.mutex);
}

typedef struct thread_start_arg_s {
    LPTHREAD_START_ROUTINE func;
    LPVOID param;
    struct compat_handle_s *h;
} thread_start_arg_t;

static void* thread_thunk(void *arg) {
    thread_start_arg_t *a = (thread_start_arg_t*)arg;
    DWORD ret = 0;
    if (a && a->func) {
        /* call the Windows-style thread function */
        ret = a->func(a->param);
    }
    free(a);
    return (void*)(uintptr_t)ret;
}

HANDLE CreateThread(LPVOID lpThreadAttributes, size_t dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId) {
    (void)lpThreadAttributes; (void)dwStackSize; (void)dwCreationFlags;
    struct compat_handle_s *h = (struct compat_handle_s*)malloc(sizeof(struct compat_handle_s));
    if (!h) return NULL;
    h->type = 1;
    h->detached = 0;
    thread_start_arg_t *arg = (thread_start_arg_t*)malloc(sizeof(thread_start_arg_t));
    if (!arg) { free(h); return NULL; }
    arg->func = lpStartAddress;
    arg->param = lpParameter;
    arg->h = h;
    pthread_t thr;
    int r = pthread_create(&thr, NULL, thread_thunk, arg);
    if (r != 0) {
        free(arg);
        free(h);
        return NULL;
    }
    h->u.thread = thr;
    if (lpThreadId) {
        *lpThreadId = (DWORD)(uintptr_t)thr;
    }
    return h;
}

DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    (void)dwMilliseconds; /* ignoring timeout, only blocking waits supported */
    if (!hHandle) return (DWORD)-1;
    struct compat_handle_s *h = (struct compat_handle_s*)hHandle;
    if (h->type == 0) {
        pthread_mutex_lock(&h->u.mutex);
        return 0; /* WAIT_OBJECT_0 */
    } else if (h->type == 1) {
        /* join thread */
        pthread_join(h->u.thread, NULL);
        return 0;
    }
    return (DWORD)-1;
}

int CloseHandle(HANDLE hObject) {
    if (!hObject) return -1;
    struct compat_handle_s *h = (struct compat_handle_s*)hObject;
    if (h->type == 0) {
        pthread_mutex_destroy(&h->u.mutex);
        free(h);
        return 0;
    } else if (h->type == 1) {
        if(!h->detached) pthread_detach(h->u.thread);
        free(h);
        return 0;
    }
    return -1;
}

void Sleep(DWORD milliseconds) {
    usleep((useconds_t)milliseconds * 1000);
}

#endif /* MinGW */
