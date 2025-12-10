/* Minimal thread/mutex compatibility layer for MinGW: map CreateThread/WaitForSingleObject/CreateMutex to pthreads.
 * For native Windows builds (MSVC), these are standard WinAPI calls and this header is a no-op.
 */
#ifndef WIN_THREAD_COMPAT_H
#define WIN_THREAD_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Only enable compatibility layer for MinGW (not MSVC) */
#if (defined(__MINGW32__) || defined(__MINGW64__)) && !defined(__CYGWIN__)

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned long DWORD;
typedef void* LPVOID;
#ifndef WINAPI
#define WINAPI
#endif
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0u
#endif

/* Define a HANDLE-like opaque pointer for MinGW that encapsulates pthread types */
typedef struct compat_handle_s compat_handle_t;
typedef compat_handle_t* HANDLE;

/* Maps several WinAPI calls to pthreads */
HANDLE CreateMutex(LPVOID lpMutexAttributes, int bInitialOwner, const char* lpName);
int ReleaseMutex(HANDLE hMutex);
HANDLE CreateThread(LPVOID lpThreadAttributes, size_t dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId);
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
int CloseHandle(HANDLE hObject);
void Sleep(DWORD milliseconds);

#endif /* MinGW/posix fallback */

#ifdef __cplusplus
}
#endif

#endif /* WIN_THREAD_COMPAT_H */
