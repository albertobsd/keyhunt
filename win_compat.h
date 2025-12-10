/* Minimal Windows compatibility wrappers for sockets */
#ifndef WIN_COMPAT_H
#define WIN_COMPAT_H

/* Initialize socket subsystem on Windows, no-op on POSIX. */
#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__MINGW32__) && !defined(__MINGW64__)
#include "win_thread_compat.h"
#endif

int socket_init(void);
void socket_cleanup(void);
int socket_close(int sockfd);

#ifdef __cplusplus
}
#endif

#endif /* WIN_COMPAT_H */
