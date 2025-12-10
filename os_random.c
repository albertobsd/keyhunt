/* Implementation of os_getrandom: uses /dev/urandom on POSIX and BCryptGenRandom on Windows */
#include "os_random.h"

#include <stddef.h>
#include <stdio.h>

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <bcrypt.h>

int os_getrandom(void *buf, size_t buflen) {
    if (buf == NULL || buflen == 0) return -1;
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)buflen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
}

#else
#include <fcntl.h>
#include <unistd.h>

int os_getrandom(void *buf, size_t buflen) {
    if (buf == NULL || buflen == 0) return -1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, buflen);
    close(fd);
    return (r == (ssize_t)buflen) ? 0 : -1;
}

#endif
