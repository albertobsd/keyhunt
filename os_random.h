/* Portable random bytes provider
 * Provides os_getrandom(void *buf, size_t len) -> 0 on success, -1 on error
 */
#ifndef OS_RANDOM_H
#define OS_RANDOM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int os_getrandom(void *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* OS_RANDOM_H */
