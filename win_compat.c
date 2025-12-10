/* Minimal Windows compatibility wrappers for sockets */
#include "win_compat.h"

#if (defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)) && !defined(__CYGWIN__)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

int socket_init(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return -1;
    return 0;
}

void socket_cleanup(void) {
    WSACleanup();
}

int socket_close(int sockfd) {
    if (closesocket((SOCKET)sockfd) == SOCKET_ERROR) return -1;
    return 0;
}

#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int socket_init(void) { return 0; }
void socket_cleanup(void) { (void)0; }
int socket_close(int sockfd) { return close(sockfd); }

#endif
