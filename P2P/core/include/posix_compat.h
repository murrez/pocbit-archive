#ifndef P2P_POSIX_COMPAT_H
#define P2P_POSIX_COMPAT_H

/*
 * Linux-compatible shims for platforms (e.g. macOS/BSD) that lack epoll,
 * accept4, pipe2 and getrandom.
 *
 * Included from common.h only when they are not provided by the system.
 */

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

/* socket(2) accepts these flags on Linux; on other platforms they are
 * zeroed out. Callers that need CLOEXEC/NONBLOCK semantics get them from
 * the helpers below where it matters. */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

/* ---- epoll (poll-backed) ---- */

#define EPOLLIN        0x001u
#define EPOLLPRI       0x002u
#define EPOLLOUT       0x004u
#define EPOLLERR       0x008u
#define EPOLLHUP       0x010u
#define EPOLL_CLOEXEC  0

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events,
               int maxevents, int timeout);

/* ---- accept4 / pipe2 ---- */

int p2p_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                int flags);
int p2p_pipe2(int pipefd[2], int flags);

#ifndef accept4
#define accept4 p2p_accept4
#endif
#ifndef pipe2
#define pipe2 p2p_pipe2
#endif

#endif /* P2P_POSIX_COMPAT_H */
