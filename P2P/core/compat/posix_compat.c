#include "common.h"

#if !defined(__linux__)

#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#define P2P_EPOLL_MAX 1024

typedef struct {
    int                  fd;
    int                  used;
    struct epoll_event   ev;
} p2p_epoll_item_t;

static p2p_epoll_item_t p2p_epoll_items[P2P_EPOLL_MAX];

int epoll_create1(int flags)
{
    (void)flags;
    int fd = open("/dev/null", O_RDONLY);
    return fd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    (void)epfd;

    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (!event) {
            errno = EINVAL;
            return -1;
        }
        int free_slot = -1;
        for (int i = 0; i < P2P_EPOLL_MAX; i++) {
            if (p2p_epoll_items[i].used && p2p_epoll_items[i].fd == fd) {
                p2p_epoll_items[i].ev = *event;
                return 0;
            }
            if (!p2p_epoll_items[i].used && free_slot < 0)
                free_slot = i;
        }
        if (op == EPOLL_CTL_MOD) {
            errno = ENOENT;
            return -1;
        }
        if (free_slot < 0) {
            errno = ENOMEM;
            return -1;
        }
        p2p_epoll_items[free_slot].used = 1;
        p2p_epoll_items[free_slot].fd   = fd;
        p2p_epoll_items[free_slot].ev   = *event;
        return 0;
    }

    if (op == EPOLL_CTL_DEL) {
        for (int i = 0; i < P2P_EPOLL_MAX; i++) {
            if (p2p_epoll_items[i].used && p2p_epoll_items[i].fd == fd) {
                p2p_epoll_items[i].used = 0;
                return 0;
            }
        }
        errno = ENOENT;
        return -1;
    }

    errno = EINVAL;
    return -1;
}

int epoll_wait(int epfd, struct epoll_event *events,
               int maxevents, int timeout)
{
    (void)epfd;

    if (!events || maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    struct pollfd pfds[P2P_EPOLL_MAX];
    int           map[P2P_EPOLL_MAX];
    int           n = 0;

    for (int i = 0; i < P2P_EPOLL_MAX; i++) {
        if (!p2p_epoll_items[i].used)
            continue;
        pfds[n].fd      = p2p_epoll_items[i].fd;
        pfds[n].events  = 0;
        pfds[n].revents = 0;
        if (p2p_epoll_items[i].ev.events & EPOLLIN)
            pfds[n].events |= POLLIN;
        if (p2p_epoll_items[i].ev.events & EPOLLOUT)
            pfds[n].events |= POLLOUT;
        map[n] = i;
        n++;
    }

    int rc = poll(pfds, (nfds_t)n, timeout);
    if (rc < 0)
        return -1;

    int out = 0;
    for (int j = 0; j < n && out < maxevents; j++) {
        short revents = pfds[j].revents;
        if (revents == 0)
            continue;

        uint32_t e = 0;
        if (revents & (POLLIN | POLLPRI))
            e |= EPOLLIN;
        if (revents & POLLOUT)
            e |= EPOLLOUT;
        if (revents & POLLERR)
            e |= EPOLLERR;
        if (revents & POLLHUP)
            e |= EPOLLHUP;
        if (revents & POLLNVAL)
            e |= EPOLLERR;

        events[out].events = e;
        events[out].data   = p2p_epoll_items[map[j]].ev.data;
        out++;
    }

    return out;
}

int p2p_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                int flags)
{
    int fd = accept(sockfd, addr, addrlen);
    if (fd < 0)
        return -1;

    if (flags & SOCK_CLOEXEC)
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (flags & SOCK_NONBLOCK) {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0)
            (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
    return fd;
}

int p2p_pipe2(int pipefd[2], int flags)
{
    if (pipe(pipefd) < 0)
        return -1;

    if (flags & O_CLOEXEC) {
        (void)fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    if (flags & O_NONBLOCK) {
        int fl0 = fcntl(pipefd[0], F_GETFL, 0);
        int fl1 = fcntl(pipefd[1], F_GETFL, 0);
        if (fl0 >= 0) (void)fcntl(pipefd[0], F_SETFL, fl0 | O_NONBLOCK);
        if (fl1 >= 0) (void)fcntl(pipefd[1], F_SETFL, fl1 | O_NONBLOCK);
    }
    return 0;
}

#endif /* !__linux__ */
