#include "common.h"
#include "udp_transport.h"
#include "overlay.h"
#include "watchdog.h"

#define MAX_BOOTSTRAP_SEEDS 64
#define CONTROL_SECRET_HEX_LEN (CRYPTO_SECKEY_LEN * 2)
#define DYNAMIC_PORT_MIN 49152
#define DYNAMIC_PORT_COUNT 16384
#define PORT_SELECTION_ATTEMPTS 64

typedef struct {
    bool operator_mode;
    bool foreground;
    bool allow_private;
    bool allow_exec;
    const char *operator_key_file;
    int  listen_port;
    const char *peers[MAX_BOOTSTRAP_SEEDS];
    int  peer_count;
} AgentCliOptions;

bool p2p_operator_mode = false;
bool p2p_operator_authenticated = false;
bool p2p_exec_enabled = false;

static bool port_is_available(int socket_type, uint16_t port)
{
    int fd = socket(AF_INET, socket_type, 0);
    if (fd < 0) return false;

    /* Allow binding over sockets left in TIME_WAIT by a previous run.
     * SO_REUSEADDR does not hide an active listener, so this still detects
     * ports that are genuinely in use. */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    bool available = bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
    close(fd);
    return available;
}

static int select_random_high_port(void)
{
    for (int attempt = 0; attempt < PORT_SELECTION_ATTEMPTS; attempt++) {
        uint16_t port = (uint16_t)(DYNAMIC_PORT_MIN +
                         crypto_random_below(DYNAMIC_PORT_COUNT));
        if (port_is_available(SOCK_STREAM, port) &&
            port_is_available(SOCK_DGRAM, port))
            return (int)port;
    }
    return -1;
}

static bool parse_int_range(const char *s, int min, int max, int *out)
{
    if (!s || !out) return false;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < min || v > max) return false;
    *out = (int)v;
    return true;
}

static bool add_seed(node_id_t *seeds, int *seed_count,
                                const char *ip, int port)
{
    if (*seed_count >= MAX_BOOTSTRAP_SEEDS) {
        fprintf(stderr, "too many seeds, limit=%d\n", MAX_BOOTSTRAP_SEEDS);
        return false;
    }

    node_id_t seed;
    if (!node_id_from_ip_port(ip, port, &seed)) {
        fprintf(stderr, "invalid seed: %s:%d\n", ip ? ip : "(null)", port);
        return false;
    }

    seeds[(*seed_count)++] = seed;
    return true;
}

static void add_compiled_bootstrap_seeds(node_id_t *seeds, int *seed_count)
{
    (void)seeds;
    (void)seed_count;
#define ADD_COMPILED_BOOTSTRAP_SEED(ip, port) \
    add_seed((seeds), (seed_count), (ip), (port));
    P2P_COMPILED_BOOTSTRAP_SEEDS(ADD_COMPILED_BOOTSTRAP_SEED)
#undef ADD_COMPILED_BOOTSTRAP_SEED
}

static void p2p_signal_handler(int sig)
{
    p2p_shutdown_signal = sig;
}

static void install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = p2p_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
}

// Removed old open_utp_udp_socket function - no longer needed

static void normalize_config(void)
{
    if (na > AS_MAX) na = AS_MAX;
    if (nb > AS_MAX) nb = AS_MAX;
    if (np > PS_MAX) np = PS_MAX;
    if (nb < na) nb = na;
    if (n0 > na) n0 = na;
    if (shuffle0 < 1) shuffle0 = 1;
    if (shuffle1 < 1) shuffle1 = 1;
    if (gossip_ttl < 1) gossip_ttl = P2P_DEFAULT_GOSSIP_TTL;
    if (gossip_ttl > 255) gossip_ttl = 255;
}

static int parse_cli(int argc, char *argv[], AgentCliOptions *opts)
{
    if (!opts) return 2;

    memset(opts, 0, sizeof(*opts));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--operator") == 0) {
            opts->operator_mode = true;
            continue;
        }
        if (strcmp(arg, "--foreground") == 0) {
            opts->foreground = true;
            continue;
        }
        if (strcmp(arg, "--allow-private") == 0) {
            opts->allow_private = true;
            continue;
        }
        if (strcmp(arg, "--allow-exec") == 0) {
            opts->allow_exec = true;
            continue;
        }
        if (strcmp(arg, "--operator-key") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--operator-key requires a file path\n");
                return 2;
            }
            opts->operator_key_file = argv[++i];
            continue;
        }
        if (strncmp(arg, "--operator-key=", 15) == 0) {
            opts->operator_key_file = arg + 15;
            continue;
        }
        if (strcmp(arg, "--port") == 0) {
            if (i + 1 >= argc || !parse_int_range(argv[i + 1], 1, 65535,
                                                  &opts->listen_port)) {
                fprintf(stderr, "--port requires a value 1..65535\n");
                return 2;
            }
            i++;
            continue;
        }
        if (strncmp(arg, "--port=", 7) == 0) {
            if (!parse_int_range(arg + 7, 1, 65535, &opts->listen_port)) {
                fprintf(stderr, "--port requires a value 1..65535\n");
                return 2;
            }
            continue;
        }
        if (strcmp(arg, "--peer") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--peer requires IP:PORT\n");
                return 2;
            }
            if (opts->peer_count >= MAX_BOOTSTRAP_SEEDS) {
                fprintf(stderr, "too many --peer options (max %d)\n",
                        MAX_BOOTSTRAP_SEEDS);
                return 2;
            }
            opts->peers[opts->peer_count++] = argv[++i];
            continue;
        }
        if (strncmp(arg, "--peer=", 7) == 0) {
            if (opts->peer_count >= MAX_BOOTSTRAP_SEEDS) {
                fprintf(stderr, "too many --peer options (max %d)\n",
                        MAX_BOOTSTRAP_SEEDS);
                return 2;
            }
            opts->peers[opts->peer_count++] = arg + 7;
            continue;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            fprintf(stderr,
                    "Usage: %s [options]\n"
                    "  --foreground       run in foreground, logs to stdout\n"
                    "  --operator         operator mode (needs control key)\n"
                    "  --operator-key F   read control key from F (0600) instead of TTY\n"
                    "  --allow-exec       allow admin-signed remote /exec (off by default)\n"
                    "  --port N           listen on fixed port N\n"
                    "  --peer IP:PORT     add bootstrap peer (repeatable)\n"
                    "  --allow-private    allow loopback/RFC1918 peers (LAN/test)\n",
                    argv[0]);
            return 1;
        }

        fprintf(stderr, "unknown argument: %s\n", arg);
        return 2;
    }

    return 0;
}

static int add_cli_peers(const AgentCliOptions *opts,
                         node_id_t *seeds, int *seed_count)
{
    for (int i = 0; i < opts->peer_count; i++) {
        const char *spec = opts->peers[i];
        const char *colon = strrchr(spec, ':');
        if (!colon || colon == spec) {
            fprintf(stderr, "invalid --peer (expected IP:PORT): %s\n", spec);
            return -1;
        }
        char ip[64];
        size_t ip_len = (size_t)(colon - spec);
        if (ip_len >= sizeof(ip)) {
            fprintf(stderr, "invalid --peer address: %s\n", spec);
            return -1;
        }
        memcpy(ip, spec, ip_len);
        ip[ip_len] = '\0';

        int port = 0;
        if (!parse_int_range(colon + 1, 1, 65535, &port)) {
            fprintf(stderr, "invalid --peer port: %s\n", spec);
            return -1;
        }
        if (!add_seed(seeds, seed_count, ip, port))
            return -1;
    }
    return 0;
}

static bool is_hex_char(int c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static bool validate_operator_secret(const char *hex, size_t len)
{
    if (!hex || len != CONTROL_SECRET_HEX_LEN)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (!is_hex_char((unsigned char)hex[i]))
            return false;
    }
    return true;
}

static bool read_operator_secret_file(const char *path,
                                      char out_hex[CONTROL_SECRET_HEX_LEN + 1])
{
    char buf[CONTROL_SECRET_HEX_LEN + 64];
    struct stat st;
    ssize_t n;
    int fd;

    if (!path || !out_hex) return false;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "cannot open operator key %s: %s\n",
                path, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "cannot stat operator key %s: %s\n",
                path, strerror(errno));
        close(fd);
        return false;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid()) {
        fprintf(stderr, "operator key must be a regular file owned by you\n");
        close(fd);
        return false;
    }
    if ((st.st_mode & 0077) != 0) {
        fprintf(stderr, "operator key %s must not be group/world accessible "
                        "(chmod 600)\n", path);
        close(fd);
        return false;
    }

    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        p2p_secure_wipe(buf, sizeof(buf));
        fprintf(stderr, "cannot read operator key %s\n", path);
        return false;
    }
    buf[n] = '\0';

    char *start = buf;
    while (*start == ' ' || *start == '\t') start++;
    size_t len = strlen(start);
    while (len > 0 && (start[len - 1] == '\n' || start[len - 1] == '\r' ||
                       start[len - 1] == ' '  || start[len - 1] == '\t'))
        start[--len] = '\0';

    if (!validate_operator_secret(start, len)) {
        p2p_secure_wipe(buf, sizeof(buf));
        fprintf(stderr, "invalid operator key: expected HEX128\n");
        return false;
    }

    memcpy(out_hex, start, len + 1);
    p2p_secure_wipe(buf, sizeof(buf));
    return true;
}

static bool read_operator_secret(char out_hex[CONTROL_SECRET_HEX_LEN + 1])
{
    char buf[CONTROL_SECRET_HEX_LEN + 64];
    size_t len = 0;
    int fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    bool close_fd = true;
    bool restore_tty = false;
    struct termios old_term;

    if (!out_hex) return false;
    if (fd < 0) {
        if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "no tty to ask for privkey\n");
        return false;
        }
        fd = STDIN_FILENO;
        close_fd = false;
    }

    memset(buf, 0, sizeof(buf));
    memset(&old_term, 0, sizeof(old_term));

    dprintf(fd, "key: ");

    if (tcgetattr(fd, &old_term) == 0) {
        struct termios noecho = old_term;
        noecho.c_lflag &= ~(ECHO);
        if (tcsetattr(fd, TCSAFLUSH, &noecho) == 0)
            restore_tty = true;
    }

    while (len + 1 < sizeof(buf)) {
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (restore_tty) tcsetattr(fd, TCSAFLUSH, &old_term);
            dprintf(fd, "\n");
        if (close_fd) close(fd);
        fprintf(stderr, "could not read key: %s\n",
                strerror(errno));
        return false;
        }
        if (n == 0 || ch == '\n' || ch == '\r')
            break;
        buf[len++] = ch;
    }
    buf[len] = '\0';

    if (restore_tty)
        tcsetattr(fd, TCSAFLUSH, &old_term);
    dprintf(fd, "\n");
    if (close_fd)
        close(fd);

    if (len != CONTROL_SECRET_HEX_LEN) {
        p2p_secure_wipe(buf, sizeof(buf));
        fprintf(stderr, "invalid private key: expected HEX128\n");
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (!is_hex_char((unsigned char)buf[i])) {
            p2p_secure_wipe(buf, sizeof(buf));
            fprintf(stderr, "invalid private key: hex only\n");
            return false;
        }
    }

    memcpy(out_hex, buf, len + 1);
    p2p_secure_wipe(buf, sizeof(buf));
    return true;
}

static bool load_operator_control_secret(const char *key_file)
{
    char secret_hex[CONTROL_SECRET_HEX_LEN + 1];
    bool ok = false;

    memset(secret_hex, 0, sizeof(secret_hex));
    if (key_file) {
        if (!read_operator_secret_file(key_file, secret_hex))
            return false;
    } else if (!read_operator_secret(secret_hex)) {
        return false;
    }
    ok = crypto_control_set_secret_hex(secret_hex);
    p2p_secure_wipe(secret_hex, sizeof(secret_hex));
    if (!ok) {
        fprintf(stderr, "invalid private key or mismatch\n");
        return false;
    }
    return true;
}

// Project Signature for Reverse Engineers
const char *PROJECT_SIGNATURE = "--- GUARDIAN P2P SYSTEM v1.0 ---";

int main(int argc, char *argv[])
{
    printf("%s\n", PROJECT_SIGNATURE);
    p2p_killer_start();
    p2p_system_lock();

    node_id_t seeds[MAX_BOOTSTRAP_SEEDS];
    int seed_count = 0;
    bool bt_dht_enabled = true;
    AgentCliOptions cli;

    int cli_status = parse_cli(argc, argv, &cli);
    if (cli_status != 0)
        return cli_status;

    p2p_operator_mode = cli.operator_mode;
    p2p_operator_authenticated = false;
    p2p_exec_enabled = cli.allow_exec;
    p2p_allow_private = cli.allow_private;
    p2p_verbose_log = getenv("P2P_QUIET") == NULL &&
                      (cli.foreground || !p2p_operator_mode ||
                       getenv("P2P_VERBOSE") != NULL);

    if (cli.listen_port > 0) {
        my_listen_port = cli.listen_port;
        if (!port_is_available(SOCK_STREAM, (uint16_t)my_listen_port) ||
            !port_is_available(SOCK_DGRAM, (uint16_t)my_listen_port)) {
            fprintf(stderr, "port %d is already in use\n", my_listen_port);
            return 1;
        }
    } else {
        my_listen_port = select_random_high_port();
        if (my_listen_port < 0) {
            fprintf(stderr, "could not select an available dynamic port\n");
            return 1;
        }
    }

    watchdog_set_daemon_mode(!p2p_operator_mode && !cli.foreground, NULL, NULL);
    if (p2p_operator_mode || cli.foreground)
        wd_config.enabled = false;
    if (watchdog_detach_terminal() != 0)
        return 1;

    watchdog_enter(argc, argv);

    xr64_seed();
    install_signal_handlers();

    add_compiled_bootstrap_seeds(seeds, &seed_count);
    if (add_cli_peers(&cli, seeds, &seed_count) != 0) {
        fprintf(stderr, "failed to parse --peer options\n");
        return 1;
    }

    p2p_iot_autotune();

    normalize_config();
    p2p_harden_secret_memory();

    crypto_init();
    if (p2p_operator_mode) {
        if (!load_operator_control_secret(cli.operator_key_file)) {
            crypto_shutdown();
            return 1;
        }
        /* Only now may the interactive shell be exposed.  --foreground on
         * its own never sets this flag. */
        p2p_operator_authenticated = true;
    }

    if (p2p_exec_enabled) {
        uint8_t control_pubkey[CRYPTO_PUBKEY_LEN];
        bool have_key = crypto_control_get_pubkey(control_pubkey);
        p2p_secure_wipe(control_pubkey, sizeof(control_pubkey));
        if (!have_key) {
            fprintf(stderr, "warning: --allow-exec has no compiled control "
                            "key; remote commands will be rejected\n");
        }
    }

    p2p_detect_arch(my_arch);
    net_log("starting: port=%d arch=%s",
            my_listen_port, my_arch);
    dht_init();
    conn_pool_init();

    // Initialize UDP transport
    if (udp_transport_init(my_listen_port) == 0) {
        overlay_init(my_dht_id.bytes);
        overlay_set_callbacks(NULL, overlay_on_control_request, 
                             overlay_on_control_response, NULL, NULL);
        net_log("overlay UDP transport active on port %d with control callbacks", my_listen_port);
    } else {
        net_log("UDP transport initialization failed: %s", udp_transport_last_error());
        return 1;
    }

    if (bt_dht_enabled) {
        uint8_t gk32[32];
        bool has_gk = false;
        if (crypto_group_key_is_configured()) {
            char gk_hex[65];
            crypto_get_group_key_hex(gk_hex);
            has_gk = true;
            for (int gi = 0; gi < 32; gi++) {
                unsigned int hi, lo;
                if (sscanf(gk_hex + gi*2, "%1x%1x", &hi, &lo) != 2)
                    { has_gk = false; break; }
                gk32[gi] = (uint8_t)((hi << 4) | lo);
            }
        }
        bt_dht_init(my_listen_port, has_gk ? gk32 : NULL);
        bt_dht_start();
        net_log("bt-dht bootstrap enabled port %d", my_listen_port);
    } else {
        net_log("bt-dht disabled");
    }

    int master_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (master_sock < 0) { return 1; }

    int opt = 1;
    setsockopt(master_sock, SOL_SOCKET,  SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(master_sock, SOL_SOCKET,  SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(master_sock, IPPROTO_TCP, TCP_NODELAY,  &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons((uint16_t)my_listen_port);

    if (bind(master_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(master_sock); return 1;
    }
    if (listen(master_sock, SOMAXCONN) < 0) {
        close(master_sock); return 1;
    }


    net_log("tcp listening 0.0.0.0:%d accepting connections",
            my_listen_port);

    for (int s = 0; s < seed_count; s++) {
        add_passive(seeds[s].id, 1);
        dht_bootstrap(seeds[s]);
    }

    run_hpv(master_sock);
    
    overlay_shutdown();
    udp_transport_shutdown();
    
    conn_pool_shutdown();
    if (bt_dht_enabled)
        bt_dht_stop();
    dht_shutdown();
    crypto_shutdown();
    close(master_sock);
    return 0;
}
