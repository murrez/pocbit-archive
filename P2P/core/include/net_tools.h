// net_tools.h - bounded, one-shot network diagnostics used by the operator shell

#ifndef P2P_NET_TOOLS_H
#define P2P_NET_TOOLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_NET_DEFAULT_TIMEOUT_MS 5000
#define P2P_NET_MAX_TIMEOUT_MS    15000
#define P2P_NET_MAX_RESPONSE      65536
#define P2P_NET_MAX_ICMP_COUNT        4

/*
 * All functions are single-shot and bounded: they resolve one host, perform
 * one request, enforce a timeout and never loop over hosts or ports.
 *
 * On success they return 0 (or an HTTP status for p2p_net_http_request) and
 * fill `out` with a human-readable result.  On failure they return -1 and
 * fill `out` with an error description.
 */

/* Send one UDP datagram.  If wait_reply is true, wait for at most one reply. */
int p2p_net_udp_send(const char *host, uint16_t port,
                     const void *data, size_t len,
                     bool wait_reply, int timeout_ms,
                     char *out, size_t out_len);

/* Connect to host:port, optionally send data, then read a bounded reply. */
int p2p_net_tcp_request(const char *host, uint16_t port,
                        const void *send_data, size_t send_len,
                        int timeout_ms, char *out, size_t out_len);

/* Send 1..P2P_NET_MAX_ICMP_COUNT ICMP echo requests. */
int p2p_net_icmp_ping(const char *host, int count, int timeout_ms,
                      char *out, size_t out_len);

/*
 * Perform an HTTP request.  `method` is GET/POST/PUT/DELETE/HEAD (NULL means
 * GET).  `content_type` and `body` may be NULL.  Returns the HTTP status
 * code (100-599) on success, or -1 on a transport/parse error.  `out`
 * receives the response body (sanitized, NUL-terminated).
 *
 * http:// always works.  https:// is used when the build detected libcurl;
 * otherwise it returns an explanatory error.
 */
int p2p_net_http_request(const char *method, const char *url,
                         const char *content_type, const char *body,
                         int timeout_ms, char *out, size_t out_len);

/* Minecraft Java Edition server-list ping (handshake + status + ping). */
int p2p_net_minecraft_status(const char *host, uint16_t port,
                             int timeout_ms, char *out, size_t out_len);

/* POST a message to a Discord webhook (https://discord.com/api/webhooks/...). */
int p2p_net_discord_webhook(const char *webhook_url, const char *content,
                            int timeout_ms, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // P2P_NET_TOOLS_H
