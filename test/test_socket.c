#define LK_DEBUG_MEM
#define LOKI_IMPLEMENTATION
#include "../loki_services.h"

#include <stdio.h>

static void on_tcp(lk_State *S, void *ud, unsigned err, lk_Accept *accept, lk_Tcp *tcp) {
    lk_send(tcp, "Hello World!", 12);
    lk_deltcp(tcp);
    lk_delaccept(accept);
}

static size_t on_header(lk_State *S, void *ud, lk_Tcp *tcp, const char *s, size_t len) {
    if (s) {
        printf("%.*s\n", (int)len, s);
        lk_close(S);
    }
    return len;
}

int main(void) {
    lk_State *S = lk_newstate(NULL, NULL, NULL);
    lk_Accept *accept;
    lk_Service *svr;
    lk_launch(S, "log", loki_service_log, NULL);
    svr = lk_launch(S, "socket", loki_service_socket, NULL);
    lk_setonheader(svr, on_header, NULL);
    accept = lk_newaccept(svr, on_tcp, NULL);
    lk_listen(accept, "127.0.0.1", 12345);
    lk_connect(svr, "127.0.0.1", 12345, NULL, NULL);
    lk_start(S, 0);
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* unixcc: flags+='-ggdb' input+='service_*.c' libs+='-pthread -ldl' */
/* win32cc: cc='clang' output='test_socket.exe' input+='service_*.c' libs+='-lws2_32' */

