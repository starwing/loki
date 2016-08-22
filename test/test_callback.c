#define LOKI_IMPLEMENTATION
#include "../loki_services.h"

static int on_echo(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    (void)slot;
    if (sig->source)
        lk_log(S, "echo: %d: %s", (int)(ptrdiff_t)sig->source->ud, sig->data);
    else
        lk_log(S, "echo: %s", sig->data);
    sig->isack = 1;
    lk_emit((lk_Slot*)lk_service(sig->sender), sig);
    return LK_OK;
}

static int on_echo_return(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    int count = (int)(ptrdiff_t)sig->source->ud;
    (void)slot;
    lk_log(S, "echo callback: %d: %s", count, sig->data);
    if (count != 0) {
        lk_Slot *echo = lk_slot(S, "root.echo");
        /*lk_emitstring(echo, 0, "Hello");*/
        sig->source->ud = (void*)(ptrdiff_t)(count - 1);
        sig->isack = 0;
        lk_emit(echo, sig);
    }
    else {
        lk_close(S);
    }
    return LK_OK;
}

int main(void)
{
    lk_State *S = lk_newstate(NULL, NULL, NULL);
    lk_Slot *echo = lk_newslot(S, "echo", on_echo, NULL);
    lk_setcallback(S, on_echo_return, (void*)5);
    lk_emitstring(echo, 0, "Hello");
    lk_launch(S, "log", loki_service_log, NULL);
    lk_start(S, 0);
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* cc: flags+='-Wextra -ggdb -O0' input+='service_*.c'
 * unixcc: libs+='-pthread -ldl'
 * win32cc: libs+='-lws2_32' */

