#define LOKI_IMPLEMENTATION
#include "../loki_services.h"


static int on_echo(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_log(S, "receive message: %s", sig->data);
    sig->isack = 1;
    lk_emit(sender, sig);
    return LK_OK;
}

static int on_echo_return(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_log(S, "from %s return: %s", sender, sig->data);
    lk_close(S);
    return LK_OK;
}

static int on_echo_listener(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_log(S, "from listener#%d (slot: %s): %s",
            (int)(ptrdiff_t)sig->source->ud, sender, sig->data);
    return LK_OK;
}

int main(void) {
    lk_State *S = lk_newstate(NULL, NULL, NULL);
    lk_Slot *echo = lk_newslot(S, "echo", on_echo, NULL);
    lk_launch(S, "log", loki_service_log, NULL);
    lk_setcallback(S, on_echo_return, NULL);
    lk_addlistener(S, echo, on_echo_listener, (void*)(ptrdiff_t)1);
    lk_addlistener(S, echo, on_echo_listener, (void*)(ptrdiff_t)2);
    lk_addlistener(S, echo, on_echo_listener, (void*)(ptrdiff_t)3);
    lk_addlistener(S, echo, on_echo_listener, (void*)(ptrdiff_t)4);
    lk_addlistener(S, echo, on_echo_listener, (void*)(ptrdiff_t)5);
    lk_emitstring(echo, 0, "Hello slot!");
    lk_start(S, 0);
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* cc: flags+='-Wextra -ggdb -O0' input+='service_log.c'
 * unixcc: libs+='-pthread -ldl'
 * win32cc: libs+='-lws2_32' */

