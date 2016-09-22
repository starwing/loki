#define LOKI_IMPLEMENTATION
#include "../loki_services.h"

static int on_echo(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    if (sig->source)
        lk_log(S, "echo: %d: %s", (int)(ptrdiff_t)sig->source->ud, sig->data);
    else
        lk_log(S, "echo: %s", sig->data);
    sig->isack = 1;
    lk_emit((lk_Slot*)lk_service(sender), sig);
    return LK_OK;
}

static int on_poll(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    int i = 0;
    for (;;) {
        lk_log(S, "poll: in loop %d", i++);
        if (lk_wait(S, sig, -1) != LK_OK)
            break;
        if (sig->source)
            lk_log(S, "poll: %d: %s", (int)(ptrdiff_t)sig->source->ud, sig->data);
        else
            lk_log(S, "poll: %s", sig->data);
        sig->isack = 1;
        lk_emit((lk_Slot*)lk_service(sender), sig);
    }
    lk_log(S, "poll: exiting...");
    return LK_OK;
}

static int on_echo_return(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    int count = (int)(ptrdiff_t)sig->source->ud;
    (void)sender;
    lk_log(S, "echo callback: %d: %s", count, sig->data);
    if (count != 0) {
        lk_Slot *echo = lk_slot(S, "echo");
        lk_Slot *poll = lk_slot(S, "poll");
        /*lk_emitstring(echo, 0, "Hello");*/
        sig->source->ud = (void*)(ptrdiff_t)(count - 1);
        sig->isack = 0;
        if (echo) lk_emit(echo, sig);
        if (poll) lk_emit(poll, sig);
    }
    else {
        lk_log(S, "echo exiting...");
        lk_close(S);
    }
    return LK_OK;
}

int main(void)
{
    lk_State *S = lk_newstate(NULL, NULL, NULL);
    lk_Slot *echo = lk_newslot(S, "echo", on_echo, NULL);
    lk_Slot *poll = lk_newpoll(S, "poll", on_poll, NULL);
    lk_setcallback(S, on_echo_return, (void*)5);
    lk_emitstring(echo, 0, "Hello to slot");
    lk_setcallback(S, on_echo_return, (void*)5);
    lk_emitstring(poll, 0, "Hello to poll");
    lk_launch(S, "log", loki_service_log, NULL);
    lk_log(S, "=======================");
    lk_log(S, "test_callback start ...");
    lk_log(S, "=======================");
    lk_start(S, 0);
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* cc: flags+='-Wextra -ggdb -O0' input+='service_*.c'
 * unixcc: libs+='-pthread -ldl'
 * win32cc: libs+='-lws2_32' */

