#define LOKI_IMPLEMENTATION
#include "loki_services.h"

static int echo(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_Signal new;
    printf("msg: %s\n", (char*)sig->data);
    new = *sig;
    sig->copy = 0;
    lk_emit((lk_Slot*)sig->src, &new);
    return LK_OK;
}

static lk_Time repeater(lk_State *S, void *ud, lk_Timer *timer, lk_Time elapsed) {
    lk_Slot *echo = lk_slot(S, "echo.echo");
    lk_Signal new = LK_SIGNAL;
    int *pi = (int*)ud;
    new.copy = 1;
    new.size = 13;
    if ((*pi)++ == 10) {
        lk_free(S, pi);
        lk_close(S);
        return 0;
    }
    printf("timer: %d: %u\n", *pi, elapsed);
    new.data = lk_strdup(S, "hello world!");
    lk_emit(echo, &new);
    return 1000;
}

static int resp(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    if (sig != NULL) {
        printf("res: %s\n", (char*)sig->data);
        lk_close(S);
    }
    return LK_OK;
}

static int loki_service_echo(lk_State *S) {
    lk_Service *svr = lk_require(S, "timer");
    lk_Timer *t;
    int *pi = lk_malloc(S, sizeof(int));
    *pi = 0;
    lk_newslot(S, "echo", echo, NULL);
    t = lk_newtimer(svr, repeater, (void*)pi);
    lk_starttimer(t, 1000);
    return LK_OK;
}

int main(void) {
    lk_State *S = lk_newstate();
    lk_openlibs(S);
    lk_setslothandler((lk_Slot*)S, resp, NULL);

    lk_requiref(S, "echo", loki_service_echo);

    lk_Slot *slot = lk_slot(S, "echo.echo");
    lk_Signal sig = LK_SIGNAL;
    sig.copy = 1;
    sig.size = 13;
    sig.data = lk_strdup(S, "hello world!");
    lk_emit(slot, &sig);

    printf("thread count: %d\n", lk_start(S));
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* unixcc: input+='service_timer.c' libs+='-pthread -ldl' */
/* win32cc: input+='service_timer.c' */
