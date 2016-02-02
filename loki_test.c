#define LK_DEBUG_MEM
#define LOKI_IMPLEMENTATION
#include "loki_services.h"

static int echo(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_Signal ret = *sig;
    printf("msg: %s\n", (char*)sig->data);
    sig->free = 0;
    lk_emit((lk_Slot*)sig->src, &ret);
    return LK_OK;
}

static lk_Time repeater(lk_State *S, void *ud, lk_Timer *timer, lk_Time elapsed) {
    lk_Slot *echo = lk_slot(S, "echo.echo");
    int *pi = (int*)ud;
    if ((*pi)++ == 10) {
        lk_free(S, pi);
        lk_close(S);
        return 0;
    }
    printf("timer: %d: %u\n", *pi, elapsed);
    lk_emitstring(echo, 0, 0, "Hello world!");
    return 1;
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
    int *pi = (int*)lk_malloc(S, sizeof(int));
    *pi = 0;
    lk_newslot(S, "echo", echo, NULL);
    t = lk_newtimer(svr, repeater, (void*)pi);
    lk_starttimer(t, 1000);

    return LK_OK;
}

int main(void) {
    lk_State *S = lk_newstate(NULL);
    lk_openlibs(S);
    lk_setslothandler((lk_Slot*)S, resp, NULL);

    lk_requiref(S, "echo", loki_service_echo);

    lk_Slot *slot = lk_slot(S, "echo.echo");
    lk_emitstring(slot, 0, 0, "Hello World!");

    printf("thread count: %d\n", lk_start(S));
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* unixcc: input+='service_*.c' libs+='-pthread -ldl -lrt' */
/* win32cc: input+='service_*.c' libs+='-lws2_32' */
