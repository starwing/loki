#undef  LOKI_IMPLEMENTATION
#define LOKI_IMPLEMENTATION
#define LK_DEBUG_MEM
#include "loki_services.h"

static int echo(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_Signal ret;
    lk_log(S, "msg: %s", (char*)sig->data);
    lk_log(S, "T[]" lk_loc("get msg: [%s]"), (char*)sig->data);
    ret = *sig;
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
    lk_log(S, "V[] timer: %d: %u", *pi, elapsed);
    lk_emitstring(echo, 0, 0, "Hello World!");
    return 1000;
}

static int resp(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    if (sig != NULL) {
        lk_log(S, "res: %s", (char*)sig->data);
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
    lk_require(S, "log");
    lk_setslothandler((lk_Slot*)S, resp, NULL);

    lk_log(S, "");
    lk_log(S, "I[]");
    lk_log(S, "I[test]" lk_loc("test test test"));
    lk_log(S, "T[test]" lk_loc("test test test"));
    lk_log(S, "V[test]" lk_loc("test test test"));
    lk_log(S, "W[test]" lk_loc("test test test"));
    lk_log(S, "E[test]" lk_loc("你好，世界"));

    lk_requiref(S, "echo", loki_service_echo);

    lk_Slot *slot = lk_slot(S, "echo.echo");
    lk_emitstring(slot, 0, 0, "Hello World!");

    lk_log(S, "thread count: %d", lk_start(S));
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* unixcc: input+='service_*.c' libs+='-pthread -ldl -lrt' */
/* win32cc: input+='service_*.c' libs+='-lws2_32' */
