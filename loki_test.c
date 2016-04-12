#undef  LOKI_IMPLEMENTATION
#define LOKI_IMPLEMENTATION
#include "loki_services.h"

static  size_t totalmem;
static lk_Lock memlock;

static void *debug_allocf(void *ud, void *ptr, size_t size, size_t osize) {
    void *newptr = NULL;
    if (size == 0) free(ptr);
    else newptr = realloc(ptr, size);
    lk_lock(memlock);
    totalmem += size;
    totalmem -= osize;
    lk_unlock(memlock);
    if (osize == 0)
        printf(" malloc:  %p:%d (%d)\n", newptr, (int)size, (int)totalmem);
    else if (size == 0)
        printf(" free:    %p:%d (%d)\n", ptr, (int)osize, (int)totalmem);
    else
        printf(" realloc: %p:%d -> %p:%d (%d)\n",
                ptr, (int)osize, newptr, (int)size, (int)totalmem);
    return newptr;
}

static int echo(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
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
        lk_free(S, pi, sizeof(int));
        lk_close(S);
        return 0;
    }
    lk_log(S, "V[] timer: %d: %u", *pi, elapsed);
    lk_emitstring(echo, 0, 0, "Hello World!");
    return 1000;
}

static int resp(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    if (sig != NULL) {
        lk_log(S, "res: %s", (char*)sig->data);
        lk_close(S);
    }
    return LK_OK;
}

static int loki_service_echo(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    if (slot == NULL) {
        lk_Service *svr = lk_launch(S, "timer", loki_service_timer, NULL);
        lk_Timer *t;
        int *pi = (int*)lk_malloc(S, sizeof(int));
        *pi = 0;
        lk_newslot(S, "echo", echo, NULL);
        t = lk_newtimer(svr, repeater, (void*)pi);
        lk_starttimer(t, 1000);
    }
    return LK_OK;
}

static int my_monitor(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    if (slot == NULL) {
        lk_log(S, "T[monitor] initialized!");
        int *p = lk_malloc(S, sizeof(int));
        lk_setdata(lk_current(S), p);
        return LK_WEAK;
    }
    else if (sig == NULL) {
        lk_log(S, "T[monitor] shutdown!");
        lk_free(S, lk_data(slot), sizeof(int));
        return LK_OK;
    }
    if (sig->type == 0)
        lk_log(S, "T[monitor] service '%s' required by '%s'!",
                (char*)sig->data, (char*)sig->src);
    else if (sig->type == 1)
        lk_log(S, "T[monitor] service '%s' launched by '%s'!",
                (char*)sig->data, (char*)sig->src);
    else if (sig->type == 2)
        lk_log(S, "T[monitor] service '%s' mark weak!", (char*)sig->src);
    else if (sig->type == 3)
        lk_log(S, "T[monitor] service '%s' closed!", (char*)sig->src);
    return LK_OK;
}

int main(void) {
    lk_State *S;
    (void)lk_initlock(&memlock);
    S = lk_newstate(NULL, debug_allocf, NULL);

    /*lk_openlibs(S);*/
    lk_launch(S, "log", loki_service_log, NULL);
    lk_setslothandler((lk_Slot*)S, resp);

    lk_log(S, "");
    lk_log(S, "I[]");
    lk_log(S, "I[test]" lk_loc("test test test"));
    lk_log(S, "T[test]" lk_loc("test test test"));
    lk_log(S, "V[test]" lk_loc("test test test"));
    lk_log(S, "W[test]" lk_loc("test test test"));
    lk_log(S, "E[test]" lk_loc("你好，世界"));

    lk_launch(S, "monitor", my_monitor, NULL);
    lk_launch(S, "echo", loki_service_echo, NULL);

    lk_Slot *slot = lk_slot(S, "echo.echo");
    lk_emitstring(slot, 0, 0, "Hello World!");

    lk_log(S, "thread count: %d", lk_start(S, 0));
    lk_waitclose(S);
    lk_close(S);
    printf("totalmem = %d\n", (int)totalmem);
    assert(totalmem == 0);
    return 0;
}

/* unixcc: flags+='-ggdb' input+='service_*.c' libs+='-pthread -ldl' */
/* win32cc: input+='service_*.c' libs+='-lws2_32' */
