#define LOKI_IMPLEMENTATION
#include "loki.h"

static int echo(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_Signal new;
    printf("msg: %s\n", (char*)sig->data);
    new = *sig;
    sig->copy = 0;
    lk_emit((lk_Slot*)sig->src, &new);
    return LK_OK;
}

static int repeater(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_Slot *echo = lk_slot(S, "echo.echo");
    lk_Signal new = LK_SIGNAL_INIT_VALUE;
    int i;
    new.copy = 1;
    new.size = 13;
    for (i = 0; i < 10; ++i) {
        new.data = lk_strdup(S, "hello world!");
        lk_emit(echo, &new);
        lk_wait(slot, NULL, 1000);
    }
    lk_close(S);
    return LK_OK;
}

static int resp(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    if (sig != NULL) {
        printf("res: %s\n", (char*)sig->data);
        lk_close(S);
    }
    return LK_OK;
}

static int snopen_echo(lk_State *S) {
    lk_newslot(S, "echo", echo, NULL);
    lk_newpoll(S, "repeater", repeater, NULL);
    return LK_OK;
}

int main(void) {
    lk_State *S = lk_newstate();
    lk_setslothandler((lk_Slot*)S, resp, NULL);

    lk_requiref(S, "echo", snopen_echo);

    lk_Slot *slot = lk_slot(S, "echo.echo");
    lk_Signal sig = LK_SIGNAL_INIT_VALUE;
    sig.copy = 1;
    sig.size = 13;
    sig.data = lk_strdup(S, "hello world!");
    lk_emit(slot, &sig);

    printf("thread count: %d\n", lk_start(S));
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* unixcc: libs+='-pthread -ldl' */
