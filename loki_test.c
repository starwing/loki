#define LOKI_IMPLEMENTATION
#include "loki.h"

static int echo(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    printf("msg: %s\n", (char*)sig->data);
    lk_emit((lk_Slot*)sig->src, sig);
    lk_close(S);
    return LK_OK;
}

static int resp(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    printf("res: %s\n", (char*)sig->data);
    lk_close(S);
    return LK_OK;
}

static int snopen_echo(lk_State *S) {
    lk_newslot(S, "echo", echo, NULL);
    return LK_OK;
}

int main(void) {
    lk_State *S = lk_newstate();
    lk_setslothandler((lk_Slot*)S, resp, NULL);

    lk_requiref(S, "echo", snopen_echo);

    lk_Slot *slot = lk_slot(S, "echo.echo");
    lk_Signal sig = { NULL };
    sig.data = "hello world!";

    printf("thread count: %d\n", lk_start(S));
    lk_emit(slot, &sig);
    lk_waitclose(S);
    lk_close(S);
    return 0;
}

/* unixcc: libs+='-pthread -ldl' */
