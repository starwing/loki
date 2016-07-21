#define LOKI_MODULE
#include "loki_services.h"


#define lkX_getstate(svr) ((lk_MonitorState*)lk_data((lk_Slot*)(svr)))

typedef lkQ_type(struct lk_MonitorNode) lk_MonitorList;

typedef struct lk_MonitorNode {
    lkQ_entry(struct lk_MonitorNode);
    lk_Service *svr;
    lk_MonitorHandler *handler;
    void *ud;
} lk_MonitorNode;

typedef struct lk_MonitorState {
    lk_State *S;
    lk_MemPool callbcaks;
    int current;
    lk_MonitorList cbs[LK_MONITOR_EVENTS];
    lk_Lock lock;
} lk_MonitorState;

static int lkX_triggerevent (lk_State *S, lk_MonitorNode *list, lk_Signal *sig) {
    lk_MonitorNode *node, *volatile next;
    volatile int removed = 0;
    lk_Service *svrs[2];
    lk_Context ctx;
    svrs[0] = sig->src;
    svrs[1] = (lk_Service*)sig->data;

    lk_pushcontext(S, &ctx, NULL);
    node = list;
    while (node != NULL) {
        next = node->next;
        ctx.current = (lk_Slot*)node->svr;
        if (node->handler == NULL)
            ++removed;
        else
            lk_try(S, &ctx, node->handler(S, node->ud, sig->type, svrs));
        node = next;
    }
    lk_popcontext(S, &ctx);
    return removed;
}

static void lkX_sweepevents (lk_MonitorState *ms, lk_MonitorList *list) {
    lk_MonitorNode **pnode = &list->first;
    while (*pnode != NULL) {
        lk_MonitorNode **pnext = &(*pnode)->next;
        if ((*pnode)->handler != NULL)
            pnode = pnext;
        else {
            lk_poolfree(&ms->callbcaks, *pnode);
            *pnode = *pnext;
        }
    }
}

static void lkX_monitorevent (lk_MonitorState *ms, lk_Signal *sig) {
    lk_MonitorList list;
    int removed;
    if (sig->type >= LK_MONITOR_EVENTS) return;

    lk_lock(ms->lock);
    list = ms->cbs[sig->type];
    lkQ_init(&ms->cbs[sig->type]);
    lk_unlock(ms->lock);

    ms->current = sig->type;
    removed = lkX_triggerevent(ms->S, list.first, sig);
    ms->current = -1;

    lk_lock(ms->lock);
    lkQ_merge(&ms->cbs[sig->type], &list);
    if (removed) lkX_sweepevents(ms, &ms->cbs[sig->type]);
    lk_unlock(ms->lock);
}

LK_API void lk_addmonitor (lk_Service *svr, int event, lk_MonitorHandler *h, void *ud) {
    lk_MonitorState *ms = lkX_getstate(svr);
    lk_MonitorNode *node;
    if (event < 0 || event >= LK_MONITOR_EVENTS) return;
    lk_lock(ms->lock);
    node = (lk_MonitorNode*)lk_poolalloc(ms->S, &ms->callbcaks);
    node->svr     = lk_self(ms->S);
    node->handler = h;
    node->ud      = ud;
    lkQ_enqueue(&ms->cbs[event], node);
    lk_unlock(ms->lock);
}

LK_API void lk_delmonitor (lk_Service *svr, int event, lk_MonitorHandler *h, void *ud) {
    lk_MonitorState *ms = lkX_getstate(svr);
    lk_MonitorNode **pnode;
    if (event < 0 || event >= LK_MONITOR_EVENTS) return;
    lk_lock(ms->lock);
    pnode = &ms->cbs[event].first;
    for (; *pnode != NULL
                && (*pnode)->handler == h && (*pnode)->ud == ud;
            pnode = &(*pnode)->next)
        ;
    if (*pnode != NULL) {
        if (ms->current == event)
            (*pnode)->handler = NULL;
        else {
            lk_MonitorNode *next = (*pnode)->next;
            lk_poolfree(&ms->callbcaks, *pnode);
            *pnode = next;
        }
    }
    lk_unlock(ms->lock);
}

LKMOD_API int loki_service_monitor (lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    lk_MonitorState *ms = lkX_getstate(slot);
    if (slot == NULL) { /* init */
        ms = (lk_MonitorState*)lk_malloc(S, sizeof(lk_MonitorState));
        memset(ms, 0, sizeof(*ms));
        ms->S = S;
        ms->current = -1;
        if (lk_initlock(&ms->lock)) {
            lk_free(S, ms, sizeof(*ms));
            lk_log(S, lk_loc("[E]monitor: initialize failure"));
            return LK_ERR;
        }
        lk_initpool(&ms->callbcaks, sizeof(lk_MonitorNode));
        return LK_WEAK;
    }
    else if (sig == NULL) { /* free */
        lk_freelock(ms->lock);
        lk_freepool(S, &ms->callbcaks);
        lk_free(ms->S, ms, sizeof(*ms));
        return LK_OK;
    }
    lkX_monitorevent(ms, sig);
    return LK_OK;
}

/* win32cc: flags+='-Wextra -s -O3 -mdll' libs+='-lws2_32'
 * win32cc: input='lokilib.c service_*.c' output='loki.dll'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared' libs+='-pthread -ldl'
 * unixcc: input='lokilib.c service_*.c' output='loki.so' */

