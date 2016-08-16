#ifndef lk_notify_h
#define lk_notify_h


#include "loki.h"

LK_NS_BEGIN


typedef struct lk_Notifier lk_Notifier;

typedef int lk_Notify       (lk_State *S, void *ud, void *data);
typedef int lk_NotifyFilter (lk_State *S, void *ud,
                             lk_Notify *h, void *hud, void *data);

LK_API void lk_initnotifier (lk_State *S, lk_Notifier *n);
LK_API void lk_freenotifier (lk_Notifier *n);
LK_API void lk_setfilter    (lk_Notifier *n, lk_NotifyFilter *h, void *ud);
LK_API void lk_addnotify    (lk_Notifier *n, lk_Notify *h, void *ud);
LK_API void lk_delnotify    (lk_Notifier *n, lk_Notify *h, void *ud);

LK_API void lk_notify (lk_Notifier *n, void *data);

typedef lkQ_type(struct lk_NotifyNode) lk_NotifyList;

typedef struct lk_NotifyNode {
    lkQ_entry(struct lk_NotifyNode);
    lk_Notify *handler;
    void      *ud;
} lk_NotifyNode;

struct lk_Notifier {
    lk_NotifyList    queue;
    lk_State        *S;
    lk_NotifyFilter *filter;
    void            *ud;
    lk_MemPool       pool;
    lk_Lock          lock;
    unsigned         in_notify   : 1;
};


LK_NS_END

#endif /* lk_notify_h */


#if defined(LOKI_IMPLEMENTATION) && !defined(lk_notify_implemented)
#define lk_notify_implemented

LK_NS_BEGIN


LK_API void lk_initnotifier (lk_State *S, lk_Notifier *n) {
    memset(n, 0, sizeof(*n));
    if (lk_initlock(&n->lock))
        return;
    n->S = S;
    lk_initpool(&n->pool, sizeof(lk_NotifyNode));
    lkQ_init(&n->queue);
}

LK_API void lk_freenotifier (lk_Notifier *n) {
    lk_freelock(n->lock);
    lk_freepool(n->S, &n->pool);
}

LK_API void lk_setfilter (lk_Notifier *n, lk_NotifyFilter *h, void *ud) {
    lk_lock(n->lock);
    n->filter = h;
    n->ud     = ud;
    lk_unlock(n->lock);
}

LK_API void lk_addnotify (lk_Notifier *n, lk_Notify *h, void *ud) {
    lk_NotifyNode *node;
    lk_lock(n->lock);
    node = (lk_NotifyNode*)lk_poolalloc(n->S, &n->pool);
    node->handler = h;
    node->ud      = ud;
    lkQ_enqueue(&n->queue, node);
    lk_unlock(n->lock);
}

LK_API void lk_delnotify (lk_Notifier *n, lk_Notify *h, void *ud) {
    lk_NotifyNode **pnode;
    assert(n != NULL);
    lk_lock(n->lock);
    pnode = &n->queue.first;
    for (; *pnode != NULL
                && (*pnode)->handler == h && (*pnode)->ud == ud;
            pnode = &(*pnode)->next)
        ;
    if (*pnode != NULL) {
        if (n->in_notify)
            (*pnode)->handler = NULL;
        else {
            lk_NotifyNode *next = (*pnode)->next;
            lk_poolfree(&n->pool, *pnode);
            *pnode = next;
        }
    }
    lk_unlock(n->lock);
}

static int lkN_notify(lk_Notifier *n, lk_Context *ctx, lk_NotifyNode *node, void *data) {
    int ret = LK_OK;
    lk_try(n->S, ctx, ret = n->filter != NULL ?
            n->filter(n->S, n->ud, node->handler, node->ud, data) :
            node->handler(n->S, node->ud, data));
    return ctx->retcode != LK_OK ? 0 : ret;
}

static int lkN_callhandlers(lk_Notifier *n, lk_NotifyNode *list, void *data) {
    lk_Context ctx;
    lk_NotifyNode *node = list, *next;
    int removed = 0;
    lk_pushcontext(n->S, &ctx, (lk_Slot*)lk_self(n->S));
    for (; node != NULL; node = next) {
        next = node->next;
        if (node->handler == NULL)
            ++removed;
        else {
            int ret = lkN_notify(n, &ctx, node, data);
            if (ret <  0) break;
            if (ret != 0) continue;
            if (n->filter != NULL) node->handler = NULL;
        }
    }
    lk_popcontext(n->S, &ctx);
    return removed;
}

static void lkN_sweephandlers (lk_Notifier *n) {
    lk_NotifyNode **pnode = &n->queue.first;
    while (*pnode != NULL) {
        lk_NotifyNode **pnext = &(*pnode)->next;
        if ((*pnode)->handler != NULL)
            pnode = pnext;
        else {
            lk_poolfree(&n->pool, *pnode);
            *pnode = *pnext;
        }
    }
}

LK_API void lk_notify (lk_Notifier *n, void *data) {
    lk_NotifyList list;
    int removed;

    lk_lock(n->lock);
    assert(!n->in_notify);
    list = n->queue;
    lkQ_init(&n->queue);
    lk_unlock(n->lock);

    n->in_notify = 1;
    removed = lkN_callhandlers(n, list.first, data);
    n->in_notify = 0;

    lk_lock(n->lock);
    lkQ_merge(&n->queue, &list);
    if (removed) lkN_sweephandlers(n);
    lk_unlock(n->lock);
}


LK_NS_END

#endif /* LOKI_IMPLEMENTATION */

/* win32cc: flags+='-Wextra -s -O3 -mdll -DLOKI_IMPLEMENTATION -std=c90 -pedantic -xc'
 * win32cc: output='loki.dll'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared -DLOKI_IMPLEMENTATION -xc'
 * unixcc: output='loki.so' */

