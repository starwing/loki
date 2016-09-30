#define LOKI_MODULE
#include "loki_services.h"

#include <assert.h>


typedef struct lk_ListenerState lk_ListenerState;
typedef struct lk_Listener      lk_Listener;
typedef struct lk_SlotEntry     lk_SlotEntry;

struct lk_ListenerState {
    lk_State         *S;
    lk_Listener      *freed;
    lk_Lock           lock;
    lk_Table          svrmap;
    lk_Table          slotmap;
    lk_MemPool        listeners;
};

struct lk_Listener {
    lk_Source         source;
    lk_SlotEntry     *entry;
    lk_Listener      *link;
    lk_Listener      *next;
    lk_Listener      *prev;
};

struct lk_SlotEntry {
    lk_Entry          base;
    lk_ListenerState *ls;
    lk_Slot          *target;
    lk_Listener      *listeners;
    unsigned          broadcast;
};


#define lkX_svrstate(svr) ((lk_ListenerState*)lk_data((lk_Slot*)(svr)))
#define lkX_state(S)      ((lk_ListenerState*)lk_userdata(S))

static void lkX_link (lk_Listener **pp, lk_Listener *node) {
    if (*pp == NULL)
        *pp = node->prev = node->next = node;
    else {
        lk_Listener *h = *pp;
        node->prev = h->prev;
        node->next = h;
        h->prev->next = node;
        h->prev = node;
    }
}

static void lkX_unlink (lk_Listener **pp, lk_Listener *node) {
    if (*pp == node) *pp = node == node->next ? NULL : node->next;
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

static unsigned lkX_ptrhash (unsigned p) {
    p = (p+0x7ed55d16) + (p<<12);
    p = (p^0xc761c23c) ^ (p>>19);
    p = (p+0x165667b1) + (p<<5);
    p = (p+0xd3a2646c) ^ (p<<9);
    p = (p+0xfd7046c5) + (p<<3);
    p = (p^0xb55a4f09) ^ (p>>16);
    return p;
}

static lk_Entry *lkX_gettable (lk_Table *t, void *key) {
    unsigned hash;
    lk_Entry *e;
    if (t->size == 0 || key == NULL) return NULL;
    hash = lkX_ptrhash((unsigned)(ptrdiff_t)key);
    e = (lk_Entry*)((char*)t->hash + ((hash & (t->size - 1))*t->entry_size));
    for (;;) {
        if (e->key && (e->hash == hash && strcmp(e->key, key) == 0))
            return e;
        if (e->next == 0) return NULL;
        e = (lk_Entry*)((char*)e + e->next);
    }
    return e;
}

static lk_Entry *lkX_settable (lk_State *S, lk_Table *t, void *key) {
    lk_Entry e, *ret;
    if (key == NULL) return NULL;
    if ((ret = lkX_gettable(t, key)) != NULL)
        return ret;
    e.key  = key;
    e.hash = lkX_ptrhash((unsigned)(ptrdiff_t)key);
    return lk_newkey(S, t, &e);
}

static lk_Listener *lkX_merge (lk_Listener *oldh, lk_Listener *newh) {
    lk_Listener *last = newh->prev;
    oldh->prev->next = last->next;
    last->next->prev = oldh->prev;
    oldh->prev = last;
    last->prev = oldh;
    return oldh;
}

static int lkX_next (lk_Listener *h, lk_Listener **pnode, lk_Listener **pnext) {
    if (h == NULL) return 0;
    if (*pnode != NULL) {
        lk_Listener *next = pnext ? *pnext : (*pnode)->next;
        if (next != h) {
            if (pnext) *pnext = next;
            *pnode = next;
            return 1;
        }
        *pnode = NULL;
        return 0;
    }
    *pnode = h;
    if (pnext) *pnext = h->next;
    return 1;
}

static int lkX_srcdeletor (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_Listener *node = (lk_Listener*)sig->source;
    lk_SlotEntry *list = node->entry;
    lk_ListenerState *ls = list->ls;
    (void)S, (void)sender;
    lk_lock(ls->lock);
    if (list->broadcast) {
        node->source.callback = NULL;
        node->link = ls->freed;
        ls->freed = node->link;
    }
    else {
        lkX_unlink(&list->listeners, node);
        lk_poolfree(&list->ls->listeners, node);
        if (list->listeners == NULL) {
            lk_Entry *e = lkX_gettable(&ls->slotmap, list->target);
            e->key = NULL;
            lk_sethook(list->target, NULL, NULL);
        }
    }
    lk_unlock(ls->lock);
    return LK_OK;
}

static lk_Listener *lkX_newlistener (lk_ListenerState *ls, lk_Handler *h, void *ud) {
    lk_Listener *node;
    lk_lock(ls->lock);
    node = (lk_Listener*)lk_poolalloc(ls->S, &ls->listeners);
    lk_unlock(ls->lock);
    lk_initsource(ls->S, &node->source, h, ud);
    node->source.deletor = lkX_srcdeletor;
    node->source.refcount = 1;
    node->source.force = 1;
    return node;
}

static int lkX_broadcast (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_Source *src = sig->source;
    lk_SlotEntry *list = (lk_SlotEntry*)lk_userdata(S);
    lk_ListenerState *ls = list->ls;
    lk_Listener *h, *node = NULL;
    (void)sender;
    lk_lock(ls->lock);
    h = list->listeners;
    list->listeners = NULL;
    list->broadcast = 1;
    lk_unlock(ls->lock);
    while (lkX_next(h, &node, NULL)) {
        if (node->source.callback != NULL) {
            sig->source = &node->source;
            lk_emit((lk_Slot*)node->source.service, sig);
        }
    }
    lk_lock(ls->lock);
    list->broadcast = 0;
    list->listeners = list->listeners ? lkX_merge(h, list->listeners) : h;
    node = ls->freed;
    ls->freed = NULL;
    lk_unlock(ls->lock);
    while (node) {
        lk_Listener *next = node->link;
        lk_freesource(&node->source);
        node = next;
    }
    sig->source = src;
    return LK_OK;
}

static int lkX_addlistener (lk_ListenerState *ls, lk_Slot *slot, lk_Handler *h, void *ud) {
    lk_Listener *node;
    lk_PtrEntry *e = (lk_PtrEntry*)
        lkX_gettable(&ls->svrmap, lk_service(slot));
    lk_SlotEntry *list;
    if (e == NULL) return LK_ERR;
    list = (lk_SlotEntry*)lkX_settable(ls->S, &ls->slotmap, slot);
    if (list->ls == NULL) {
        list->ls     = ls;
        list->target = slot;
        lk_sethook(slot, lkX_broadcast, list);
    }
    node = lkX_newlistener(ls, h, ud);
    node->entry = list;
    node->link = (lk_Listener*)e->data;
    e->data = node;
    lkX_link(&list->listeners, node);
    return LK_OK;
}

static lk_Listener *lkX_dellistener (lk_ListenerState *ls, lk_Slot *slot, lk_Handler *h, void *ud) {
    lk_Listener **pp, *node = NULL;
    lk_PtrEntry *e = (lk_PtrEntry*)lkX_gettable(&ls->slotmap, slot);
    for (pp = (lk_Listener**)&e->data; *pp != NULL; pp = &(*pp)->link)
        if ((*pp)->source.callback == h && (*pp)->source.ud == ud)
            break;
    if (*pp != NULL) {
        node = *pp;
        *pp = (*pp)->link;
    }
    return node;
}

LK_API int lk_addlistener (lk_Service *svr, lk_Slot *slot, lk_Handler *h, void *ud) {
    lk_ListenerState *ls = lkX_svrstate(svr);
    int ret;
    lk_lock(ls->lock);
    ret = lkX_addlistener(ls, slot, h, ud);
    lk_unlock(ls->lock);
    return ret;
}

LK_API int lk_dellistener (lk_Service *svr, lk_Slot *slot, lk_Handler *h, void *ud) {
    lk_ListenerState *ls = lkX_svrstate(svr);
    lk_Listener *node;
    lk_lock(ls->lock);
    node = lkX_dellistener(ls, slot, h, ud);
    lk_unlock(ls->lock);
    if (node != NULL) {
        lk_freesource(&node->source);
        return LK_OK;
    }
    return LK_ERR;
}

static int lkX_launch (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_ListenerState *ls = (lk_ListenerState*)lk_userdata(S);
    lk_Service *svr = (lk_Service*)sig->data;
    lk_PtrEntry *e;
    (void)sender;
    lk_lock(ls->lock);
    e = (lk_PtrEntry*)lkX_settable(S, &ls->svrmap, svr);
    if (lk_key(e) == NULL) {
        lk_key(e) = (const char*)svr;
        e->data = NULL;
    }
    lk_unlock(ls->lock);
    return LK_OK;
}

static int lkX_close (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_ListenerState *ls = lkX_state(S);
    lk_Service *svr = (lk_Service*)sig->data;
    lk_PtrEntry *e;
    lk_Listener *node;
    (void)sender;
    lk_lock(ls->lock);
    e = (lk_PtrEntry*)lkX_gettable(&ls->svrmap, svr);
    if (e && lk_key(e) == (const char*)svr) {
        node = (lk_Listener*)e->data;
        while (node != NULL) {
            lk_Listener *next = node->link;
            node->link = ls->freed;
            ls->freed = node;
            node = next;
        }
        lk_key(e) = NULL;
        e->data = NULL;
    }
    node = ls->freed;
    ls->freed = NULL;
    lk_unlock(ls->lock);
    while (node) {
        lk_Listener *next = node->link;
        lk_freesource(&node->source);
        node = next;
    }
    return LK_OK;
}

LKMOD_API int loki_service_listener (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    if (sender == NULL) { /* init */
        lk_ListenerState *ls = (lk_ListenerState*)
            lk_malloc(S, sizeof(lk_ListenerState));
        memset(ls, 0, sizeof(*ls));
        ls->S = S;
        if (!lk_initlock(&ls->lock)) return LK_ERR;
        lk_initpool(&ls->listeners, sizeof(lk_Listener));
        lk_inittable(&ls->svrmap, sizeof(lk_PtrEntry));
        lk_inittable(&ls->slotmap, sizeof(lk_SlotEntry));
        lk_newslot(S, LK_SLOTNAME_LAUNCH, lkX_launch, ls);
        lk_newslot(S, LK_SLOTNAME_CLOSE, lkX_close, ls);
        lkX_settable(S, &ls->svrmap, S);
        lk_setdata(lk_current(S), ls);
        return LK_WEAK;
    }
    else if (sig == NULL) { /* free */
        lk_ListenerState *ls = lkX_state(S);
        lk_freelock(ls->lock);
        lk_freepool(S, &ls->listeners);
        lk_freetable(S, &ls->svrmap);
        lk_freetable(S, &ls->slotmap);
        lk_free(S, ls, sizeof(*ls));
    }
    return LK_OK;
}

/* win32cc: flags+='-s -mdll -xc' output='loki.dll' libs+='-lws2_32'
 * unixcc: flags+='-fPIC -shared -xc' output='loki.so'
 * cc: flags+='-Wextra -O3' input+='lokilib.c' */

