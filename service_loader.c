#define LOKI_MODULE
#include "loki_services.h"
#include "lk_buffer.h"

#include <stdlib.h>

#ifdef __APPLE__
# include <libproc.h>
#endif

typedef lkQ_type(struct lk_LoaderNode) lk_LoaderList;

typedef struct lk_HandlerEntry {
    lk_Entry entry;
    lk_Handler *handler;
} lk_HandlerEntry;

typedef struct lk_LoaderNode {
    lkQ_entry(struct lk_LoaderNode);
    lk_LoaderHandler *loader;
    void *ud;
} lk_LoaderNode;

typedef struct lk_LoaderState {
    lk_State     *S;
    lk_Service   *monitor;
    unsigned      in_require : 1;
    lk_Table      preloads;
    lk_Table      modules;
    lk_MemPool    loader_pool;
    lk_LoaderList loader_list;
    lk_Data      *binpath;
    lk_Lock       lock;
} lk_LoaderState;

struct lk_Loader {
    lk_State     *S;
    const char   *module;
    lk_Buffer     name;
    lk_Buffer     error;
    lk_Data      *binpath;
    lk_Handler   *handler;
    void         *data;
    lk_Handler   *deletor;
    void         *deletor_ud;
};

static lk_Data *lkP_getmodulename(lk_State *S) {
#ifdef _WIN32
    char buff[MAX_PATH];
    DWORD size;
    if ((size = GetModuleFileName(GetModuleHandle(NULL), buff, MAX_PATH)) == 0)
#elif defined(__APPLE__)
    char buff[PROC_PIDPATHINFO_MAXSIZE];
    int size;
    if ((size = proc_pidpath(0, buff, sizeof(buff))) == 0)
#else
    char buff[PATH_MAX];
    ssize_t size;
    if ((size = readlink("/proc/self/exe", buff, PATH_MAX)) <= 0)
#endif
        return lk_newstring(S, ".");
    else {
        while (--size != 0 && buff[size] != '/' && buff[size] != '\\')
            ;
        return lk_newlstring(S, buff, size);
    }
}

static int lkP_readable(const char *path) {
#ifdef _WIN32
    HANDLE hFile = INVALID_HANDLE_VALUE;
    int bytes = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (bytes != 0) {
        WCHAR *wp = NULL;
        wp = (WCHAR*)malloc(sizeof(WCHAR)*bytes);
        if (wp != NULL) {
            MultiByteToWideChar(CP_UTF8, 0, path, -1, wp, bytes);
            hFile = CreateFileW(wp,        /* file to open         */
                    FILE_WRITE_ATTRIBUTES, /* open only for handle */
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL,                  /* default security     */
                    OPEN_EXISTING,         /* existing file only   */
                    FILE_FLAG_BACKUP_SEMANTICS, /* open directory also */
                    NULL);                 /* no attr. template    */
            free(wp);
            if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
            return hFile != INVALID_HANDLE_VALUE;
        }
    }
    hFile = CreateFileA(path,      /* file to open         */
            FILE_WRITE_ATTRIBUTES, /* open only for handle */
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL,                  /* default security     */
            OPEN_EXISTING,         /* existing file only   */
            FILE_FLAG_BACKUP_SEMANTICS, /* open directory also */
            NULL);                 /* no attr. template    */
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return hFile != INVALID_HANDLE_VALUE;
#else
    int fd = open(path, O_RDONLY|O_NOCTTY);
    if (fd >= 0) close(fd);
    return fd >= 0;
#endif
}


/* loader routines */

LK_API void lk_sethandler (lk_Loader *loader, lk_Handler *h, void *data)
{ loader->handler = h; loader->data = data; }

LK_API void lk_setdeletor (lk_Loader *loader, lk_Handler *h, void *data)
{ loader->deletor = h; loader->deletor_ud = data; }

LK_API int lk_loaderror (lk_Loader *loader, const char *msg, ...) {
    va_list l;
    va_start(l, msg);
    lk_addchar(&loader->error, '\t');
    lk_addvfstring(&loader->error, msg, l);
    lk_addchar(&loader->error, '\n');
    va_end(l);
    return lk_discard(loader->S);
}

LK_API int lk_loadverror (lk_Loader *loader, const char *msg, va_list l) {
    lk_addchar(&loader->error, '\t');
    lk_addvfstring(&loader->error, msg, l);
    lk_addchar(&loader->error, '\n');
    return lk_discard(loader->S);
}

LK_API lk_Data *lk_searchpath (lk_Loader *loader, const char *paths, const char *name) {
    lk_Buffer B;
    while (*paths != '\0') {
        lk_initbuffer(loader->S, &B);
        for (; *paths != '\0' && *paths != ';'; ++paths) {
            if (*paths == '!')
                lk_adddata(&B, loader->binpath);
            else if (*paths == '?')
                lk_addstring(&B, name);
            else
                lk_addchar(&B, *paths);
        }
        *lk_prepbuffsize(&B, 1) = '\0';
        if (lkP_readable(lk_buffer(&B)))
            return lk_buffresult(&B);
    }
    return NULL;
}

static void lkX_initloader (lk_State *S, lk_Loader *loader, const char *name) {
    memset(loader, 0, sizeof(*loader));
    loader->S = S;
    lk_initbuffer(S, &loader->name);
    lk_initbuffer(S, &loader->error);
    lk_addstring(&loader->name, name);
}

static void lkX_freeloader (lk_Loader *loader) {
    lk_freebuffer(&loader->name);
    lk_freebuffer(&loader->error);
}

static int lkX_callhandlers (lk_Loader *loader, lk_LoaderNode *list) {
    lk_Context ctx;
    lk_State *S = loader->S;
    lk_LoaderNode *volatile node = list;
    volatile int removed = 0;
    lk_pushcontext(S, &ctx, (lk_Slot*)lk_self(S));
    while (loader->handler == NULL && node != NULL) {
        lk_LoaderNode *next = node->next;
        if (node->loader == NULL)
            ++removed;
        else {
            int ret;
            lk_try(S, &ctx,
                    ret = node->loader(S, node->ud, loader, loader->module));
            if (ret == LK_ERR || ctx.retcode == LK_ERR)
                loader->handler = NULL;
        }
        node = next;
    }
    lk_popcontext(S, &ctx);
    if (loader->handler == NULL)
        lk_log(S, lk_loc("E[require] load service error:\n"),
                lk_buffer(&loader->error));
    return removed;
}

static void lkX_sweephandlers (lk_LoaderState *ls) {
    lk_LoaderNode **pnode = &ls->loader_list.first;
    while (*pnode != NULL) {
        lk_LoaderNode **pnext = &(*pnode)->next;
        if ((*pnode)->loader != NULL)
            pnode = pnext;
        else {
            lk_poolfree(&ls->loader_pool, *pnode);
            *pnode = *pnext;
        }
    }
}

static lk_Service *lkX_loadservice(lk_Loader *loader) {
    lk_State *S = loader->S;
    lk_Service *svr = NULL;
    if (loader->handler == NULL)
        lk_log(S, lk_loc("E[require] load service error: %s"),
                lk_buffer(&loader->error));
    else if ((svr = lk_launch(S, lk_buffer(&loader->name),
                    loader->handler, loader->data)) == NULL)
        lk_log(S, lk_loc("E[require] launch service '%s' error"),
                lk_buffer(&loader->name));
    else if (loader->deletor) { /* XXX monitor the deletion of module */
    }
    return svr;
}


/* interface */

#define lkX_getstate(svr) ((lk_LoaderState*)lk_data((lk_Slot*)svr))

LK_API void lk_preload (lk_Service *svr, const char *name, lk_Handler *h) {
    lk_LoaderState *ls = lkX_getstate(svr);
    lk_HandlerEntry *e;
    lk_lock(ls->lock);
    e = (lk_HandlerEntry*)lk_settable(ls->S, &ls->preloads, name);
    if (e->handler == NULL) {
        lk_key(e) = (char*)lk_newstring(ls->S, name);
        e->handler = h;
    }
    lk_unlock(ls->lock);
}

LK_API void lk_addloader (lk_Service *svr, lk_LoaderHandler *h, void *ud) {
    lk_LoaderState *ls = lkX_getstate(svr);
    lk_LoaderNode *node;
    lk_lock(ls->lock);
    node = (lk_LoaderNode*)lk_poolalloc(ls->S, &ls->loader_pool);
    node->loader = h;
    node->ud     = ud;
    lkQ_enqueue(&ls->loader_list, node);
    lk_unlock(ls->lock);
}

LK_API void lk_delloader (lk_Service *svr, lk_LoaderHandler *h, void *ud) {
    lk_LoaderState *ls = lkX_getstate(svr);
    lk_LoaderNode **pnode;
    lk_lock(ls->lock);
    pnode = &ls->loader_list.first;
    for (; *pnode != NULL
                && (*pnode)->loader == h && (*pnode)->ud == ud;
            pnode = &(*pnode)->next)
        ;
    if (*pnode != NULL) {
        if (ls->in_require)
            (*pnode)->loader = NULL;
        else {
            lk_LoaderNode *next = (*pnode)->next;
            lk_poolfree(&ls->loader_pool, *pnode);
            *pnode = next;
        }
    }
    lk_unlock(ls->lock);
}

LK_API lk_Service *lk_require (lk_Service *svr, const char *name) {
    lk_LoaderState *ls = lkX_getstate(svr);
    lk_LoaderList list;
    lk_Service *loaded;
    lk_Loader loader;
    int removed;

    lkX_initloader(ls->S, &loader, name);
    list = ls->loader_list;
    lkQ_init(&ls->loader_list);
    lk_unlock(ls->lock);

    ls->in_require = 1;
    removed = lkX_callhandlers(&loader, list.first);
    ls->in_require = 0;

    lk_lock(ls->lock);
    lkQ_merge(&ls->loader_list, &list);
    if (removed) lkX_sweephandlers(ls);
    lk_unlock(ls->lock);

    loaded = lkX_loadservice(&loader);
    lkX_freeloader(&loader);
    return loaded;
}

LKMOD_API int loki_service_loader (lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    if (slot == NULL) { /* init */
        lk_LoaderState *ls = (lk_LoaderState*)lk_malloc(S, sizeof(lk_LoaderState));
        memset(ls, 0, sizeof(*ls));
        ls->S = S;
        (void)lk_initlock(&ls->lock);
        lk_inittable(&ls->preloads, sizeof(lk_HandlerEntry));
        lk_initpool(&ls->loader_pool, sizeof(lk_LoaderNode));
        lkQ_init(&ls->loader_list);
        ls->binpath = lkP_getmodulename(S);
        lk_setdata(lk_current(S), ls);
    }
    else if (sig == NULL) { /* free */
        lk_LoaderState *ls = lkX_getstate((lk_Service*)slot);
        lk_free(S, ls, sizeof(*ls));
        lk_freelock(ls->lock);
        lk_freetable(S, &ls->preloads);
        lk_freepool(S, &ls->loader_pool);
        lk_deldata(S, ls->binpath);
    }
    return LK_WEAK;
}

/* win32cc: flags+='-s -mdll -xc' output='loki.dll' libs+='-lws2_32'
 * unixcc: flags+='-fPIC -shared -xc' output='loki.so'
 * cc: flags+='-Wextra -O3' input='service_*.c lokilib.c' */

