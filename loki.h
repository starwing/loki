#ifndef loki_h
#define loki_h


#ifndef LK_NS_BEGIN
# ifdef __cplusplus
#   define LK_NS_BEGIN extern "C" {
#   define LK_NS_END   }
# else
#   define LK_NS_BEGIN
#   define LK_NS_END
# endif
#endif /* LK_NS_BEGIN */

#ifdef LK_STATIC_API
# ifndef LOKI_IMPLEMENTATION
#  define LOKI_IMPLEMENTATION
# endif
# if __GNUC__
#   define LK_API static __attribute((unused))
# else
#   define LK_API static
# endif
#endif

#if !defined(LK_API) && defined(_WIN32)
# if defined(LOKI_IMPLEMENTATION) || defined(LOKI_MODULE)
#   define LK_API __declspec(dllexport)
# else
#   define LK_API __declspec(dllimport)
# endif
#endif

#ifndef LK_API
# define LK_API extern
#endif

#ifndef LKMOD_API
# define LKMOD_API LK_API
#endif

#define LK_OK      (0)
#define LK_WEAK    (1)
#define LK_ERR     (-1)
#define LK_TIMEOUT (-2)


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>


LK_NS_BEGIN

typedef struct lk_State   lk_State;
typedef struct lk_Service lk_Service;
typedef struct lk_Slot    lk_Slot;

typedef struct lk_Signal {
    lk_Service *src;
    void *data;
    unsigned free : 1;
    unsigned type : 7;
    unsigned size : 24;
    unsigned session;
} lk_Signal;

typedef int lk_ServiceHandler (lk_State *S);
typedef int lk_SignalHandler  (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig);
typedef int lk_Handler        (lk_State *S, void *ud);


/* global routines */

LK_API lk_State *lk_newstate (const char *name);

LK_API void lk_waitclose (lk_State *S);

LK_API void lk_setthreads (lk_State *S, int threads);
LK_API void lk_setpath    (lk_State *S, const char *path);

LK_API int lk_start (lk_State *S);

LK_API int lk_pcall   (lk_State *S, lk_Handler *h, void *ud);
LK_API int lk_discard (lk_State *S);

LK_API int lk_addcleanup (lk_State *S, lk_Handler *h, void *ud);

LK_API char *lk_getconfig (lk_State *S, const char *key);
LK_API void  lk_setconfig (lk_State *S, const char *key, const char *value);

LK_API void lk_log(lk_State *S, const char *fmt, ...);
LK_API void lk_vlog(lk_State *S, const char *fmt, va_list l);

#define lk_str_(str) # str
#define lk_str(str) lk_str_(str)
#define lk_loc(str) __FILE__ ":" lk_str(__LINE__) ": " str


/* service routines */

LK_API lk_Service *lk_self (lk_State *S);

LK_API void lk_close (lk_State *S);

LK_API void lk_preload (lk_State *S, const char *name, lk_ServiceHandler *h);

LK_API lk_Service *lk_require  (lk_State *S, const char *name);
LK_API lk_Service *lk_requiref (lk_State *S, const char *name, lk_ServiceHandler *h);

LK_API void *lk_data    (lk_Service *svr);
LK_API void  lk_setdata (lk_State *S, void *data);

LK_API lk_SignalHandler *lk_refactor (lk_Service *svr, void **pud);
LK_API void  lk_setrefactor (lk_State *S, lk_SignalHandler *h, void *ud);


/* message routines */

#define LK_SIGNAL { NULL, NULL, 0, 0, 0, 0 }

LK_API lk_Slot *lk_newslot (lk_State *S, const char *name, lk_SignalHandler *h, void *ud);
LK_API lk_Slot *lk_slot    (lk_State *S, const char *name);

LK_API int lk_emit       (lk_Slot *slot, const lk_Signal *sig);
LK_API int lk_emitdata   (lk_Slot *slot, unsigned type, unsigned session, const void *data, size_t size);
LK_API int lk_emitstring (lk_Slot *slot, unsigned type, unsigned session, const char *s);

LK_API lk_Slot *lk_newpoll (lk_State *S, const char *name, lk_SignalHandler *h, void *ud);
LK_API int      lk_wait    (lk_Slot *slot, lk_Signal *sig, int waitms);

LK_API const char *lk_name    (lk_Slot *slot);
LK_API lk_Service *lk_service (lk_Slot *slot);
LK_API lk_State   *lk_state   (lk_Slot *slot);

LK_API lk_SignalHandler *lk_slothandler (lk_Slot *slot, void **pud);
LK_API void lk_setslothandler (lk_Slot *slot, lk_SignalHandler *h, void *ud);


LK_NS_END

#endif /* loki_h */

/****************************************************************************/

#ifndef lk_utils_h
#define lk_utils_h

LK_NS_BEGIN


/* memory management */

LK_API void *lk_malloc  (lk_State *S, size_t size);
LK_API void *lk_realloc (lk_State *S, void *ptr, size_t size);
LK_API void  lk_free    (lk_State *S, void *ptr);

LK_API char *lk_strdup  (lk_State *S, const char *s);
LK_API char *lk_memdup  (lk_State *S, const void *buff, size_t size);
LK_API char *lk_strncpy (char *dst, size_t n, const char *s);


/* memory pool routines */

#define LK_MPOOLPAGESIZE 4096

typedef struct lk_MemPool {
    void *pages;
    void *freed;
    lk_State *S;
    size_t size;
    size_t align;
} lk_MemPool;

LK_API void  lk_initmempool (lk_State *S, lk_MemPool *mpool, size_t size, size_t align);
LK_API void  lk_freemempool (lk_MemPool *mpool);
LK_API void *lk_poolalloc   (lk_MemPool *mpool);
LK_API void  lk_poolfree    (lk_MemPool *mpool, void *obj);


/* buffer routines */

#define LK_BUFFERSIZE 1024

typedef struct lk_Buffer {
    size_t size;
    size_t capacity;
    lk_State *S;
    char *buff;
    char init_buff[LK_BUFFERSIZE];
} lk_Buffer;

#define lk_buffer(B)      ((B)->buff)
#define lk_buffsize(B)    ((B)->size)
#define lk_resetbuffer(B) ((B)->size = 0)
#define lk_addsize(B,sz)  ((B)->size += (sz))
#define lk_addchar(B,ch)  (*lk_prepbuffsize((B), 1) = (ch), ++(B)->size)
#define lk_addstring(B,s) lk_addlstring((B),(s),strlen(s))

LK_API void lk_initbuffer (lk_State *S, lk_Buffer *b);
LK_API void lk_freebuffer (lk_Buffer *b);

LK_API char *lk_prepbuffsize (lk_Buffer *B, size_t len);

LK_API int lk_addlstring  (lk_Buffer *B, const char *s, size_t len);
LK_API int lk_addvfstring (lk_Buffer *B, const char *fmt, va_list l);
LK_API int lk_addfstring  (lk_Buffer *B, const char *fmt, ...);

LK_API void lk_replacebuffer (lk_Buffer *B, char origch, char newch);

LK_API const char *lk_buffresult (lk_Buffer *B);


/* table routines */

typedef struct lk_Entry {
    int next;
    unsigned hash;
    const char *key;
    void *value;
} lk_Entry;

typedef struct lk_Table {
    size_t   size;
    size_t   lastfree;
    lk_State *S;
    lk_Entry *hash;
}lk_Table;

LK_API void lk_inittable (lk_State *S, lk_Table *t);
LK_API void lk_freetable (lk_Table *t, int freekey);

LK_API size_t lk_resizetable (lk_Table *t, size_t len);

LK_API lk_Entry *lk_getentry (lk_Table *t, const char *key);
LK_API lk_Entry *lk_setentry (lk_Table *t, const char *key);
LK_API void      lk_delentry (lk_Table *t, lk_Entry *e, int freekey);

LK_API int lk_nextentry (lk_Table *t, lk_Entry **pentry);


LK_NS_END

#endif /* lk_pool_h */

/****************************************************************************/

#ifndef lk_thread_h
#define lk_thread_h

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
# include <Windows.h>

typedef HMODULE           lk_Module;
typedef DWORD             lk_TlsKey;
typedef CRITICAL_SECTION  lk_Lock;
typedef HANDLE            lk_Event;
typedef HANDLE            lk_Thread;

#define lk_loadlib(name)  LoadLibraryA(name)
#define lk_freelib(mod)   FreeLibrary(mod)
#define lk_getaddr(mod, name) GetProcAddress(mod, name)

#define lk_inittls(key)   ((*(key) = TlsAlloc()) != TLS_OUT_OF_INDEXES)
#define lk_freetls(key)   TlsFree(key)
#define lk_gettls(key)    TlsGetValue(key)
#define lk_settls(key, p) TlsSetValue((key),(p))

#define lk_initlock(lock) (InitializeCriticalSection(lock), 1)
#define lk_freelock(lock) DeleteCriticalSection(&(lock))
#define lk_trylock(lock)  TryEnterCriticalSection(&(lock))
#define lk_lock(lock)     EnterCriticalSection(&(lock))
#define lk_unlock(lock)   LeaveCriticalSection(&(lock))

#define lk_initevent(evt) \
    ((*(evt)=CreateEvent(NULL,FALSE,FALSE,NULL))!=NULL)
#define lk_freeevent(evt) CloseHandle(evt)
#define lk_signal(evt)    SetEvent(evt)

#define lk_initthread(t,f,ud) \
    ((*(t)=CreateThread(NULL,0,(f),(ud),0,NULL))!=NULL)
#define lk_waitthread(t)  \
    (WaitForSingleObject((t), INFINITE),(void)CloseHandle(t))
#define lk_freethread(t)  CloseHandle(t)

#else /* POSIX systems */

#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/time.h>

typedef void             *lk_Module;
typedef pthread_key_t     lk_TlsKey;
typedef pthread_mutex_t   lk_Lock;
typedef pthread_cond_t    lk_Event;
typedef pthread_t         lk_Thread;

#define lk_loadlib(name)  dlopen((name), RTLD_NOW|RTLD_GLOBAL)
#define lk_freelib(mod)   dlclose(mod)
#define lk_getaddr(mod, name) dlsym(mod, name)

#define lk_inittls(key)   (pthread_key_create((key), NULL) == 0)
#define lk_freetls(key)   pthread_key_delete(key)
#define lk_gettls(key)    pthread_getspecific(key)
#define lk_settls(key, p) pthread_setspecific((key), (p))

#define lk_initlock(lock) (pthread_mutex_init(lock, NULL) == 0)
#define lk_freelock(lock) pthread_mutex_destroy(&(lock))
#define lk_trylock(lock)  pthread_mutex_trylock(&(lock))
#define lk_lock(lock)     pthread_mutex_lock(&(lock))
#define lk_unlock(lock)   pthread_mutex_unlock(&(lock))

#define lk_initevent(evt) (pthread_cond_init((evt), NULL) == 0)
#define lk_freeevent(evt) pthread_cond_destroy(&(evt))
#define lk_signal(evt)    pthread_cond_signal(&(evt))

#define lk_initthread(t,f,ud) (pthread_create((t),NULL,(f),(ud)) == 0)
#define lk_waitthread(t)  pthread_join((t),NULL)
#define lk_freethread(t)  pthread_cancel(t)

#endif

#endif /* lk_thread_h */

/****************************************************************************/

#ifndef lk_queue_h
#define lk_queue_h

#define lkL_entry(T) T *next; T **pprev

#define lkL_init(n)                    do { \
    (n)->pprev = &(n)->next;                \
    (n)->next = NULL;                     } while (0)

#define lkL_insert(h, n)               do { \
    (n)->pprev = (h);                       \
    (n)->next = *(h);                       \
    if (*(h) != NULL)                       \
        (*(h))->pprev = &(n)->next;         \
    *(h) = (n);                           } while (0)

#define lkL_remove(n)                  do { \
    if ((n)->next != NULL)                  \
        (n)->next->pprev = (n)->pprev;      \
    *(n)->pprev = (n)->next;              } while (0)

#define lkL_apply(h, type, stmt)       do { \
    type *cur = (type*)(h);                 \
    (h) = NULL;                             \
    while (cur)      {                      \
        type *next_ = cur->next;            \
        stmt;                               \
        cur = next_; }                    } while (0)

#define lkQ_entry(T) T *next
#define lkQ_type(T)  struct { T *first; T *last; }

#define lkQ_init(h)  ((h)->first = (h)->last = NULL)
#define lkQ_empty(h) ((h)->first == NULL)

#define lkQ_clear(h, n)                do { \
    (n) = (h)->first;                       \
    (h)->first = (h)->last = NULL;        } while (0)

#define lkQ_enqueue(h, n)              do { \
    (n)->next = NULL;                       \
    if (lkQ_empty(h))                       \
        (h)->first = (h)->last = (n);       \
    else {                                  \
        (h)->last->next = n;                \
        (h)->last = n; }                  } while (0)

#define lkQ_dequeue(h, n)              do { \
    (n) = (h)->first;                       \
    if ((n) == (h)->last)                   \
        (h)->first = (h)->last = NULL;      \
    else if ((h)->first != NULL)            \
        (h)->first = (h)->first->next;    } while (0)

#define lkQ_merge(h, n)                do { \
    if (lkQ_empty(h)) {                     \
        (h)->first = (h)->last = (n);       \
        if ((n) != NULL) (n) = (n)->next; } \
    while ((n) != NULL) {                   \
        (h)->last = (n);                    \
        (n) = (n)->next; }                } while (0)

#define lkQ_apply(h, type, stmt)       do { \
    type *cur = (type*)(h)->first;          \
    while (cur != NULL) {                   \
        type *next_ = cur->next;            \
        stmt;                               \
        cur = next_;    }                 } while (0)

#endif /* lk_queue_h */

/****************************************************************************/

#ifndef lk_context_h
#define lk_context_h

# if defined(__cplusplus) && !defined(LK_USE_LONGJMP)
#   define lk_throw(S,c) throw(c)
#   define lk_try(S,c,a) do { try { a; } catch(...) \
              { if ((c)->status == 0) (c)->status = LK_ERR; } } while (0)
#   define lk_JmpBuf     int  /* dummy variable */

# elif _WIN32 /* ISO C handling with long jumps */
#   define lk_throw(S,c) longjmp((c)->b, 1)
#   define lk_try(S,c,a) do { if (setjmp((c)->b) == 0) { a; } } while (0)
#   define lk_JmpBuf     jmp_buf

# else /* in POSIX, try _longjmp/_setjmp (more efficient) */
#   define lk_throw(L,c) _longjmp((c)->b, 1)
#   define lk_try(L,c,a) do { if (_setjmp((c)->b) == 0) { a; } } while (0)
#   define lk_JmpBuf     jmp_buf
# endif

LK_NS_BEGIN

typedef struct lk_Cleanup {
    lkQ_entry(struct lk_Cleanup);
    lk_Handler *h;
    void *ud;
} lk_Cleanup;

typedef struct lk_Context {
    struct lk_Context *prev;
    lk_State *S;
    lk_Service *current;
    lk_Cleanup *cleanups;
    lk_JmpBuf b;
    volatile int status; /* error code */
} lk_Context;

LK_API lk_Context *lk_context (lk_State *S);
LK_API void lk_pushcontext (lk_State *S, lk_Context *ctx, lk_Service *svr);
LK_API void lk_popcontext (lk_State *S, lk_Context *ctx);

LK_NS_END

#endif /* lk_context_h */

/****************************************************************************/

#if defined(LOKI_IMPLEMENTATION) && !defined(lk_implemented)
#define lk_implemented


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef LK_NAME
# define LK_NAME "root"
#endif /* LK_PREFIX */

#ifndef LK_PREFIX
# define LK_PREFIX "loki_service_"
#endif /* LK_PREFIX */

#ifndef LK_PATH
# ifdef _WIN32
#   define LK_PATH "!\\services\\?.dll;" "!\\..\\services\\?.dll;" "!\\?.dll;" \
                   ".\\services\\?.dll;" "..\\services\\?.dll;" ".\\?.dll"
# else
#   define LK_PATH "services/?.so;" "../services/?.so;" "./?.so"
# endif
#endif /* LK_PATH */

#define LK_MAX_THREADS    32
#define LK_MAX_NAMESIZE   32
#define LK_MAX_SLOTNAME   63
#define LK_HASHLIMIT      5
#define LK_MIN_HASHSIZE   8
#define LK_MAX_SIZET      (~(size_t)0 - 100)

#define LK_INITIALING 0
#define LK_WORKING    1
#define LK_SLEEPING   2
#define LK_STOPPING   3
#define LK_ZOMBIE     4 /* service stopping but has signal unprocessed */

LK_NS_BEGIN


/* structures */

typedef struct lk_Poll lk_Poll;

typedef struct lk_SignalNode {
    lkQ_entry(struct lk_SignalNode);
    lk_Slot    *slot;
    lk_Signal   data;
} lk_SignalNode;

struct lk_Slot {
    char name[LK_MAX_SLOTNAME];
    unsigned ispoll : 1;
    lk_State   *S;
    lk_Service *service;
    lk_SignalHandler *handler; void *ud;
    lk_Slot    *next; /* all slots in same service */
};

struct lk_Poll {
    lk_Slot   slot;
    lk_Thread thread;
    lk_Event  event;
    lk_Lock   lock;
    lkQ_type(lk_SignalNode) signals;
    volatile unsigned status;
};

struct lk_Service {
    lk_Slot slot;
    lkQ_entry(lk_Service);
    volatile unsigned status;
    unsigned pending : 31; /* pending signals in queue */
    unsigned weak    : 1;
    lkQ_type(lk_SignalNode) signals;
    lk_Slot *slots;
    lk_Slot *polls;
    void    *data;
    lk_SignalHandler *refactor; void *ud;
    lk_Module module;
    lk_Event *event;
    lk_Lock   lock;
};

struct lk_State {
    lk_Service root;
    volatile  unsigned status;
    unsigned  nthreads : 16;
    unsigned  nservices : 16;
    lk_Table  preload;
    lk_Table  slots;
    lk_Table  config;
    lk_Buffer path;
    lk_Slot  *logger;
    lk_Slot  *monitor;
    lk_MemPool cleanups;
    lk_MemPool signals;
    lkQ_type(lk_Service) active_services;
    lk_TlsKey tls_index;
    lk_Lock   lock;
    lk_Event  event;
    lk_Thread threads[LK_MAX_THREADS];
#ifdef LK_DEBUG_MEM
    lk_Lock   memlock;
    unsigned  totalmem;
#endif
};


/* memory management */

static int lkM_outofmemory (lk_State *S) {
    (void)S;
    fprintf(stderr, "out of memory\n");
    abort();
    return LK_ERR;
}

LK_API void *lk_malloc (lk_State *S, size_t size) {
#ifdef LK_DEBUG_MEM
    void *ptr = malloc(size + 8);
    if (ptr == NULL) lkM_outofmemory(S);
    *(size_t*)ptr = size;
    lk_lock(S->memlock);
    S->totalmem += size;
    lk_unlock(S->memlock);
    return (char*)ptr + 8;
#else
    void *ptr = malloc(size);
    if (ptr == NULL) lkM_outofmemory(S);
    return ptr;
#endif
}

LK_API void *lk_realloc (lk_State *S, void *ptr, size_t size) {
#ifdef LK_DEBUG_MEM
    size_t oldsize = 0;
    void *newptr = realloc(ptr == NULL ? NULL : (char*)ptr-8, size + 8);
    if (newptr == NULL) lkM_outofmemory(S);
    if (ptr) oldsize = *(size_t*)newptr;
    *(size_t*)newptr = size;
    lk_lock(S->memlock);
    S->totalmem += size;
    S->totalmem -= oldsize;
    lk_unlock(S->memlock);
    return (char*)newptr + 8;
#else
    void *newptr = realloc(ptr, size);
    if (newptr == NULL) lkM_outofmemory(S);
    return newptr;
#endif
}

LK_API void lk_free (lk_State *S, void *ptr) {
#ifdef LK_DEBUG_MEM
    void *rptr = (char*)ptr - 8;
    size_t size;
    if (ptr == NULL) return;
    size = *(size_t*)rptr;
    free(rptr);
    lk_lock(S->memlock);
    S->totalmem -= size;
    lk_unlock(S->memlock);
#else
    (void)S; free(ptr);
#endif
}

LK_API char *lk_strdup (lk_State *S, const char *s) {
    size_t len = strlen(s) + 1;
    char *newstr = (char*)lk_malloc(S, len);
    memcpy(newstr, s, len);
    return newstr;
}

LK_API char *lk_memdup (lk_State *S, const void *buff, size_t size) {
    char *newstr = (char*)lk_malloc(S, size);
    memcpy(newstr, buff, size);
    return newstr;
}

LK_API char *lk_strncpy (char *dst, size_t n, const char *s) {
    size_t len = strlen(s);
    if (len >= n - 1) {
        memcpy(dst, s, n-1);
        dst[n-1] = '\0';
    }
    else {
        memcpy(dst, s, len);
        memset(dst+len, 0, n-len);
    }
    return dst;
}


/* memory pool routines */

static void lkM_dividepage (lk_MemPool *mpool, void *page) {
    ptrdiff_t pageaddr = (ptrdiff_t)page;
    ptrdiff_t pageend  = pageaddr + LK_MPOOLPAGESIZE;
    const size_t align = mpool->align;
    const size_t size  = mpool->size;
    pageaddr += sizeof(void*);
    for (;;) {
        ptrdiff_t obj = pageaddr;
        obj = (obj + sizeof(void*) - 1) & ~(sizeof(void*)-1);
        obj += sizeof(void*);
        if (align > sizeof(void*))
            obj = (obj + align - 1) & ~(align - 1);
        if (obj + (ptrdiff_t)size > pageend)
            return;
        ((void**)obj)[-1] = mpool->freed;
        mpool->freed = (void*)obj;
        pageaddr = obj + size;
    }
}

LK_API void lk_initmempool (lk_State *S, lk_MemPool *mpool, size_t size, size_t align) {
    if (align == 0) align = sizeof(void*);
    mpool->pages = NULL;
    mpool->freed = NULL;
    mpool->S = S;
    mpool->size = size;
    mpool->align = align;
    assert(LK_MPOOLPAGESIZE / size > 1);
    assert(((align - 1) & align) == 0);
    assert(((sizeof(void*)-1) & sizeof(void*)) == 0);
}

LK_API void lk_freemempool (lk_MemPool *mpool) {
    while (mpool->pages != NULL) {
        void *next = *(void**)mpool->pages;
        lk_free(mpool->S, mpool->pages);
        mpool->pages = next;
    }
    lk_initmempool(mpool->S, mpool, mpool->size, mpool->align);
}

LK_API void *lk_poolalloc (lk_MemPool *mpool) {
    void *obj = mpool->freed;
    if (obj == NULL) {
        void *newpage = lk_malloc(mpool->S, LK_MPOOLPAGESIZE);
        *(void**)newpage = mpool->pages;
        mpool->pages = newpage;
        lkM_dividepage(mpool, newpage);
        obj = mpool->freed;
    }
    mpool->freed = ((void**)obj)[-1];
    return obj;
}

LK_API void lk_poolfree (lk_MemPool *mpool, void *obj) {
    ((void**)obj)[-1] = mpool->freed;
    mpool->freed = obj;
}


/* buffer routines */

#if defined(_WIN32) && !defined(__MINGW32__)
static int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap) {
    int count = -1;
    if (size != 0)
        count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);
    return count;
}
#else
# define c99_vsnprintf vsnprintf
#endif

LK_API void lk_initbuffer (lk_State *S, lk_Buffer *B) {
    B->size = 0;
    B->capacity = LK_BUFFERSIZE;
    B->S = S;
    B->buff = B->init_buff;
}

LK_API void lk_freebuffer (lk_Buffer *B) {
    if (B->buff != B->init_buff)
        lk_free(B->S, B->buff);
    lk_initbuffer(B->S, B);
}

LK_API char *lk_prepbuffsize (lk_Buffer *B, size_t len) {
    if (B->size + len > B->capacity) {
        void *newptr;
        size_t newsize = LK_BUFFERSIZE;
        while (newsize < B->size + len && newsize < ~(size_t)0/2)
            newsize *= 2;
        if (B->buff != B->init_buff) {
            newptr = lk_realloc(B->S, B->buff, newsize);
        }
        else {
            newptr = lk_malloc(B->S, newsize);
            memcpy(newptr, B->buff, B->size);
        }
        B->buff = (char*)newptr;
        B->capacity = newsize;
    }
    return &B->buff[B->size];
}

LK_API int lk_addlstring (lk_Buffer *B, const char *s, size_t len) {
    memcpy(lk_prepbuffsize(B, len), s, len);
    return B->size += len;
}

LK_API int lk_addvfstring (lk_Buffer *B, const char *fmt, va_list l) {
    const size_t init_size = 80;
    char *ptr = lk_prepbuffsize(B, init_size+1);
    va_list l_count;
    int len;
#ifdef va_copy
    va_copy(l_count, l);
#else
    __va_copy(l_count, l);
#endif
    len = c99_vsnprintf(ptr, init_size, fmt, l_count);
    va_end(l_count);
    if (len <= 0) return 0;
    if ((size_t)len > init_size) {
        ptr = lk_prepbuffsize(B, len + 1);
        c99_vsnprintf(ptr, len+1, fmt, l);
    }
    return B->size += len;
}

LK_API int lk_addfstring (lk_Buffer *B, const char *fmt, ...) {
    int ret;
    va_list l;
    va_start(l, fmt);
    ret = lk_addvfstring(B, fmt, l);
    va_end(l);
    return ret;
}

LK_API void lk_replacebuffer (lk_Buffer *B, char origch, char newch) {
    size_t i;
    for (i = 0; i < B->size; ++i)
        if (B->buff[i] == origch)
            B->buff[i] = newch;
}

LK_API const char *lk_buffresult (lk_Buffer *B) {
    char *result = (char*)lk_malloc(B->S, B->size + 1);
    memcpy(result, B->buff, B->size);
    result[B->size] = '\0';
    lk_freebuffer(B);
    return result;
}


/* hashtable routines */

static size_t lkH_hashsize (size_t len) {
    size_t newsize = LK_MIN_HASHSIZE;
    while (newsize < LK_MAX_SIZET/2 && newsize < len)
        newsize <<= 1;
    return newsize;
}

static size_t lkH_countsize (lk_Table *t) {
    size_t i, count = 0;
    for (i = 0; i < t->size; ++i) {
        if (t->hash[i].key != NULL)
            ++count;
    }
    return count;
}

static lk_Entry *lkH_mainposition (lk_Table *t, lk_Entry *entry) {
    assert((t->size & (t->size - 1)) == 0);
    return &t->hash[entry->hash & (t->size - 1)];
}

static lk_Entry *lkH_newkey (lk_Table *t, lk_Entry *entry) {
    lk_Entry *mp;
    if (t->size == 0 && lk_resizetable(t, LK_MIN_HASHSIZE) == 0) 
        return NULL;
redo:
    mp = lkH_mainposition(t, entry);
    if (mp->key != 0) {
        lk_Entry *f = NULL, *othern;
        while (t->lastfree > 0) {
            lk_Entry *e = &t->hash[--t->lastfree];
            if (e->key == 0)  { f = e; break; }
        }
        if (f == NULL) {
            if (lk_resizetable(t, lkH_countsize(t)*2) == 0)
                return NULL;
            goto redo; /* return lkH_newkey(t, entry); */
        }
        assert(f->hash == 0);
        othern = lkH_mainposition(t, mp);
        if (othern != mp) {
            while (othern + othern->next != mp)
                othern += othern->next;
            othern->next = f - othern;
            *f = *mp;
            if (mp->next != 0) {
                f->next += mp - f;
                mp->next = 0;
            }
        }
        else {
            if (mp->next != 0)
                f->next = (mp + mp->next) - f;
            else assert(f->next == 0);
            mp->next = f - mp;
            mp = f;
        }
    }
    mp->key = entry->key;
    mp->hash = entry->hash;
    mp->value = entry->value;
    return mp;
}

static unsigned lkH_calchash (const char *s, size_t len) {
    size_t l1;
    size_t step = (len >> LK_HASHLIMIT) + 1;
    unsigned h = (unsigned)len;
    for (l1 = len; l1 >= step; l1 -= step)
        h ^= (h<<5) + (h>>2) + (unsigned char)s[l1 - 1];
    return h;
}

LK_API void lk_inittable (lk_State *S, lk_Table *t) {
    t->size = t->lastfree = 0;
    t->S = S;
    t->hash = NULL;
}

LK_API void lk_freetable (lk_Table *t, int freekey) {
    if (freekey) {
        size_t i;
        for (i = 0; i < t->size; ++i) {
            const char *key = t->hash[i].key;
            if (key) lk_free(t->S, (void*)key);
        }
    }
    if (t->hash != NULL) lk_free(t->S, t->hash);
    lk_inittable(t->S, t);
}

LK_API size_t lk_resizetable (lk_Table *t, size_t len) {
    size_t i;
    lk_Table new_map;
    new_map.S = t->S;
    new_map.size = lkH_hashsize(len);
    new_map.hash = (lk_Entry*)lk_malloc(t->S, new_map.size*sizeof(lk_Entry));
    new_map.lastfree = new_map.size;
    memset(new_map.hash, 0, sizeof(lk_Entry)*new_map.size);
    for (i = 0; i < t->size; ++i) {
        if (t->hash[i].key != NULL)
            lkH_newkey(&new_map, &t->hash[i]);
    }
    lk_free(t->S, t->hash);
    *t = new_map;
    return t->size;
}

LK_API lk_Entry *lk_getentry (lk_Table *t, const char *key) {
    unsigned hash;
    lk_Entry *e;
    if (t->size == 0 || key == NULL) return NULL;
    hash = lkH_calchash(key, strlen(key));
    assert((t->size & (t->size - 1)) == 0);
    e = &t->hash[hash & (t->size - 1)];
    while (1) {
        int next = e->next;
        if (e->hash == hash && key && e->key && strcmp(e->key, key) == 0)
            return e;
        if (next == 0) return NULL;
        e += next;
    }
    return NULL;
}

LK_API lk_Entry *lk_setentry (lk_Table *t, const char *key) {
    lk_Entry e, *ret;
    if (key == NULL) return NULL;
    if ((ret = lk_getentry(t, key)) != NULL)
        return ret;
    e.key = key;
    e.hash = lkH_calchash(key, strlen(key));
    e.value = 0;
    return lkH_newkey(t, &e);
}

LK_API void lk_delentry (lk_Table *t, lk_Entry *e, int freekey) {
    if (freekey) lk_free(t->S, (void*)e->key);
    e->hash = 0;
    e->key = NULL;
    e->value = NULL;
}

LK_API int lk_nextentry (lk_Table *t, lk_Entry **pentry) {
    size_t i = *pentry ? *pentry - &t->hash[0] + 1 : 0;
    for (; i < t->size; ++i) {
        if (t->hash[i].key != NULL) {
            *pentry = &t->hash[i];
            return 1;
        }
    }
    return 0;
}


/* platform specific routines */

static void lkT_dispatchGS (lk_State *S, lk_Service *svr);

#ifdef _WIN32

static size_t lkP_getcpucount (void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors;
}

static void lkP_getmodulename(lk_Buffer *B) {
    char *buff = lk_prepbuffsize(B, MAX_PATH);
    DWORD size;
    if ((size = GetModuleFileName(GetModuleHandle(NULL), buff, MAX_PATH)) == 0)
        lk_addchar(B, '.');
    else {
        while (--size != 0 && buff[size] != '/' && buff[size] != '\\')
            ;
        lk_addsize(B, size);
    }
}

static lk_Service *lkP_waitinit (lk_Service *svr, lk_Event *event) {
    WaitForSingleObject(*event, INFINITE);
    return svr;
}

static DWORD WINAPI lkP_poller (void *lpParameter) {
    lk_Context ctx;
    lk_Slot *slot  = (lk_Slot*)lpParameter;
    lk_Poll *poll = (lk_Poll*)slot;
    lk_State *S = slot->S;
    lk_pushcontext(S, &ctx, slot->service);
    lk_try(S, &ctx, slot->handler(S, slot->ud, slot, NULL));
    lk_popcontext(S, &ctx);
    poll->status = LK_STOPPING;
    return 0;
}

static DWORD WINAPI lkP_worker (void *lpParameter) {
    int status  = LK_WORKING;
    lk_State *S = (lk_State*)lpParameter;
    while (status == LK_WORKING) {
        lk_Service *svr;
        WaitForSingleObject(S->event, INFINITE);
        lk_lock(S->lock);
        lkQ_dequeue(&S->active_services, svr);
        if ((status = S->status) >= LK_STOPPING)
            lk_signal(S->event);
        lk_unlock(S->lock);
        while (svr != NULL) {
            lkT_dispatchGS(S, svr);
            lk_lock(S->lock);
            lkQ_dequeue(&S->active_services, svr);
            lk_unlock(S->lock);
        }
    }
    return 0;
}

LK_API void lk_waitclose (lk_State *S) {
    WaitForMultipleObjects(S->nthreads, S->threads, TRUE, INFINITE);
}

LK_API int lk_wait (lk_Slot *slot, lk_Signal* sig, int waitms) {
    lk_Poll *poll = (lk_Poll*)slot;
    lk_SignalNode *node;
    if (!slot->ispoll) return LK_ERR;
    lk_lock(poll->lock);
    lkQ_dequeue(&poll->signals, node);
    lk_unlock(poll->lock);
    if (waitms != 0 && (!node || poll->status < LK_STOPPING)) {
        DWORD timeout = waitms < 0 ? INFINITE : (DWORD)waitms;
        WaitForSingleObject(poll->event, timeout);
    }
    if (node) {
        lk_State *S = slot->S;
        if (sig) *sig = node->data;
        lk_lock(S->lock);
        lk_poolfree(&S->signals, node);
        lk_unlock(S->lock);
        return LK_OK;
    }
    return poll->status >= LK_STOPPING ? LK_ERR : LK_TIMEOUT;
}

#else

static size_t lkP_getcpucount (void) {
    return (size_t)sysconf(_SC_NPROCESSORS_ONLN);
}

static void lkP_getmodulename(lk_Buffer *B) {
    char *buff = lk_prepbuffsize(B, PATH_MAX);
    size_t size;
    if ((size = readlink("/proc/self/exe", buff, PATH_MAX)) <= 0)
        lk_addchar(B, '.');
    else {
        while (--size != 0 && buff[size] != '/')
            ;
        lk_addsize(B, size);
    }
}

static lk_Service *lkP_waitinit (lk_Service *svr, lk_Event *event) {
     lk_lock(svr->lock);
     while (svr->status == LK_INITIALING)
         pthread_cond_wait(event, &svr->lock);
     lk_unlock(svr->lock);
     return svr;
}

static void *lkP_poller (void *ud) {
    lk_Context ctx;
    lk_Slot *slot  = (lk_Slot*)ud;
    lk_Poll *poll = (lk_Poll*)slot;
    lk_State *S = slot->S;
    lk_pushcontext(S, &ctx, slot->service);
    lk_try(S, &ctx, slot->handler(S, slot->ud, slot, NULL));
    lk_popcontext(S, &ctx);
    poll->status = LK_STOPPING;
    return NULL;
}

static void *lkP_worker (void *ud) {
    int status = LK_WORKING;
    lk_State *S = (lk_State*)ud;
    lk_lock(S->lock);
    while (status == LK_WORKING) {
        lk_Service *svr;
        for (;;) {
            lkQ_dequeue(&S->active_services, svr);
            status = S->status;
            if (svr != NULL || status != LK_WORKING)
                break;
            pthread_cond_wait(&S->event, &S->lock);
        }
        if (status >= LK_STOPPING)
            pthread_cond_broadcast(&S->event);
        while (svr != NULL) {
            lk_unlock(S->lock);
            lkT_dispatchGS(S, svr);
            lk_lock(S->lock);
            lkQ_dequeue(&S->active_services, svr);
        }
    }
    lk_unlock(S->lock);
    return NULL;
}

LK_API void lk_waitclose (lk_State *S) {
    size_t i;
    for (i = 0; i < S->nthreads; ++i)
        pthread_join(S->threads[i], NULL);
    S->nthreads = 0;
}

static int lk_timedwait (lk_Event *event, lk_Lock *lock, int waitms) {
    struct timeval tv;
    struct timespec ts;
    int sec  = waitms / 1000;
    int usec = waitms % 1000 * 1000;
    gettimeofday(&tv, NULL);
    if (tv.tv_usec + usec > 1000000) {
        sec += 1;
        usec = (tv.tv_usec + usec) - 1000000;
    }
    ts.tv_sec = tv.tv_sec + sec;
    ts.tv_nsec = (tv.tv_usec + usec) * 1000;
    return pthread_cond_timedwait(event, lock, &ts);
}

LK_API int lk_wait (lk_Slot *slot, lk_Signal* sig, int waitms) {
    lk_Poll *poll = (lk_Poll*)slot;
    lk_SignalNode *node;
    if (!slot->ispoll) return LK_ERR;
    lk_lock(poll->lock);
    lkQ_dequeue(&poll->signals, node);
    if (waitms != 0 && (!node || poll->status < LK_STOPPING)) {
        if (waitms < 0)
            pthread_cond_wait(&poll->event, &poll->lock);
        else
            lk_timedwait(&poll->event, &poll->lock, waitms);
    }
    lk_unlock(poll->lock);
    if (node) {
        if (sig) *sig = node->data;
        return LK_OK;
    }
    return poll->status >= LK_STOPPING ? LK_ERR : LK_TIMEOUT;
}

#endif


/* singal slot routines */

LK_API const char *lk_name    (lk_Slot *slot) { return slot->name;    }
LK_API lk_Service *lk_service (lk_Slot *slot) { return slot->service; }
LK_API lk_State   *lk_state   (lk_Slot *slot) { return slot->S;       }

LK_API lk_SignalHandler *lk_slothandler (lk_Slot *slot, void **pud)
{ if (pud) *pud = slot->ud; return slot->handler; }

static const char *lkS_name (lk_Service *svr, lk_Buffer *B, const char *name) {
    lk_initbuffer(svr->slot.S, B);
    lk_addstring(B, svr->slot.name);
    lk_addchar(B, '.');
    lk_addstring(B, name);
    lk_addchar(B, '\0');
    assert(lk_buffsize(B) <= LK_MAX_SLOTNAME);
    return lk_buffer(B);
}

static lk_Slot *lkS_new (lk_State *S, size_t sz, const char *name) {
    lk_Slot *slot = (lk_Slot*)lk_malloc(S, sz);
    size_t len = strlen(name);
    assert(len < LK_MAX_NAMESIZE);
    memset(slot, 0, sz);
    memcpy(slot->name, name, len);
    slot->S = S;
    return slot;
}

static lk_Slot *lkS_register (lk_State *S, lk_Slot *slot) {
    lk_Entry *e = lk_setentry(&S->slots, slot->name);
    if (e->value != NULL) {
        if (&slot->service->slot == slot)
            lk_freelock(slot->service->lock);
        lk_free(S, slot);
        return NULL;
    }
    e->value = slot;
    return slot;
}

static int lkP_startpoll (lk_Poll *poll) {
    lkQ_init(&poll->signals);
    poll->status = LK_WORKING;
    if (!lk_initlock(&poll->lock))   goto err_lock;
    if (!lk_initevent(&poll->event)) goto err_event;
    if (!lk_initthread(&poll->thread, lkP_poller, poll)) {
        lk_freeevent(poll->event);
err_event:
        lk_freelock(poll->lock);
err_lock:
        lk_free(poll->slot.S, poll);
        return LK_ERR;
    }
    return LK_OK;
}

static void lkS_delpollG (lk_State *S, lk_Poll *poll) {
    lk_lock(poll->lock);
    poll->status = LK_STOPPING;
    lk_signal(poll->event);
    lk_unlock(poll->lock);
    lk_waitthread(poll->thread);
    lk_freeevent(poll->event);
    lk_freelock(poll->lock);
    lk_lock(S->lock);
    {
        lk_SignalNode *node = poll->signals.first;
        while (node) {
            lk_SignalNode *next = node->next;
            lk_poolfree(&S->signals, node);
            node = next;
        }
    }
    lk_unlock(S->lock);
    lk_free(S, poll);
}

static lk_Slot *lkS_findslotG (lk_State *S, const char *name) {
    lk_Slot *slot = NULL;
    lk_Entry *e;
    lk_lock(S->lock);
    e = lk_getentry(&S->slots, name);
    if (e != NULL) slot = (lk_Slot*)e->value;
    lk_unlock(S->lock);
    return slot;
}

static void lkS_emitpollP (lk_Poll *poll, lk_SignalNode *node) {
    lk_lock(poll->lock);
    lkQ_enqueue(&poll->signals, node);
    lk_signal(poll->event);
    lk_unlock(poll->lock);
}

static void lkS_emitslotGS (lk_State *S, lk_Service *svr, lk_SignalNode *node) {
    lk_lock(S->lock);
    lk_lock(svr->lock);
    lkQ_enqueue(&svr->signals, node);
    if (svr->status == LK_SLEEPING) {
        lkQ_enqueue(&S->active_services, svr);
        svr->status = LK_WORKING;
        lk_signal(S->event);
    }
    lk_unlock(svr->lock);
    lk_unlock(S->lock);
}

static int lkS_check (lk_State *S, const char *tag, const char *name) {
    if (strlen(name) >= LK_MAX_NAMESIZE) {
        lk_log(S, "E[%s]" lk_loc("slot name '%s' too long"), tag, name);
        return 0;
    }
    if (lk_self(S)->status >= LK_STOPPING) {
        lk_log(S, "E[%s]"
                lk_loc("can not create slot after service destroyed"), tag);
        return 0;
    }
    return 1;
}

LK_API lk_Slot *lk_newslot (lk_State *S, const char *name, lk_SignalHandler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    lk_Slot *slot = NULL;
    lk_Buffer B;
    if (!lkS_check(S, "newslot", name)) return NULL;
    name = lkS_name(svr, &B, name);
    slot = lkS_new(S, sizeof(lk_Slot), lk_buffer(&B));
    lk_freebuffer(&B);
    slot->service = svr;
    slot->handler = h;
    slot->ud = ud;
    lk_lock(S->lock);
    if ((slot = lkS_register(S, slot)) != NULL) {
        slot->next = svr->slots;
        svr->slots = slot;
    }
    lk_unlock(S->lock);
    if (slot == NULL)
        lk_log(S, "E[newslot]", lk_loc("slot '%s' exists"), name);
    return slot;
}

LK_API lk_Slot *lk_newpoll (lk_State *S, const char *name, lk_SignalHandler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    lk_Poll *poll;
    lk_Buffer B;
    if (!lkS_check(S, "newpoll", name)) return NULL;
    name = lkS_name(svr, &B, name);
    poll = (lk_Poll*)lkS_new(S, sizeof(lk_Poll), name);
    lk_freebuffer(&B);
    poll->slot.ispoll = 1;
    poll->slot.service = svr;
    poll->slot.handler = h;
    poll->slot.ud = ud;
    if (lkP_startpoll(poll) != LK_OK) return NULL;
    lk_lock(S->lock);
    if ((poll = (lk_Poll*)lkS_register(S, &poll->slot)) != NULL) {
        poll->slot.next = svr->polls;
        svr->polls = &poll->slot;
    }
    lk_unlock(S->lock);
    if (poll == NULL) {
        lk_log(S, "E[newpoll]", lk_loc("poll '%s' exists"), name);
        return NULL;
    }
    return &poll->slot;
}

LK_API lk_Slot *lk_slot (lk_State *S, const char *name) {
    lk_Slot *slot = NULL;
    if (strchr(name, '.') == NULL) {
        lk_Service *svr = lk_self(S);
        lk_Buffer B;
        const char *qname = lkS_name(svr, &B, name);
        slot = lkS_findslotG(S, qname);
    }
    if (slot == NULL)
        slot = lkS_findslotG(S, name);
    if (slot == NULL)
        lk_log(S, "E[slot]" lk_loc("slot '%s' not exists"), name);
    return slot;
}

LK_API int lk_emit (lk_Slot *slot, const lk_Signal *sig) {
    lk_State *S = slot->S;
    lk_Service *svr = slot->service, *src = sig->src ? sig->src : lk_self(S);
    lk_SignalNode *node = NULL;
    if (S->status >= LK_STOPPING
            || src->status >= LK_STOPPING
            || svr->status >= LK_STOPPING) {
        lk_log(S, "E[emit]" lk_loc("can not emit signal"));
        return LK_ERR;
    }
    lk_lock(S->lock);
    node = (lk_SignalNode*)lk_poolalloc(&S->signals);
    lk_unlock(S->lock);
    node->slot = slot;
    node->data = *sig;
    node->data.src = src;
    if (slot->ispoll)
        lkS_emitpollP((lk_Poll*)slot, node);
    else
        lkS_emitslotGS(S, svr, node);
    if (!slot->ispoll) {
        lk_lock(src->lock);
        ++src->pending;
        lk_unlock(src->lock);
    }
    return LK_OK;
}

LK_API int lk_emitdata (lk_Slot *slot, unsigned type, unsigned session, const void *data, size_t size) {
    lk_Signal sig = LK_SIGNAL;
    sig.free = 1;
    sig.type = type;
    sig.session = session;
    sig.size = size;
    sig.data = lk_memdup(slot->S, data, size);
    return lk_emit(slot, &sig);
}

LK_API int lk_emitstring (lk_Slot *slot, unsigned type, unsigned session, const char *s) {
    lk_Signal sig = LK_SIGNAL;
    sig.free = 1;
    sig.type = type;
    sig.session = session;
    sig.size = strlen(s);
    sig.data = lk_malloc(slot->S, sig.size + 1);
    memcpy(sig.data, s, sig.size + 1);
    return lk_emit(slot, &sig);
}

LK_API void lk_setslothandler (lk_Slot *slot, lk_SignalHandler *h, void *ud) {
    if (slot->service->status != LK_INITIALING)
        lk_log(slot->S, "E[setslothandler]" lk_loc("can not set slot handler "
                    "after service initialized"));
    else {
        slot->handler = h;
        slot->ud = ud;
    }
}


/* service routines */

static void lkG_onrequire (lk_State *S, lk_Service *svr);
static void lkG_onopen    (lk_State *S, lk_Service *svr);
static void lkG_onclose   (lk_State *S, lk_Service *svr);

LK_API void *lk_data (lk_Service *svr) { return svr->data; }

LK_API lk_SignalHandler *lk_refactor (lk_Service *svr, void **pud)
{ if (pud) *pud = svr->ud; return svr->refactor; }

LK_API lk_Context *lk_context (lk_State *S)
{ return (lk_Context*)lk_gettls(S->tls_index); }

LK_API lk_Service *lk_self (lk_State *S)
{ lk_Context *ctx = lk_context(S); return ctx ? ctx->current : &S->root; }

LK_API void lk_pushcontext (lk_State *S, lk_Context *ctx, lk_Service *svr) {
    ctx->prev = lk_context(S);
    ctx->S = S;
    ctx->current = svr;
    ctx->cleanups = NULL;
    ctx->status = LK_OK;
    lk_settls(S->tls_index, ctx);
}

LK_API void lk_popcontext (lk_State *S, lk_Context *ctx) {
    lk_lock(S->lock);
    {
        lk_Cleanup *cleanups = ctx->cleanups;
        while (cleanups) {
            lk_Cleanup *next = cleanups->next;
            lk_poolfree(&S->cleanups, next);
            cleanups = next;
        }
    }
    lk_unlock(S->lock);
    lk_settls(S->tls_index, ctx->prev);
}

static lk_Service *lkT_newservice (lk_State *S, const char *name) {
    lk_Service *svr = (lk_Service*)lkS_new(S, sizeof(lk_Service), name);
    svr->slot.service = svr;
    svr->slots = &svr->slot;
    lkQ_init(&svr->signals);
    if (!lk_initlock(&svr->lock) || !lkS_register(S, &svr->slot)) {
        lk_free(S, svr);
        return NULL;
    }
    return svr;
}

static void lkT_freeslotsG (lk_State *S, lk_Service *svr) {
    lk_Slot *polls;
    lk_lock(S->lock);
    while (svr->slots != NULL) {
        lk_Slot *next = svr->slots->next;
        lk_Entry *e = lk_getentry(&S->slots, svr->slots->name);
        assert(e && (lk_Slot*)e->value == svr->slots);
        lk_delentry(&S->slots, e, svr->slots != &svr->slot);
        svr->slots = next;
    }
    polls = svr->polls;
    while (svr->polls != NULL) {
        lk_Slot *next = svr->polls->next;
        lk_Entry *e = lk_getentry(&S->slots, svr->polls->name);
        assert(e && (lk_Slot*)e->value == svr->polls);
        lk_delentry(&S->slots, e, 0);
        svr->polls = next;
    }
    lk_unlock(S->lock);
    while (polls != NULL) {
        lk_Slot *next = polls->next;
        lkS_delpollG(S, (lk_Poll*)polls);
        polls = next;
    }
}

static void lkT_delserviceG (lk_State *S, lk_Service *svr) {
    lk_Context ctx;
    if (S->monitor && S->monitor != &svr->slot)
        lk_emitdata(S->monitor, 1, 0, &svr, sizeof(svr));
    if (svr->slot.handler) {
        lk_pushcontext(S, &ctx, svr);
        lk_try(S, &ctx, svr->slot.handler(S, svr->slot.ud, &svr->slot, NULL));
        lk_popcontext(S, &ctx);
    }
    lkT_freeslotsG(S, svr);
    lk_freelock(svr->lock);
    if (svr->module != NULL) lk_freelib(svr->module);
    assert(lkQ_empty(&svr->signals));
    lk_lock(S->lock);
    lkG_onclose(S, svr);
    lk_unlock(S->lock);
    if (svr != &S->root) lk_free(S, svr);
}

static lk_Service *lkT_callinitGS (lk_State *S, lk_Service *svr, lk_ServiceHandler *h) {
    lk_Context ctx;
    int ret = LK_OK;
    if (h) {
        lk_pushcontext(S, &ctx, svr);
        lk_try(S, &ctx, ret = h(S));
        lk_popcontext(S, &ctx);
        if (ctx.status == LK_ERR || ret < 0 || svr->status >= LK_STOPPING) {
            lkT_delserviceG(S, svr);
            return NULL;
        }
    }
    lk_lock(S->lock);
    lk_lock(svr->lock);
    if (svr->event) {
        lk_freeevent(*svr->event);
        svr->event = NULL;
    }
    if (ret == LK_WEAK) svr->weak = 1;
    else ++S->nservices;
    if (lkQ_empty(&svr->signals))
        svr->status = LK_SLEEPING;
    else {
        svr->status = LK_WORKING;
        lkQ_enqueue(&S->active_services, svr);
    }
    lk_unlock(svr->lock);
    lkG_onopen(S, svr);
    lk_unlock(S->lock);
    return svr;
}

static lk_Service *lkT_initserviceGS (lk_State *S, lk_Service *svr, lk_ServiceHandler *h) {
    lk_Event event, *pevent;
    int need_initialize, skip_initialize = 0;
    if (!svr) return NULL;
    lk_lock(svr->lock);
    pevent = svr->event;
    need_initialize = svr->status == LK_INITIALING && pevent == NULL;
    if (need_initialize) {
        if (!lk_initevent(&event))
            skip_initialize = 1;
        else
            svr->event = &event;
    }
    lk_unlock(svr->lock);
    if (skip_initialize)
        return NULL;
    else if (!need_initialize && pevent == NULL)
        return svr;
    if (pevent) return lkP_waitinit(svr, pevent);
    return lkT_callinitGS(S, svr, h);
}

static void lkT_callslot (lk_State *S, lk_SignalNode *node, lk_Context *ctx) {
    int ret = LK_ERR;
    lk_Slot *slot = node->slot;
    lk_Service *src = node->data.src;
    assert(src != NULL);
    if (src->refactor && slot != S->logger)
        lk_try(S, ctx, ret = src->refactor(S, src->ud, slot, &node->data));
    if (ret == LK_ERR && slot->handler)
        lk_try(S, ctx, slot->handler(S, slot->ud, slot, &node->data));
    if (node->data.free)
        lk_free(S, node->data.data);
}

static void lkT_callslotsGS (lk_State *S, lk_Service *svr) {
    lk_Context ctx;
    lk_SignalNode *node;
    /* fetch all signal */
    lk_lock(svr->lock);
    lkQ_clear(&svr->signals, node);
    lk_unlock(svr->lock);

    /* call signal handler */
    lk_pushcontext(S, &ctx, svr);
    while (node != NULL) {
        lk_SignalNode *next = node->next;
        lk_Service *src = node->data.src;
        lkT_callslot(S, node, &ctx);
        lk_lock(S->lock);
        lk_poolfree(&S->signals, node);
        lk_lock(src->lock);
        if (--src->pending == 0 && src->status == LK_ZOMBIE)
            lkQ_enqueue(&S->active_services, svr);
        lk_unlock(src->lock);
        lk_unlock(S->lock);
        node = next;
    }
    lk_popcontext(S, &ctx);
}

static void lkT_dispatchGS (lk_State *S, lk_Service *svr) {
    int should_delete = 0;
    lkT_callslotsGS(S, svr);

    lk_lock(S->lock);
    lk_lock(svr->lock);
    if (!lkQ_empty(&svr->signals))
        lkQ_enqueue(&S->active_services, svr);
    if (svr->status == LK_STOPPING && svr->pending != 0)
        svr->status = LK_ZOMBIE;
    else if (svr->status < LK_STOPPING)
        svr->status = LK_SLEEPING;
    else if (svr->pending == 0)
        should_delete = 1;
    lk_unlock(svr->lock);
    lk_unlock(S->lock);

    if (should_delete) lkT_delserviceG(S, svr);
}

static int lkT_check(lk_State *S, const char *name) {
    if (strlen(name) > LK_MAX_NAMESIZE) {
        lk_log(S, "E[require]" lk_loc("serivce name '%s' too long"), name);
        return 0;
    }
    if (S->status >= LK_STOPPING) {
        lk_log(S, "E[require]" lk_loc("can not create slot "
                    "after state destroyed"));
        return 0;
    }
    return 1;
}

LK_API void lk_preload (lk_State *S, const char *name, lk_ServiceHandler *h) {
    lk_Entry *e;
    lk_lock(S->lock);
    e = lk_getentry(&S->slots, name);
    if (e == NULL) {
        e = lk_setentry(&S->preload, name);
        if (e->value == NULL) {
            e->key = lk_strdup(S, name);
            e->value = (void*)(ptrdiff_t)h;
        }
    }
    lk_unlock(S->lock);
}

LK_API lk_Service *lk_requiref (lk_State *S, const char *name, lk_ServiceHandler *h) {
    lk_Service *svr;
    if ((svr = (lk_Service*)lk_slot(S, name)) != NULL) {
        lkG_onrequire(S, svr);
        return svr;
    }
    if (!lkT_check(S, name)) return NULL;
    lk_lock(S->lock);
    svr = lkT_newservice(S, name);
    lk_unlock(S->lock);
    if (svr == NULL) {
        lk_log(S, "E[require]", lk_loc("can not create service '%s'"), name);
        return NULL;
    }
    return lkT_initserviceGS(S, svr, h);
}

LK_API void lk_setdata (lk_State *S, void *data) {
    lk_Service *svr = lk_self(S);
    if (svr->status != LK_INITIALING)
        lk_log(S, "E[setdata]" lk_loc("can not set data "
                    "after service initialized"));
    else
        svr->data = data;
}

LK_API void lk_setrefactor (lk_State *S, lk_SignalHandler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    if (svr->status != LK_INITIALING)
        lk_log(S, "E[setrefactor]" lk_loc("can not set refactor "
                    "after service initialized"));
    else {
        svr->refactor = h;
        svr->ud = ud;
    }
}


/* service module loader */

typedef struct lk_LoaderState {
    lk_State   *S;
    lk_Service *svr;
    lk_ServiceHandler *h;
    const char *start, *end; /* path */
    const char *name, *nend; /* module name */
    lk_Module   module;
    lk_Buffer   buff;
    lk_Buffer   errmsg;
} lk_LoaderState;

static const char *lkT_modpath (lk_LoaderState *ls, const char *start) {
    lk_Buffer *B = &ls->buff;
    for (; start < ls->end && *start != ';'; ++start) {
        if (*start == '?')
            lk_addlstring(B, ls->name, ls->nend - ls->name);
        else if (*start == '!')
            lkP_getmodulename(B);
        else
            lk_addchar(B, *start);
    }
    if (lk_buffsize(B) != 0)
        lk_addchar(B, '\0');
    return start;
}

static void lkT_preload (lk_State *S, lk_LoaderState *ls, const char *name) {
    lk_Entry *e = lk_getentry(&S->preload, name);
    if (e != NULL && e->value != NULL) {
        ls->h = (lk_ServiceHandler*)(ptrdiff_t)e->value;
        lk_delentry(&S->slots, e, 1);
    }
    if (ls->h == NULL)
        lk_addfstring(&ls->errmsg, "\tno entry in preload['%s']\n", name);
}

static size_t lkT_initpath (lk_State *S, lk_LoaderState *ls, const char *name, const char *dot) {
    lk_Buffer *B = &ls->buff;
    size_t namelen;
    lk_resetbuffer(B);
    lk_addstring(B, LK_PREFIX);
    lk_addstring(B, name);
    if (dot) lk_replacebuffer(B, '.', '_');
    lk_addchar(B, '\0');
    namelen = lk_buffsize(B);
    ls->start = lk_buffer(&S->path);
    ls->end   = ls->start + lk_buffsize(&S->path);
    ls->name  = name;
    ls->nend  = name + strlen(name);
    return namelen;
}

static void lkT_module (lk_State *S, lk_LoaderState *ls, const char *name) {
    lk_Buffer *B = &ls->buff;
    const char *dot = strchr(name, '.');
    size_t offset = lkT_initpath(S, ls, name, dot);
    for (; ls->start < ls->end; ++ls->start) {
        const char *current = ls->start;
        lk_buffsize(B) = offset;
        ls->start = lkT_modpath(ls, current);
        if (lk_buffsize(B) == 0) continue;
        if ((ls->module = lk_loadlib(lk_buffer(B)+offset)) == NULL) {
            lk_addfstring(&ls->errmsg, "\tno file '%s'\n", lk_buffer(B)+offset);
            if (!dot) continue;
            lk_buffsize(B) = offset;
            ls->start = lkT_modpath(ls, current);
            if ((ls->module = lk_loadlib(lk_buffer(B)+offset)) == NULL)
                lk_addfstring(&ls->errmsg, "\tno file '%s'\n", lk_buffer(B)+offset);
        }
        if (ls->module == NULL) continue;
        ls->h = (lk_ServiceHandler*)lk_getaddr(ls->module, lk_buffer(B));
        if (ls->h != NULL) return;
        lk_addfstring(&ls->errmsg, "\tcan not find entry '%s' in file '%s'\n",
                lk_buffer(B), lk_buffer(B)+offset);
        lk_freelib(ls->module);
    }
}

LK_API lk_Service *lk_require (lk_State *S, const char *name) {
    lk_LoaderState ls;
    if ((ls.svr = (lk_Service*)lk_slot(S, name)) != NULL) {
        lkG_onrequire(S, ls.svr);
        return ls.svr;
    }
    if (!lkT_check(S, name)) return NULL;
    memset(&ls, 0, sizeof(ls));
    lk_initbuffer(S, &ls.buff);
    lk_initbuffer(S, &ls.errmsg);
    lk_addfstring(&ls.errmsg, "can not load service '%s':\n", name);
    lk_lock(S->lock);
    if (ls.h == NULL) lkT_preload(S, &ls, name);
    if (ls.h == NULL) lkT_module(S, &ls, name);
    lk_unlock(S->lock);
    if (ls.h == NULL)
        lk_log(S, "E[require]" lk_loc("%s"), lk_buffer(&ls.errmsg));
    lk_freebuffer(&ls.errmsg);
    lk_freebuffer(&ls.buff);
    if (ls.h != NULL && ls.svr == NULL
            && (ls.svr = lkT_newservice(S, name)) == NULL) {
        if (ls.module) lk_freelib(ls.module);
        lk_log(S, "E[require]" lk_loc("can not create service '%s')"), name);
        return NULL;
    }
    return lkT_initserviceGS(S, ls.svr, ls.h);
}


/* global routines */

LK_API void lk_setthreads (lk_State *S, int threads)
{ if (S->status == LK_INITIALING) S->nthreads = threads; }

static void lkG_onrequire (lk_State *S, lk_Service *svr) {
    if (S->monitor) {
        lk_Service *svrs[2];
        svrs[0] = lk_self(S), svrs[1] = svr;
        lk_emitdata(S->monitor, 0, 0, svrs, sizeof(*svrs));
    }
}

static void lkG_onopen (lk_State *S, lk_Service *svr) {
    if (S->monitor) {
        lk_Service *svrs[2];
        svrs[0] = lk_self(S), svrs[1] = svr;
        lk_emitdata(S->monitor, 0, 1, svrs, sizeof(*svrs));
    }
    if (!S->logger && strcmp(svr->slot.name, "log") == 0)
        S->logger = &svr->slot;
    if (!S->monitor && strcmp(svr->slot.name, "monitor") == 0)
        S->monitor = &svr->slot;
}

static void lkG_onclose (lk_State *S, lk_Service *svr) {
    if (&svr->slot == S->logger)  S->logger = NULL;
    if (&svr->slot == S->monitor) S->monitor = NULL;
    if (!svr->weak) --S->nservices;
    if ((S->nservices == 1 && S->root.slot.handler == NULL)
            || S->nservices == 0) {
        S->status = LK_STOPPING;
        lk_signal(S->event);
    }
}

static int lkG_initroot (lk_State *S, const char *name) {
    lk_Service *svr = &S->root;
    lk_strncpy(svr->slot.name, LK_MAX_NAMESIZE, name);
    svr->slot.S = S;
    svr->slot.service = svr;
    svr->slots = &svr->slot;
    lkQ_init(&svr->signals);
    return lk_initlock(&svr->lock);
}

static void lkG_delstate (lk_State *S) {
    lk_Entry *e = NULL;
    size_t i;
    while (lk_nextentry(&S->slots, &e)) {
        lk_Slot *slot = (lk_Slot*)e->value;
        if (slot == &slot->service->slot)
            lkT_delserviceG(S, (lk_Service*)slot);
    }
    lk_freemempool(&S->cleanups);
    lk_freemempool(&S->signals);
    lk_freetable(&S->preload, 1);
    lk_freetable(&S->config, 1);
    lk_freetable(&S->slots, 0);
    lk_freebuffer(&S->path);
    for (i = 0; i < S->nthreads; ++i)
        lk_freethread(S->threads[i]);
    lk_freeevent(S->event);
    lk_freetls(S->tls_index);
    lk_freelock(S->lock);
#ifdef LK_DEBUG_MEM
    lk_freelock(S->memlock);
    assert(S->totalmem == 0);
#endif
    free(S);
}

LK_API lk_State *lk_newstate (const char *name) {
    lk_State *S = (lk_State*)malloc(sizeof(lk_State));
    if (S == NULL) return NULL;
    memset(S, 0, sizeof(*S));
    name = name ? name : LK_NAME;
    if (!lk_inittls(&S->tls_index)) goto err_tls;
    if (!lk_initevent(&S->event))   goto err_event;
    if (!lk_initlock(&S->lock))     goto err;
    if (!lkG_initroot(S, name))     goto err;
#ifdef LK_DEBUG_MEM
    (void)lk_initlock(&S->memlock);
#endif /* LK_DEBUG_MEM */
    lk_initmempool(S, &S->cleanups, sizeof(lk_Cleanup), 0);
    lk_initmempool(S, &S->signals, sizeof(lk_SignalNode), 0);
    lk_inittable(S, &S->preload);
    lk_inittable(S, &S->slots);
    lk_initbuffer(S, &S->path);
    lk_addstring(&S->path, LK_PATH);
    lk_setentry(&S->slots, S->root.slot.name)->value = &S->root.slot;
    return S;
err:
     lk_freeevent(S->event); 
err_event:
    lk_freetls(S->tls_index);
err_tls:
    free(S);
    return NULL;
}

LK_API void lk_close (lk_State *S) {
    lk_Context *ctx = lk_context(S);
    lk_Service *svr;
    if (ctx == NULL && S->status >= LK_STOPPING)
        lkG_delstate(S);
    if (ctx != NULL && (svr = ctx->current) != NULL) {
        unsigned status;
        lk_lock(S->lock);
        lk_lock(svr->lock);
        status = svr->status;
        svr->status = LK_STOPPING;
        if (status == LK_SLEEPING) {
            lkQ_enqueue(&S->active_services, svr);
            lk_signal(S->event);
        }
        lk_unlock(svr->lock);
        lk_unlock(S->lock);
    }
}

LK_API void lk_setpath (lk_State *S, const char *path) {
    lk_lock(S->lock);
    lk_addchar(&S->path, ';');
    lk_addstring(&S->path, path);
    lk_unlock(S->lock);
}

LK_API int lk_start (lk_State *S) {
    size_t i, count = 0;
    lkT_callinitGS(S, &S->root, NULL);
    lk_lock(S->lock);
    if (S->nthreads <= 0)
        S->nthreads = lkP_getcpucount();
    S->status = LK_WORKING;
    for (i = 0; i < S->nthreads; ++i) {
        if (!lk_initthread(&S->threads[i], lkP_worker, S))
            break;
    }
    count = S->nthreads = i;
    lk_unlock(S->lock);
    return count;
}

LK_API int lk_pcall (lk_State *S, lk_Handler *h, void *ud) {
    int ret = LK_OK;
    lk_Context ctx;
    lk_pushcontext(S, &ctx, NULL);
    lk_try(S, &ctx, ret = h(S, ud));
    lk_popcontext(S, &ctx);
    return ctx.status == LK_ERR ? LK_ERR : ret;
}

LK_API int lk_discard (lk_State *S) {
    lk_Context *ctx = lk_context(S);
    if (ctx == NULL) {
        fprintf(stderr, "unproected errors\n");
        abort();
    }
    if (ctx->cleanups != NULL) {
        lk_Cleanup *cleanups = ctx->cleanups;
        while (cleanups != NULL) {
            lk_Cleanup *next = cleanups->next;
            cleanups->h(S, cleanups->ud);
            cleanups = next;
        }
        lk_lock(S->lock);
        while (cleanups != NULL) {
            lk_Cleanup *next = cleanups->next;
            lk_poolfree(&S->cleanups, cleanups);
            cleanups = next;
        }
        lk_unlock(S->lock);
    }
    lk_throw(S, ctx);
    return LK_ERR;
}

LK_API int lk_addcleanup (lk_State *S, lk_Handler *h, void *ud) {
    lk_Context *ctx = lk_context(S);
    lk_Cleanup *cleanup;
    if (ctx == NULL)
        return LK_ERR;
    lk_lock(S->lock);
    cleanup = (lk_Cleanup*)lk_poolalloc(&S->cleanups);
    lk_unlock(S->lock);
    cleanup->h = h;
    cleanup->ud = ud;
    cleanup->next = ctx->cleanups;
    ctx->cleanups = cleanup;
    return LK_OK;
}

LK_API char *lk_getconfig (lk_State *S, const char *key) {
    lk_Entry *e;
    char *value = NULL;
    lk_lock(S->lock);
    e = lk_getentry(&S->config, key);
    if (e) value = lk_strdup(S, (char*)e->value);
    lk_unlock(S->lock);
    return value;
}

LK_API void lk_setconfig (lk_State *S, const char *key, const char *value) {
    lk_Entry *e;
    size_t valuesize = strlen(value);
    lk_lock(S->lock);
    e = lk_setentry(&S->config, key);
    if (e->value && strlen((char*)e->value) >= valuesize)
        memcpy(e->value, value, valuesize+1);
    else {
        size_t keysize = strlen(key);
        lk_Buffer B;
        lk_initbuffer(S, &B);
        lk_addlstring(&B, key, keysize);
        lk_addchar(&B, '\0');
        lk_addlstring(&B, value, valuesize);
        lk_addchar(&B, '\0');
        lk_free(S, (void*)e->key);
        e->key = lk_buffresult(&B);
        e->value = (void*)&e->key[keysize + 1];
    }
    lk_unlock(S->lock);
}

LK_API void lk_log(lk_State *S, const char *fmt, ...) {
    va_list l;
    va_start(l, fmt);
    lk_vlog(S, fmt, l);
    va_end(l);
}

LK_API void lk_vlog(lk_State *S, const char *fmt, va_list l) {
    lk_Slot *logger = S->logger;
    if (logger) {
        lk_Buffer B;
        lk_initbuffer(S, &B);
        lk_addvfstring(&B, fmt, l);
        lk_emitdata(logger, 0, 0, lk_buffer(&B), lk_buffsize(&B));
        lk_freebuffer(&B);
    }
}


LK_NS_END

#endif

/* win32cc: flags+='-Wextra -s -O3 -mdll -DLOKI_IMPLEMENTATION -std=c90 -pedantic -xc'
 * win32cc: output='loki.dll'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared -DLOKI_IMPLEMENTATION -xc'
 * unixcc: output='loki.so' */

