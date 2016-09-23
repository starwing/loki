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

#include <stdarg.h>
#include <stddef.h>

#define LK_OK      (0)
#define LK_WEAK    (1)
#define LK_ERR     (-1)
#define LK_TIMEOUT (-2)

#define LK_TYPE_MASK     ((unsigned)0x3FFFFFFF)
#define LK_RESPONSE_TYPE ((unsigned)0x80000000)

LK_NS_BEGIN


typedef struct lk_State    lk_State;
typedef struct lk_Service  lk_Service;
typedef struct lk_Slot     lk_Slot;
typedef struct lk_Signal   lk_Signal;
typedef struct lk_Source   lk_Source;

typedef int   lk_Handler (lk_State *S, lk_Slot *sender, lk_Signal *sig);
typedef void *lk_Allocf  (void *ud, void *ptr, size_t size, size_t osize);

struct lk_Source {
    lk_Service *service;
    lk_Handler *callback;
    lk_Handler *deletor;
    void       *ud;
    unsigned    refcount : 31;
    unsigned    force    : 1; /* call source even in req signal */
};

struct lk_Signal {
    lk_Source  *source;
    void       *data;
    unsigned    type   : 30;
    unsigned    isdata : 1;  /* data is lk_Data* */
    unsigned    isack  : 1;  /* this is a response signal */
};


/* global routines */

LK_API lk_State *lk_newstate (const char *name, lk_Allocf *allocf, void *ud);

LK_API void lk_waitclose (lk_State *S);

LK_API int lk_start (lk_State *S, int threads);

LK_API char *lk_getconfig (lk_State *S, const char *key);
LK_API void  lk_setconfig (lk_State *S, const char *key, const char *value);

LK_API int lk_log  (lk_State *S, const char *fmt, ...);
LK_API int lk_vlog (lk_State *S, const char *fmt, va_list l);

#define lk_str_(str) # str
#define lk_str(str) lk_str_(str)
#define lk_loc(str) __FILE__ ":" lk_str(__LINE__) ": " str


/* service routines */

LK_API lk_Service *lk_launch (lk_State *S, const char *name, lk_Handler *h, void *ud);
LK_API void        lk_close  (lk_State *S);

LK_API int lk_broadcast (lk_State *S, const char *slot, const lk_Signal *sig);

LK_API lk_Service *lk_self (lk_State *S);


/* message routines */

#define LK_SIGNAL             { NULL, NULL, 0, 0, 0 }
#define LK_RESPONSE           { NULL, NULL, 0, 0, 1 }
#define lk_serviceslot(slot)  ((lk_Slot*)lk_service((lk_Slot*)(slot)))

LK_API lk_Slot *lk_newslot (lk_State *S, const char *name, lk_Handler *h, void *data);
LK_API lk_Slot *lk_newpoll (lk_State *S, const char *name, lk_Handler *h, void *data);
LK_API lk_Slot *lk_slot    (lk_State *S, const char *name);
LK_API lk_Slot *lk_current (lk_State *S);

LK_API int lk_addlistener (lk_State *S, lk_Slot *slot, lk_Handler *h, void *ud);
LK_API int lk_dellistener (lk_State *S, lk_Slot *slot, lk_Handler *h, void *ud);

LK_API int lk_wait (lk_State *S, lk_Signal *sig, int waitms);

LK_API void lk_setcallback (lk_State *S, lk_Handler *h, void *ud);
LK_API int  lk_emit        (lk_Slot *slot, const lk_Signal *sig);
LK_API int  lk_emitstring  (lk_Slot *slot, unsigned type, const char *s);

LK_API const char *lk_name    (lk_Slot *slot);
LK_API lk_Service *lk_service (lk_Slot *slot);
LK_API lk_State   *lk_state   (lk_Slot *slot);

LK_API void *lk_data    (lk_Slot *slot);
LK_API void  lk_setdata (lk_Slot *slot, void *data);

LK_API lk_Handler *lk_slothandler    (lk_Slot *slot);
LK_API void        lk_setslothandler (lk_Slot *slot, lk_Handler *h);

LK_API lk_Handler *lk_refactor    (lk_Slot *slot);
LK_API void        lk_setrefactor (lk_Slot *slot, lk_Handler *h);


LK_NS_END

#endif /* loki_h */

/****************************************************************************/

#ifndef lk_utils_h
#define lk_utils_h

#include <string.h>

LK_NS_BEGIN


#define LK_MPOOLPAGESIZE 4096

/* memory management */

#ifndef LK_DEBUG_POOL
# ifdef _NDEBUG
#   define LK_DEBUG_POOL(x) /* nothing */
# else
#   define LK_DEBUG_POOL(x) x
# endif
#endif

typedef struct lk_MemPool {
    void  *pages;
    void  *freed;
    size_t size;
    LK_DEBUG_POOL(size_t allocated;)
} lk_MemPool;

LK_API void *lk_malloc    (lk_State *S, size_t size);
LK_API void *lk_realloc   (lk_State *S, void *ptr, size_t size, size_t osize);
LK_API void  lk_free      (lk_State *S, void *ptr, size_t osize);
LK_API void  lk_initpool  (lk_MemPool *mpool, size_t size);
LK_API void  lk_freepool  (lk_State *S, lk_MemPool *mpool);
LK_API void *lk_poolalloc (lk_State *S, lk_MemPool *mpool);
LK_API void  lk_poolfree  (lk_MemPool *mpool, void *obj);


/* string routines */

typedef struct lk_Data lk_Data;

LK_API lk_Data *lk_newdata (lk_State *S, size_t size);
LK_API size_t   lk_deldata (lk_State *S, lk_Data *data);
LK_API size_t   lk_usedata (lk_Data *data);

LK_API size_t lk_len    (lk_Data *data);
LK_API size_t lk_size   (lk_Data *data);
LK_API void   lk_setlen (lk_Data *data, size_t len);

LK_API lk_Data *lk_newstring   (lk_State *S, const char *s);
LK_API lk_Data *lk_newlstring  (lk_State *S, const char *s, size_t len);
LK_API lk_Data *lk_newvfstring (lk_State *S, const char *fmt, va_list l);
LK_API lk_Data *lk_newfstring  (lk_State *S, const char *fmt, ...);

LK_API int lk_emitdata (lk_Slot *slot, unsigned type, lk_Data *data);

LK_API char *lk_strcpy    (char *buff, const char *s, size_t len);
LK_API int   lk_vsnprintf (char *buff, size_t size, const char *fmt, va_list l);


/* table routines */

typedef struct lk_Entry {
    int         next;
    unsigned    hash;
    const char *key;
} lk_Entry;

typedef struct lk_Table {
    size_t    size;
    size_t    entry_size;
    size_t    lastfree;
    lk_Entry *hash;
} lk_Table;

typedef struct lk_PtrEntry { lk_Entry entry; void *data; } lk_PtrEntry;

#define lk_key(e) (((lk_Entry*)(e))->key)

LK_API void lk_inittable (lk_Table *t, size_t entry_size);
LK_API void lk_copytable (lk_State *S, lk_Table *t, const lk_Table *other);
LK_API void lk_freetable (lk_State *S, lk_Table *t);

LK_API size_t lk_resizetable (lk_State *S, lk_Table *t, size_t len);

LK_API lk_Entry *lk_gettable (lk_Table *t, const char *key);
LK_API lk_Entry *lk_settable (lk_State *S, lk_Table *t, const char *key);

LK_API int lk_nextentry (lk_Table *t, lk_Entry **pentry);


LK_NS_END

#endif /* lk_utils_h */


#ifndef lk_thread_h
#define lk_thread_h

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
# include <Windows.h>
# include <process.h>

typedef DWORD             lk_TlsKey;
typedef CRITICAL_SECTION  lk_Lock;
typedef HANDLE            lk_Event;
typedef HANDLE            lk_Thread;

#define lk_inittls(key)   ((*(key) = TlsAlloc()) != TLS_OUT_OF_INDEXES)
#define lk_freetls(key)   TlsFree(key)
#define lk_gettls(key)    TlsGetValue(key)
#define lk_settls(key, p) TlsSetValue((key),(p))

#define lk_initlock(lock) (InitializeCriticalSection(lock), 1)
#define lk_freelock(lock) DeleteCriticalSection(&(lock))
#define lk_lock(lock)     EnterCriticalSection(&(lock))
#define lk_unlock(lock)   LeaveCriticalSection(&(lock))

#define lk_initevent(evt) ((*(evt)=CreateEvent(NULL,FALSE,FALSE,NULL))!=NULL)
#define lk_freeevent(evt) CloseHandle(evt)
#define lk_signal(evt)    SetEvent(evt)

#define lk_waitthread(t)  (WaitForSingleObject((t), INFINITE),(void)lk_freethread(t))
#define lk_freethread(t)  ((void)CloseHandle(t))

#else /* POSIX systems */

#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <sys/time.h>

typedef pthread_key_t     lk_TlsKey;
typedef pthread_mutex_t   lk_Lock;
typedef pthread_cond_t    lk_Event;
typedef pthread_t         lk_Thread;

#define lk_inittls(key)   (pthread_key_create((key), NULL) == 0)
#define lk_freetls(key)   pthread_key_delete(key)
#define lk_gettls(key)    pthread_getspecific(key)
#define lk_settls(key, p) pthread_setspecific((key), (p))

#define lk_initlock(lock) (pthread_mutex_init(lock, NULL) == 0)
#define lk_freelock(lock) pthread_mutex_destroy(&(lock))
#define lk_lock(lock)     pthread_mutex_lock(&(lock))
#define lk_unlock(lock)   pthread_mutex_unlock(&(lock))

#define lk_initevent(evt) (pthread_cond_init((evt), NULL) == 0)
#define lk_freeevent(evt) pthread_cond_destroy(&(evt))
#define lk_signal(evt)    pthread_cond_signal(&(evt))

#define lk_waitthread(t)  pthread_join((t),NULL)
#define lk_freethread(t)  pthread_cancel(t)

#endif

LK_NS_BEGIN


typedef void lk_ThreadHandler (void *args);

LK_API int lk_initthread (lk_Thread *t, lk_ThreadHandler *h, void *ud);
LK_API int lk_cpucount   (void);

LK_API int lk_waitevent (lk_Event *evt, lk_Lock *lock, int waitms);


LK_NS_END

#endif /* lk_thread_h */


#ifndef lk_queue_h
#define lk_queue_h

#define lkQ_entry(T)        T *next
#define lkQ_type(T)         struct { T *first; T **plast; }

#define lkQ_init(h)         ((h)->plast = &(h)->first, (h)->first = NULL)
#define lkQ_clear(h, n)     ((n) = (h)->first, lkQ_init(h))
#define lkQ_empty(h)        ((h)->first == NULL)

#define lkQ_merge(h, nh)    ((void)((nh)->first && \
            ((void)(!(h)->first && ((h)->first = (nh)->first)), \
             ((h)->plast = (nh)->plast))))

#define lkQ_enqueue(h, n)   (*(h)->plast = (n), \
            (h)->plast = &(n)->next, (n)->next = NULL)
#define lkQ_dequeue(h, n)   ((n) = (h)->first, (void)((n) && (n)->next ? \
            ((h)->first = (n)->next) : lkQ_init(h)))

#endif /* lk_queue_h */


#ifndef lk_context_h
#define lk_context_h


#include <setjmp.h>

#if defined(__cplusplus) && !defined(LK_USE_LONGJMP)
#  define lk_throw(S,c) throw(c)
#  define lk_try(S,c,a) do { try { a; } catch(lk_Context *c) {} } while (0)
#  define lk_JmpBuf     int  /* dummy variable */

#elif _WIN32 /* ISO C handling with long jumps */
#  define lk_throw(S,c) longjmp((c)->b, 1)
#  define lk_try(S,c,a) do { if (setjmp((c)->b) == 0) { a; } } while (0)
#  define lk_JmpBuf     jmp_buf

#else /* in POSIX, try _longjmp/_setjmp (more efficient) */
#  define lk_throw(L,c) _longjmp((c)->b, 1)
#  define lk_try(L,c,a) do { if (_setjmp((c)->b) == 0) { a; } } while (0)
#  define lk_JmpBuf     jmp_buf
#endif

LK_NS_BEGIN


typedef int lk_DeferHandler (lk_State *S, void *ud);

typedef struct lk_Defer {
    lkQ_entry(struct lk_Defer);
    lk_DeferHandler *h;
    void         *ud;
} lk_Defer;

typedef struct lk_Context {
    struct lk_Context *prev;
    lk_State     *S;
    lk_Slot      *current;
    lk_Defer     *defers;
    lk_JmpBuf     b;
    int           retcode; /* error code */
} lk_Context;

LK_API lk_Context *lk_context (lk_State *S);

LK_API void lk_pushcontext (lk_State *S, lk_Context *ctx, lk_Slot *slot);
LK_API void lk_popcontext  (lk_State *S, lk_Context *ctx);

LK_API int lk_pcall   (lk_State *S, lk_DeferHandler *h, void *ud);
LK_API int lk_discard (lk_State *S);

LK_API int lk_defer (lk_State *S, lk_DeferHandler *h, void *ud);


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
#endif /* LK_NAME */

#define LK_MAX_THREADS     32
#define LK_MAX_NAMESIZE    32
#define LK_MAX_SLOTNAME    63
#define LK_HASHLIMIT       5
#define LK_MIN_HASHSIZE    8
#define LK_MAX_SIZET       (~(size_t)0u - 100)
#define LK_MAX_DATASIZE    ((size_t)(1<<24)-100)
#define LK_SMALLPIECE_LEN (sizeof(lk_Entry)*LK_MIN_HASHSIZE)

LK_NS_BEGIN


/* structures */

typedef struct lk_Poll lk_Poll;

typedef struct lk_SignalNode {
    lkQ_entry(struct lk_SignalNode);
    lk_Slot       *sender;
    lk_Slot       *recipient;
    lk_Signal      data;
} lk_SignalNode;

typedef struct lk_Listener {
    lk_Source   source;
    lk_Slot    *target;
    struct lk_Listener *next;
    struct lk_Listener *prev;
    struct lk_Listener *link;
} lk_Listener;

struct lk_Slot {
    char           name[LK_MAX_SLOTNAME];
    unsigned       is_poll      : 1;
    unsigned       is_svr       : 1;
    unsigned       weak         : 1;
    unsigned       dead         : 1;
    unsigned       active       : 1;
    unsigned       broadcast    : 1;
    unsigned       haslisteners : 1;
    unsigned       dellisteners : 1;
    lk_State      *S;
    lk_Service    *service;
    void          *data;
    lk_Handler    *handler;
    lk_Handler    *refactor;
    lk_Source     *source;
    lk_SignalNode *current;
    lk_Listener   *listeners;
    lkQ_entry(lk_Slot); /* all slots in same service */
};

struct lk_Poll {
    lk_Slot        slot;
    lk_Thread      thread;
    lk_Event       event;
    lk_Lock        lock;
    lkQ_type(lk_SignalNode) signals;
};

struct lk_Service {
    lk_Slot        slot;
    lk_Slot       *slots;
    lk_Table       listeners;
    lk_Lock        lock;
    unsigned       pending;
    lkQ_entry(lk_Service);
    lkQ_type(lk_SignalNode) signals;
};

struct lk_State {
    lk_Service     root;
    unsigned       nservices : 32;
    unsigned       nthreads  : 31;
    unsigned       start     : 1;
    unsigned       dead      : 1;
    lk_Table       slot_names;
    lk_Slot       *logger;
    lk_Lock        lock;

    lkQ_type(lk_Service) main_queue;
    lk_Event       queue_event;
    lk_Lock        queue_lock;

    lk_MemPool     services;
    lk_MemPool     slots;
    lk_MemPool     polls;
    lk_MemPool     defers;
    lk_MemPool     signals;
    lk_MemPool     sources;
    lk_MemPool     listeners;
    lk_MemPool     smallpieces;
    lk_Lock        pool_lock;

    lk_Table       config;
    lk_Lock        config_lock;

    lk_Allocf     *allocf;
    void          *alloc_ud;
    lk_TlsKey      tls_index;
    lk_Thread      threads[LK_MAX_THREADS];
};


/* memory management */

#ifndef va_copy
# ifdef __va_copy
#  define va_copy __va_copy
# else
#  define va_copy(a,b) (*(a)=*(b))
# endif
#endif

struct lk_Data {
    unsigned ref  : 16;
    unsigned size : 24;
    unsigned len  : 24;
};

LK_API size_t lk_len  (lk_Data *data) { return data-- ? data->len  : 0; }
LK_API size_t lk_size (lk_Data *data) { return data-- ? data->size : 0; }
LK_API size_t lk_usedata (lk_Data *data) { return data-- ? ++data->ref : 0; }

LK_API void lk_setlen(lk_Data *data, size_t len)
{ if (data--) data->len = len < data->size ? (unsigned)len : data->size; }

static void *lkM_outofmemory (void)
{ fprintf(stderr, "out of memory\n"); abort(); return NULL; }

LK_API lk_Data *lk_newstring (lk_State *S, const char *s)
{ return lk_newlstring(S, s, strlen(s)); }

LK_API int lk_vsnprintf (char *buff, size_t size, const char *fmt, va_list l) {
#if !defined(_WIN32) || defined(__MINGW32__)
    return vsnprintf(buff, size, fmt, l);
#else
    int count = -1;
    if (size != 0) {
        va_list nl;
        va_copy(nl, l);
        count = _vsnprintf_s(buff, size, _TRUNCATE, fmt, nl);
        va_end(nl);
    }
    if (count == -1) count = _vscprintf(fmt, l);
    return count;
#endif
}

LK_API char *lk_strcpy (char *buff, const char *s, size_t len) {
    size_t srclen = strlen(s);
    if (srclen >= len - 1) {
        memcpy(buff, s, len-1);
        buff[len-1] = '\0';
    }
    else {
        memcpy(buff, s, srclen);
        memset(buff+srclen, 0, len-srclen);
    }
    return buff;
}

LK_API void *lk_malloc (lk_State *S, size_t size) {
    void *newptr;
    if (size > LK_SMALLPIECE_LEN)
        newptr = S->allocf(S->alloc_ud, NULL, size, 0);
    else {
        lk_lock(S->pool_lock);
        newptr = lk_poolalloc(S, &S->smallpieces);
        lk_unlock(S->pool_lock);
    }
    if (newptr == NULL) return lkM_outofmemory();
    return newptr;
}

LK_API void *lk_realloc (lk_State *S, void *ptr, size_t size, size_t osize) {
    void *newptr;
    if (osize <= LK_SMALLPIECE_LEN && size <= LK_SMALLPIECE_LEN)
        return ptr;
    else if (osize > LK_SMALLPIECE_LEN) {
        newptr = S->allocf(S->alloc_ud, ptr, size, osize);
        if (newptr == NULL) return lkM_outofmemory();
    }
    else {
        newptr = lk_malloc(S, size);
        memcpy(newptr, ptr, osize);
        lk_free(S, ptr, osize);
    }
    return newptr;
}

LK_API void lk_free (lk_State *S, void *ptr, size_t osize) {
    void *newptr = NULL;
    if (ptr == NULL) return;
    if (osize > LK_SMALLPIECE_LEN)
        newptr = S->allocf(S->alloc_ud, ptr, 0, osize);
    else {
        lk_lock(S->pool_lock);
        lk_poolfree(&S->smallpieces, ptr);
        lk_unlock(S->pool_lock);
    }
    assert(newptr == NULL);
}

LK_API void lk_initpool (lk_MemPool *mpool, size_t size) {
    const size_t sp = sizeof(void*);
    assert(((sp - 1) & sp) == 0);
    mpool->pages = NULL;
    mpool->freed = NULL;
    if (size < sp)      size = sp;
    if (size % sp != 0) size = (size + sp - 1) & ~(sp - 1);
    mpool->size = size;
    LK_DEBUG_POOL(mpool->allocated = 0);
    assert(LK_MPOOLPAGESIZE / size > 2);
}

LK_API void lk_freepool (lk_State *S, lk_MemPool *mpool) {
    const size_t offset = LK_MPOOLPAGESIZE - sizeof(void*);
    LK_DEBUG_POOL(assert(mpool->allocated == 0));
    while (mpool->pages != NULL) {
        void *next = *(void**)((char*)mpool->pages + offset);
        lk_free(S, mpool->pages, LK_MPOOLPAGESIZE);
        mpool->pages = next;
    }
    lk_initpool(mpool, mpool->size);
}

LK_API void *lk_poolalloc (lk_State *S, lk_MemPool *mpool) {
    void *obj = mpool->freed;
    LK_DEBUG_POOL(++mpool->allocated);
    if (obj == NULL) {
        const size_t offset = LK_MPOOLPAGESIZE - sizeof(void*);
        void *end, *newpage = lk_malloc(S, LK_MPOOLPAGESIZE);
        *(void**)((char*)newpage + offset) = mpool->pages;
        mpool->pages = newpage;
        end = (char*)newpage + (offset/mpool->size-1)*mpool->size;
        while (end != newpage) {
            *(void**)end = mpool->freed;
            mpool->freed = end;
            end = (char*)end - mpool->size;
        }
        return end;
    }
    mpool->freed = *(void**)obj;
    return obj;
}

LK_API void lk_poolfree (lk_MemPool *mpool, void *obj) {
    LK_DEBUG_POOL(--mpool->allocated);
    *(void**)obj = mpool->freed;
    mpool->freed = obj;
}

LK_API lk_Data *lk_newdata (lk_State *S, size_t size) {
    size_t rawlen = sizeof(lk_Data) + size;
    lk_Data *data = (lk_Data*)lk_malloc(S, rawlen);
    assert(size < LK_MAX_DATASIZE);
    data->size = (unsigned)size;
    data->ref  = 0;
    data->len  = 0;
    if (rawlen <= LK_SMALLPIECE_LEN)
        data->size = LK_SMALLPIECE_LEN - sizeof(lk_Data);
    return data + 1;
}

LK_API size_t lk_deldata (lk_State *S, lk_Data *data) {
    if (data-- == NULL) return 0;
    if (data->ref > 1) { return --data->ref; }
    lk_free(S, data, data->size + sizeof(lk_Data));
    return 0;
}

LK_API lk_Data *lk_newlstring (lk_State *S, const char *s, size_t len) {
    lk_Data *data = lk_newdata(S, len+1);
    memcpy(data, s, len);
    ((char*)data)[len] = '\0';
    lk_setlen(data, len);
    return data;
}

LK_API lk_Data *lk_newvfstring (lk_State *S, const char *fmt, va_list l) {
    va_list nl;
    lk_Data *data;
    int len;
    va_copy(nl, l);
    len = lk_vsnprintf(NULL, 0, fmt, nl);
    va_end(nl);
    if (len <= 0) return NULL;
    data = lk_newdata(S, len+1);
    lk_vsnprintf((char*)data, len+1, fmt, l);
    lk_setlen(data, len);
    return data;
}

LK_API lk_Data *lk_newfstring (lk_State *S, const char *fmt, ...) {
    lk_Data *data;
    va_list l;
    va_start(l, fmt);
    data = lk_newvfstring(S, fmt, l);
    va_end(l);
    return data;
}


/* hashtable routines */

#define lk_offset(lhs, rhs) ((int)((char*)(lhs) - (char*)(rhs)))
#define lk_index(lhs, rhs)  ((lk_Entry*)((char*)(lhs) + (rhs)))

LK_API void lk_inittable (lk_Table *t, size_t entry_size)
{ memset(t, 0, sizeof(*t)); t->entry_size = entry_size; }

static size_t lkH_hashsize (lk_Table *t, size_t len) {
    size_t newsize = LK_MIN_HASHSIZE;
    const size_t maxsize = LK_MAX_SIZET/2/t->entry_size;
    while (newsize < maxsize && newsize < len)
        newsize <<= 1;
    assert(newsize < maxsize);
    return newsize < maxsize ? newsize : 0;
}

static size_t lkH_countsize (lk_Table *t) {
    size_t i, size = t->size * t->entry_size;
    size_t count = 0;
    for (i = 0; i < size; i += t->entry_size) {
        lk_Entry *e = lk_index(t->hash, i);
        if (e->key != NULL) ++count;
    }
    return count;
}

static lk_Entry *lkH_mainposition (lk_Table *t, unsigned hash) {
    assert((t->size & (t->size - 1)) == 0);
    return lk_index(t->hash, (hash & (t->size - 1))*t->entry_size);
}

static lk_Entry *lkH_newkey (lk_State *S, lk_Table *t, lk_Entry *entry) {
    lk_Entry *mp;
    if (entry->key == NULL ||
            (t->size == 0 && lk_resizetable(S, t, LK_MIN_HASHSIZE) == 0))
        return NULL;
redo:
    mp = lkH_mainposition(t, entry->hash);
    if (mp->key != NULL) {
        lk_Entry *f = NULL, *othern;
        while (t->lastfree > 0) {
            lk_Entry *e = lk_index(t->hash, t->lastfree -= t->entry_size);
            if (e->key == NULL && e->next == 0)  { f = e; break; }
        }
        if (f == NULL) {
            if (lk_resizetable(S, t, lkH_countsize(t)*2) == 0) return NULL;
            goto redo; /* return lkH_newkey(t, entry); */
        }
        othern = lkH_mainposition(t, mp->hash);
        if (othern != mp) {
            lk_Entry *next;
            while ((next = lk_index(othern, othern->next)) != mp)
                othern = next;
            othern->next = lk_offset(f, othern);
            memcpy(f, mp, t->entry_size);
            if (mp->next != 0) f->next += lk_offset(mp, f), mp->next = 0;
        }
        else {
            if (mp->next != 0) f->next = lk_offset(mp, f) + mp->next;
            else        assert(f->next == 0);
            mp->next = lk_offset(f, mp), mp = f;
        }
    }
    mp->key  = entry->key;
    mp->hash = entry->hash;
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

LK_API void lk_freetable (lk_State *S, lk_Table *t) {
    lk_free(S, t->hash, t->size*t->entry_size);
    lk_inittable(t, t->entry_size);
}

LK_API size_t lk_resizetable (lk_State *S, lk_Table *t, size_t len) {
    size_t i, size = t->size*t->entry_size;
    lk_Table nt = *t;
    nt.size = lkH_hashsize(t, len);
    if (nt.size == 0) return 0;
    nt.lastfree = nt.size*nt.entry_size;
    nt.hash = (lk_Entry*)lk_malloc(S, nt.lastfree);
    memset(nt.hash, 0, nt.lastfree);
    for (i = 0; i < size; i += t->entry_size) {
        lk_Entry *olde = lk_index(t->hash, i);
        lk_Entry *newe = lkH_newkey(S, &nt, olde);
        assert(newe != NULL);
        if (newe != NULL && t->entry_size > sizeof(lk_Entry))
            memcpy(newe + 1, olde + 1, t->entry_size - sizeof(lk_Entry));
    }
    lk_free(S, t->hash, size);
    *t = nt;
    return t->size;
}

LK_API void lk_copytable (lk_State *S, lk_Table *nt, const lk_Table *t) {
    size_t size = t->size*t->entry_size;
    *nt = *t;
    nt->hash = (lk_Entry*)lk_malloc(S, size);
    memcpy(nt->hash, t->hash, size);
}

LK_API lk_Entry *lk_gettable (lk_Table *t, const char *key) {
    unsigned hash;
    lk_Entry *e;
    if (t->size == 0 || key == NULL) return NULL;
    hash = lkH_calchash(key, strlen(key));
    e = lkH_mainposition(t, hash);
    for (;;) {
        int next = e->next;
        if (e->key && (key == e->key
                    || (e->hash == hash && strcmp(e->key, key) == 0)))
            return e;
        if (next == 0) return NULL;
        e = lk_index(e, next);
    }
}

LK_API lk_Entry *lk_settable (lk_State *S, lk_Table *t, const char *key) {
    lk_Entry e, *ret;
    if (key == NULL) return NULL;
    if ((ret = lk_gettable(t, key)) != NULL)
        return ret;
    e.key  = key;
    e.hash = lkH_calchash(key, strlen(key));
    if ((ret = lkH_newkey(S, t, &e)) == NULL)
        return NULL;
    if (t->entry_size > sizeof(lk_Entry))
        memset(ret + 1, 0, t->entry_size - sizeof(lk_Entry));
    return ret;
}

LK_API int lk_nextentry (lk_Table *t, lk_Entry **pentry) {
    const size_t size = t->size * t->entry_size;
    ptrdiff_t i = *pentry == NULL ? 0 :
        ((char*)*pentry - (char*)t->hash) + t->entry_size;
    assert(i >= 0 && (size_t)i <= size);
    for (; (size_t)i < size; i += t->entry_size) {
        lk_Entry *e = lk_index(t->hash, i);
        if (e->key != NULL) { *pentry = e; return 1; }
    }
    *pentry = NULL;
    return 0;
}


/* context routines */

LK_API lk_Context *lk_context (lk_State *S)
{ return S ? (lk_Context*)lk_gettls(S->tls_index) : NULL; }

static void lkC_calldefers (lk_State *S, lk_Context *ctx) {
    if (ctx->defers != NULL) {
        lk_Defer *defers = ctx->defers;
        while (defers != NULL) {
            lk_Defer *next = defers->next;
            defers->h(S, defers->ud);
            defers = next;
        }
        lk_lock(S->pool_lock);
        while (defers != NULL) {
            lk_Defer *next = defers->next;
            lk_poolfree(&S->defers, defers);
            defers = next;
        }
        lk_unlock(S->pool_lock);
    }
}

LK_API void lk_pushcontext (lk_State *S, lk_Context *ctx, lk_Slot *slot) {
    ctx->prev = lk_context(S);
    ctx->S = S;
    ctx->current  = slot;
    ctx->defers = NULL;
    ctx->retcode  = LK_OK;
    lk_settls(S->tls_index, ctx);
}

LK_API void lk_popcontext (lk_State *S, lk_Context *ctx) {
    if (ctx == NULL) return;
    lkC_calldefers(S, ctx);
    lk_settls(S->tls_index, ctx->prev);
}

LK_API int lk_pcall (lk_State *S, lk_DeferHandler *h, void *ud) {
    int ret = LK_OK;
    lk_Context ctx;
    lk_pushcontext(S, &ctx, NULL);
    lk_try(S, &ctx, ret = h(S, ud));
    lk_popcontext(S, &ctx);
    return ctx.retcode == LK_ERR ? LK_ERR : ret;
}

LK_API int lk_discard (lk_State *S) {
    lk_Context *ctx = lk_context(S);
    if (ctx == NULL) {
        fprintf(stderr, "unproected errors\n");
        abort();
    }
    lkC_calldefers(S, ctx);
    ctx->retcode = LK_ERR;
    lk_throw(S, ctx);
    return LK_ERR;
}

LK_API int lk_defer (lk_State *S, lk_DeferHandler *h, void *ud) {
    lk_Context *ctx = lk_context(S);
    lk_Defer *defer;
    if (ctx == NULL)
        return LK_ERR;
    lk_lock(S->pool_lock);
    defer = (lk_Defer*)lk_poolalloc(S, &S->defers);
    lk_unlock(S->pool_lock);
    defer->h = h;
    defer->ud = ud;
    defer->next = ctx->defers;
    ctx->defers = defer;
    return LK_OK;
}


/* thread routines */

typedef struct lk_ThreadContext {
    lk_ThreadHandler *h;
    void             *ud;
} lk_ThreadContext;

#ifdef _WIN32

static unsigned __stdcall lkT_worker (void *lpParameter) {
    lk_ThreadContext ctx = *(lk_ThreadContext*)lpParameter;
    free(lpParameter);
    ctx.h(ctx.ud);
    return 0;
}

LK_API int lk_initthread (lk_Thread *t, lk_ThreadHandler *h, void *ud) {
    lk_ThreadContext *ctx = (lk_ThreadContext*)malloc(sizeof(lk_ThreadContext));
    if (ctx == NULL) return 0;
    ctx->h  = h;
    ctx->ud = ud;
    *t = (HANDLE)_beginthreadex(NULL, 0, lkT_worker, ctx, 0, NULL);
    return *t != NULL;
}

LK_API int lk_waitevent (lk_Event *evt, lk_Lock *lock, int waitms) {
    DWORD ret;
    lk_unlock(*lock);
    ret = WaitForSingleObject(*evt, waitms < 0 ? INFINITE : (DWORD)waitms);
    lk_lock(*lock);
    return ret != WAIT_FAILED ? LK_OK : LK_ERR;
}

#else

#include <errno.h>

static void *lkT_worker (void *ud) {
    lk_ThreadContext ctx = *(lk_ThreadContext*)ud;
    free(ud);
    ctx.h(ctx.ud);
    return NULL;
}

LK_API int lk_initthread (lk_Thread *t, lk_ThreadHandler *h, void *ud) {
    lk_ThreadContext *ctx = (lk_ThreadContext*)malloc(sizeof(lk_ThreadContext));
    if (ctx == NULL) return 0;
    ctx->h  = h;
    ctx->ud = ud;
    return pthread_create(t, NULL, lkT_worker, ctx) == 0;
}

LK_API int lk_waitevent (lk_Event *evt, lk_Lock *lock, int waitms) {
    int ret;
    if (waitms < 0)
        ret = pthread_cond_wait(evt, lock);
    else {
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
        ret = pthread_cond_timedwait(evt, lock, &ts);
    }
    return ret == 0 || ret == ETIMEDOUT ? LK_OK : LK_ERR;
}

#endif


/* slot/poll routines */

#define lkP_isdead(obj) (((lk_Slot*)(obj))->dead)

LK_API const char *lk_name    (lk_Slot *slot) { return slot ? slot->name    : NULL; }
LK_API lk_Service *lk_service (lk_Slot *slot) { return slot ? slot->service : NULL; }
LK_API lk_State   *lk_state   (lk_Slot *slot) { return slot ? slot->S       : NULL; }
LK_API void       *lk_data    (lk_Slot *slot) { return slot ? slot->data    : NULL; }

LK_API lk_Handler *lk_slothandler (lk_Slot *slot) { return slot ? slot->handler : NULL; }
LK_API lk_Handler *lk_refactor    (lk_Slot *slot) { return slot ? slot->refactor : NULL; }

LK_API lk_Slot *lk_current (lk_State *S)
{ lk_Context *ctx = lk_context(S); return ctx ? ctx->current : &S->root.slot; }

LK_API void lk_setdata (lk_Slot *slot, void *data)
{ if (slot) slot->data = data; }

LK_API void lk_setslothandler (lk_Slot *slot, lk_Handler *h)
{ if (slot) slot->handler = h; }

LK_API void lk_setrefactor (lk_Slot *slot, lk_Handler *h)
{ if (slot) slot->refactor = h; }

static void lkP_name (char *buff, const char *svr, const char *name) {
    size_t svrlen = strlen(svr);
    assert(svrlen < LK_MAX_NAMESIZE);
    memcpy(buff, svr, svrlen); buff += svrlen;
    if (name != NULL) {
        size_t namelen = strlen(name);
        *buff++ = '.';
        assert(namelen < LK_MAX_NAMESIZE);
        memcpy(buff, name, namelen); buff += namelen;
    }
    *buff = '\0';
}

static lk_Slot *lkP_new (lk_State *S, lk_MemPool *pool, lk_Service *svr, const char *name) {
    lk_Slot *slot = NULL;
    lk_lock(S->pool_lock);
    slot = (lk_Slot*)lk_poolalloc(S, pool);
    lk_unlock(S->pool_lock);
    memset(slot, 0, pool->size);
    lkP_name(slot->name, (const char*)svr, name);
    slot->S       = S;
    slot->service = svr;
    return slot;
}

static lk_Slot *lkP_register (lk_State *S, lk_Slot *slot) {
    lk_Entry *e = lk_settable(S, &S->slot_names, slot->name);
    if (S->dead || (lk_Slot*)e->key != slot) {
        if (&slot->service->slot == slot)
            lk_freelock(slot->service->lock);
        lk_lock(S->pool_lock);
        if (slot->is_svr)       lk_poolfree(&S->services, slot);
        else if (slot->is_poll) lk_poolfree(&S->polls, slot);
        else                    lk_poolfree(&S->slots, slot);
        lk_unlock(S->pool_lock);
        return NULL;
    }
    return slot;
}

static int lkP_delpoll (lk_State *S, lk_Poll *poll) {
    if (!lkP_isdead(poll)) {
        lk_lock(poll->lock);
        lkP_isdead(poll) = 1;
        lk_signal(poll->event);
        lk_unlock(poll->lock);
        lk_waitthread(poll->thread);
    }
    if (poll->slot.service->pending != 0)
        return LK_ERR;
    lk_freeevent(poll->event);
    lk_freelock(poll->lock);
    lk_lock(S->pool_lock);
    lk_poolfree(&S->polls, poll);
    lk_unlock(S->pool_lock);
    return LK_OK;
}

static void lkP_poller (void *ud) {
    lk_Context ctx;
    lk_Signal sig = LK_SIGNAL;
    lk_Poll  *poll = (lk_Poll*)ud;
    lk_State *S    = poll->slot.S;
    lk_pushcontext(S, &ctx, &poll->slot);
    lk_try(S, &ctx, poll->slot.handler(S, &poll->slot, &sig));
    lkP_isdead(poll) = 1;
    while (lk_wait(S, &sig, 0) == LK_OK)
        ;
    lk_popcontext(S, &ctx);
}

static int lkP_startpoll (lk_Poll *poll) {
    lk_State *S = poll->slot.S;
    lkQ_init(&poll->signals);
    if (!lk_initlock(&poll->lock))   goto err_lock;
    if (!lk_initevent(&poll->event)) goto err_event;
    if (!lk_initthread(&poll->thread, lkP_poller, poll)) {
        lk_freeevent(poll->event);
err_event:
        lk_freelock(poll->lock);
err_lock:
        lk_lock(S->pool_lock);
        lk_poolfree(&S->polls, poll);
        lk_unlock(S->pool_lock);
        return LK_ERR;
    }
    return LK_OK;
}

static lk_Slot *lkP_findslotG (lk_State *S, const char *name) {
    lk_Slot *slot = NULL;
    lk_Entry *e;
    lk_lock(S->lock);
    e = lk_gettable(&S->slot_names, name);
    if (e != NULL) slot = (lk_Slot*)e->key;
    lk_unlock(S->lock);
    return slot;
}

static int lkP_check (lk_State *S, const char *tag, const char *name) {
    if (name == NULL)
        lk_log(S, "E[%s]" lk_loc("slot name required"));
    else if (strlen(name) >= LK_MAX_NAMESIZE)
        lk_log(S, "E[%s]" lk_loc("slot name '%s' too long"), tag, name);
    else if (!lkP_isdead(lk_self(S)))
        return LK_OK;
    return LK_ERR;
}

LK_API lk_Slot *lk_newslot (lk_State *S, const char *name, lk_Handler *h, void *data) {
    lk_Service *svr = lk_self(S);
    lk_Slot *slot = NULL;
    if (S == NULL || svr == NULL || lkP_check(S, "newslot", name) != LK_OK)
        return NULL;
    slot = lkP_new(S, &S->slots, svr, name);
    slot->handler = h;
    slot->data    = data;
    lk_lock(S->lock);
    if ((slot = lkP_register(S, slot)) != NULL) {
        slot->next = svr->slots;
        svr->slots = slot;
    }
    lk_unlock(S->lock);
    if (slot == NULL)
        lk_log(S, "E[newslot]", lk_loc("slot '%s' exists"), name);
    return slot;
}

LK_API lk_Slot *lk_newpoll (lk_State *S, const char *name, lk_Handler *h, void *data) {
    lk_Service *svr = lk_self(S);
    lk_Poll *poll;
    if (S == NULL || svr == NULL || lkP_check(S, "newpoll", name) != LK_OK)
        return NULL;
    poll = (lk_Poll*)lkP_new(S, &S->polls, svr, name);
    poll->slot.is_poll = 1;
    poll->slot.handler = h;
    poll->slot.data    = data;
    if (lkP_startpoll(poll) != LK_OK) return NULL;
    lk_lock(S->lock);
    if ((poll = (lk_Poll*)lkP_register(S, &poll->slot)) != NULL) {
        poll->slot.next = svr->slots;
        svr->slots = &poll->slot;
    }
    lk_unlock(S->lock);
    if (poll == NULL) {
        lk_log(S, "E[newpoll]", lk_loc("poll '%s' exists"), name);
        return NULL;
    }
    return &poll->slot;
}

LK_API lk_Slot *lk_slot (lk_State *S, const char *name) {
    lk_Service *svr = lk_self(S);
    lk_Slot *slot = NULL;
    if (S == NULL || svr == NULL || lkP_check(S, "slot", name) != LK_OK)
        return NULL;
    if (strchr(name, '.') == NULL) {
        char qname[LK_MAX_NAMESIZE];
        lkP_name(qname, svr->slot.name, name);
        slot = lkP_findslotG(S, qname);
    }
    else if (name[0] == '.') {
        char qname[LK_MAX_NAMESIZE];
        lkP_name(qname, S->root.slot.name, name + 1);
        slot = lkP_findslotG(S, qname);
    }
    if (slot == NULL)
        slot = lkP_findslotG(S, name);
    if (slot == NULL)
        lk_log(S, "E[slot]" lk_loc("slot '%s' not exists"), name);
    return slot;
}


/* emit signal */

static void lkS_active    (lk_State *S, lk_Service *svr);
static int  lkL_broadcast (lk_Slot *slot, lk_Signal *sig);

LK_API int lk_emitstring (lk_Slot *slot, unsigned type, const char *s)
{ return slot ? lk_emitdata(slot, type, lk_newstring(slot->S, s)) : LK_ERR; }

static int lkE_srcdeletor (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    (void)sender;
    lk_lock(S->pool_lock);
    lk_poolfree(&S->sources, sig->source);
    lk_unlock(S->pool_lock);
    return LK_OK;
}

static int lkE_checkemit (lk_State *S, lk_Slot *sender, lk_Slot *recipient) {
    lk_Service *from, *to;
    if (sender == NULL || recipient == NULL) return LK_ERR;
    from = sender->service, to = recipient->service;
    if (S->dead)
        return LK_ERR; /*lk_log(S, "E[emit]" lk_loc("host stopped"));*/
    else if (lkP_isdead(from) || recipient != S->logger)
        return LK_OK; /* lk_log(S, "E[emit]" lk_loc("source service stopped")); */
    else if (lkP_isdead(to) && recipient != S->logger)
        lk_log(S, "E[emit]" lk_loc("destination service stopped"));
    else if (recipient->is_poll && lkP_isdead(recipient))
        return LK_ERR;
    else
        return LK_OK;
    return LK_ERR;
}

static void lkE_delsource (lk_State *S, lk_Source *src) {
    lk_Signal sig = LK_SIGNAL;
    unsigned refcount;
    sig.source = src;
    lk_lock(src->service->lock);
    refcount = src->refcount = (src->refcount > 1 ? src->refcount-1 : 0);
    lk_unlock(src->service->lock);
    if (refcount == 0 && src->deletor != NULL) {
        lk_Context ctx;
        lk_pushcontext(S, &ctx, &src->service->slot);
        lk_try(svr->S, &ctx, src->deletor(S, NULL, &sig));
        lk_popcontext(S, &ctx);
    }
}

static lk_SignalNode *lkE_newsignal (lk_State *S, lk_Slot *slot, const lk_Signal *sig) {
    lk_Slot *sender = lk_current(S);
    lk_SignalNode *node;
    lk_Source *src;
    if (sig == NULL || lkE_checkemit(S, sender, slot) != LK_OK) return NULL;
    lk_lock(S->pool_lock);
    node = (lk_SignalNode*)lk_poolalloc(S, &S->signals);
    lk_unlock(S->pool_lock);
    node->recipient = slot;
    node->sender    = sender;
    node->data      = *sig;
    lk_lock(sender->service->lock);
    ++sender->service->pending;
    lk_unlock(sender->service->lock);
    if (node->data.source == NULL && sender->source != NULL) {
        node->data.source = sender->source;
        sender->source = NULL;
    }
    if ((src = node->data.source) != NULL) {
        lk_lock(src->service->lock);
        ++src->service->pending;
        ++src->refcount;
        lk_unlock(src->service->lock);
    }
    if (node->data.isdata) lk_usedata((lk_Data*)node->data.data);
    return node;
}

static void lkE_delsignal (lk_State *S, lk_SignalNode *node) {
    lk_Source *src = node->data.source;
    lk_Service *svr;
    if (node->data.isdata) lk_deldata(S, (lk_Data*)node->data.data);
    if (src != NULL && (svr = src->service) != NULL) {
        lkE_delsource(S, src);
        lk_lock(svr->lock);
        if (--svr->pending == 0) lkS_active(S, svr);
        lk_unlock(svr->lock);
    }
    if ((svr = node->sender->service) != NULL) {
        lk_lock(svr->lock);
        if (--svr->pending == 0) lkS_active(S, svr);
        lk_unlock(svr->lock);
    }
    lk_lock(S->pool_lock);
    lk_poolfree(&S->signals, node);
    lk_unlock(S->pool_lock);
}

static int lkE_emitS (lk_Slot *slot, lk_SignalNode *node) {
    lk_Service *svr = slot->service;
    int ret = LK_ERR;
    lk_lock(svr->lock);
    if (!lkP_isdead(svr)) {
        lk_Poll *poll = (lk_Poll*)slot;
        if (!slot->is_poll) {
            lkQ_enqueue(&svr->signals, node);
            lkS_active(svr->slot.S, svr);
            ret = LK_OK;
        }
        else if (!lkP_isdead(slot)) {
            lk_lock(poll->lock);
            lkQ_enqueue(&poll->signals, node);
            lk_signal(poll->event);
            lk_unlock(poll->lock);
            ret = LK_OK;
        }
    }
    lk_unlock(svr->lock);
    return ret;
}

LK_API void lk_setcallback (lk_State *S, lk_Handler *h, void *ud) {
    lk_Slot *slot = lk_current(S);
    lk_Source *src;
    if (slot == NULL) return;
    if (slot->source != NULL)
        lkE_delsource(S, slot->source);
    lk_lock(S->pool_lock);
    src = (lk_Source*)lk_poolalloc(S, &S->sources);
    lk_unlock(S->pool_lock);
    memset(src, 0, sizeof(*src));
    src->service  = lk_self(S);
    src->callback = h;
    src->deletor  = lkE_srcdeletor;
    src->ud       = ud;
    slot->source  = src;
}

LK_API int lk_emit (lk_Slot *slot, const lk_Signal *sig) {
    lk_State *S = slot ? slot->S : NULL;
    lk_SignalNode *node = lkE_newsignal(S, slot, sig);
    if (node == NULL) return LK_ERR;
    if (lkE_emitS(slot, node) != LK_OK) {
        lkE_delsignal(S, node);
        return LK_ERR;
    }
    return LK_OK;
}

LK_API int lk_broadcast (lk_State *S, const char *name, const lk_Signal *sig) {
    lk_Table t;
    lk_Entry *e = NULL;
    lk_Slot *current = lk_current(S);
    lk_Source *src = current->source;
    int count = 0;
    lk_lock(S->lock);
    lk_copytable(S, &t, &S->slot_names);
    lk_unlock(S->lock);
    if (src && sig) ++src->refcount;
    while (lk_nextentry(&t, &e)) {
        lk_Slot *slot = (lk_Slot*)e->key;
        const char *slotname;
        if ((name == NULL) == (!slot->is_svr)) continue;
        if (name && ((slotname = strchr(slot->name, '.')) == NULL
                    || strcmp(slotname+1, name) != 0))
            continue;
        current->source = src;
        if (sig == NULL || lk_emit(slot, sig) == LK_OK) ++count;
    }
    lk_freetable(S, &t);
    if (src && sig) { lkE_delsource(S, src); current->source = NULL; }
    return count;
}

LK_API int lk_emitdata (lk_Slot *slot, unsigned type, lk_Data *data) {
    lk_Signal sig = LK_SIGNAL;
    if (slot == NULL) return LK_ERR;
    sig.type   = type & LK_TYPE_MASK;
    sig.isdata = 1;
    sig.isack  = (type & LK_RESPONSE_TYPE) != 0;
    sig.data   = data;
    return lk_emit(slot, &sig);
}

LK_API int lk_wait (lk_State *S, lk_Signal* sig, int waitms) {
    lk_Poll *poll = (lk_Poll*)lk_current(S);
    lk_SignalNode *node = NULL;
    if (poll == NULL || !poll->slot.is_poll) return LK_ERR;
    if (poll->slot.current) {
        if (poll->slot.haslisteners)
            lkL_broadcast(&poll->slot, &poll->slot.current->data);
        lkE_delsignal(S, poll->slot.current);
        poll->slot.current = NULL;
    }
    lk_lock(poll->lock);
    if (sig) lkQ_dequeue(&poll->signals, node);
    while (node == NULL && !lkP_isdead(poll)) {
        int ret = lk_waitevent(&poll->event, &poll->lock, waitms);
        if (sig) lkQ_dequeue(&poll->signals, node);
        if (ret != LK_OK || waitms >= 0) break;
    }
    lk_unlock(poll->lock);
    if (node == NULL)
        return lkP_isdead(poll) ? LK_ERR : LK_TIMEOUT;
    poll->slot.current = node;
    if (sig) *sig = node->data;
    return LK_OK;
}


/* listeners routines */

static void lkL_link (lk_Listener **pp, lk_Listener *node) {
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

static void lkL_unlink(lk_Listener **pp, lk_Listener *node) {
    if (*pp == node) *pp = node == node->next ? NULL : node->next;
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

static lk_Listener *lkL_merge (lk_Listener *oldh, lk_Listener *newh) {
    lk_Listener *last = newh->prev;
    oldh->prev->next = last->next;
    last->next->prev = oldh->prev;
    oldh->prev = last;
    last->prev = oldh;
    return oldh;
}

static int lkL_next (lk_Listener *h, lk_Listener **pnode, lk_Listener **pnext) {
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

static int lkL_srcdeletor (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_Listener *node = (lk_Listener*)sig->source;
    if ((sender = node->target)->broadcast) {
        node->source.callback = NULL;
        sender->dellisteners = 1;
    }
    else {
        lk_lock(sender->service->lock);
        lkL_unlink(&sender->listeners, node);
        if (sender->listeners == NULL) sender->haslisteners = 0;
        lk_unlock(sender->service->lock);
        lk_lock(S->pool_lock);
        lk_poolfree(&S->listeners, node);
        lk_unlock(S->pool_lock);
    }
    return LK_OK;
}

static lk_Listener *lkL_newlistener (lk_Service *svr, lk_Slot *slot) {
    lk_State *S = svr->slot.S;
    lk_Listener *node;
    lk_lock(S->pool_lock);
    node = (lk_Listener*)lk_poolalloc(S, &S->listeners);
    lk_unlock(S->pool_lock);
    memset(node, 0, sizeof(*node));
    node->target  = slot;
    node->source.service = svr;
    node->source.deletor = lkL_srcdeletor;
    node->source.refcount = 1;
    return node;
}

static int lkL_register (lk_State *S, lk_Service *svr, lk_Listener *node) {
    lk_Slot *slot = node->target;
    lk_PtrEntry *e = (lk_PtrEntry*)lk_settable(S, &svr->listeners, slot->name);
    if (e == NULL) return LK_ERR;
    node->link = (lk_Listener*)e->data;
    e->data = node;
    return LK_OK;
}

static void lkL_sweep (lk_Slot *slot) {
    lk_State *S = slot->S;
    lk_Listener *node = NULL, *next = NULL;
    /* XXX */
    while (lkL_next(slot->listeners, &node, &next)) {
        if (node->source.callback == NULL)
            lkE_delsource(S, &node->source);
    }
    slot->dellisteners = 0;
}

static int lkL_broadcast (lk_Slot *slot, lk_Signal *sig) {
    lk_Source *src = sig->source;
    lk_Listener *h, *node = NULL;
    lk_lock(slot->service->lock);
    h = slot->listeners;
    slot->listeners = NULL;
    slot->broadcast = 1;
    lk_unlock(slot->service->lock);
    while (lkL_next(h, &node, NULL)) {
        if (node->source.callback != NULL) {
            sig->source = &node->source;
            lk_emit(&sig->source->service->slot, sig);
        }
    }
    lk_lock(slot->service->lock);
    slot->broadcast = 0;
    if (slot->listeners) slot->listeners = lkL_merge(h, slot->listeners);
    if (slot->dellisteners) lkL_sweep(slot);
    lk_unlock(slot->service->lock);
    sig->source = src;
    return LK_OK;
}

static void lkL_clearslot (lk_State *S, lk_Slot *slot) {
    lk_Listener *h, *node = NULL, *next;
    lk_Context ctx;
    assert(lkP_isdead(slot->service) || slot->service->slot.weak);
    lk_lock(slot->service->lock);
    h = slot->listeners;
    slot->listeners = NULL;
    lk_unlock(slot->service->lock);
    lk_pushcontext(S, &ctx, NULL);
    while (lkL_next(h, &node, &next)) {
        ctx.current = &node->source.service->slot;
        lk_dellistener(S, slot, node->source.callback, node->source.ud);
    }
    lk_popcontext(S, &ctx);
}

static void lkL_clearlisteners (lk_State *S, lk_Service *svr) {
    lk_PtrEntry *e = NULL;
    lk_Slot *slot;
    assert(lkP_isdead(svr) || svr->slot.weak);
    for (slot = svr->slots; slot != NULL; slot = slot->next)
        lkL_clearslot(S, slot);
    while (lk_nextentry(&svr->listeners, (lk_Entry**)&e)) {
        lk_Listener *node = (lk_Listener*)e->data;
        e->data = NULL;
        while (node != NULL) {
            lk_Listener *next = node->link;
            lkE_delsource(S, &node->source);
            node = next;
        }
    }
    lk_freetable(S, &svr->listeners);
}

LK_API int lk_addlistener (lk_State *S, lk_Slot *slot, lk_Handler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    lk_Listener *node;
    if (svr == NULL || slot == NULL
            || lkP_isdead(svr) || lkP_isdead(slot->service))
        return LK_ERR;
    node = lkL_newlistener(svr, slot);
    node->source.callback = h;
    node->source.ud = ud;
    lk_lock(svr->lock);
    if (lkL_register(S, svr, node) != LK_OK) {
        lk_lock(S->pool_lock);
        lk_poolfree(&S->listeners, node);
        lk_unlock(S->pool_lock);
        node = NULL;
    }
    lk_unlock(svr->lock);
    if (node) {
        lk_lock(slot->service->lock);
        lkL_link(&slot->listeners, node);
        slot->haslisteners = 1;
        lk_unlock(slot->service->lock);
    }
    return node ? LK_OK : LK_ERR;
}

LK_API int lk_dellistener (lk_State *S, lk_Slot *slot, lk_Handler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    lk_Listener **pp;
    lk_PtrEntry *e;
    if (svr == NULL || slot == NULL) return LK_ERR;
    lk_lock(svr->lock);
    e = (lk_PtrEntry*)lk_gettable(&svr->listeners, slot->name);
    for (pp = (lk_Listener**)&e->data; *pp != NULL; pp = &(*pp)->link)
        if ((*pp)->source.callback == h && (*pp)->source.ud == ud)
            break;
    lk_unlock(svr->lock);
    if (*pp != NULL) {
        *pp = (*pp)->link;
        lkE_delsource(slot->S, &(*pp)->source);
    }
    return LK_OK;
}


/* service routines */

LK_API lk_Service *lk_self (lk_State *S)
{ lk_Slot *slot = lk_current(S); return slot ? slot->service : NULL; }

static int lkS_initsevice (lk_State *S, lk_Service *svr) {
    svr->slot.active  = 1;
    svr->slot.is_svr  = 1;
    svr->slot.service = svr;
    svr->slots = &svr->slot;
    lkQ_init(&svr->signals);
    lk_inittable(&svr->listeners, sizeof(lk_PtrEntry));
    if (!lk_initlock(&svr->lock)) {
        if (svr != &S->root) {
            lk_lock(S->pool_lock);
            lk_poolfree(&S->services, svr);
            lk_unlock(S->pool_lock);
        }
        return LK_ERR;
    }
    return LK_OK;
}

static void lkS_freepolls (lk_State *S, lk_Service *svr) {
    lk_Slot *slot, **pslots = &svr->slots;
    while (*pslots != NULL) {
        if ((slot = *pslots)->is_poll
                && lkP_delpoll(S, (lk_Poll*)slot) == LK_OK)
            *pslots = slot->next;
        else
            pslots = &slot->next;
    }
}

static void lkS_freeslotsG (lk_State *S, lk_Service *svr) {
    lk_Slot **pslots, *slot;
    lk_lock(S->lock);
    for (slot = svr->slots; slot != NULL; slot = slot->next) {
        lk_Entry *e = lk_gettable(&S->slot_names, slot->name);
        assert(e && (lk_Slot*)e->key == slot);
        if (e) e->key = NULL;
    }
    lk_unlock(S->lock);
    lk_lock(S->pool_lock);
    for (pslots = &svr->slots; *pslots != NULL;) {
        if ((slot = *pslots)->is_svr || slot->is_poll)
            pslots = &slot->next;
        else {
            *pslots = slot->next;
            lk_poolfree(&S->slots, slot);
        }
    }
    lk_unlock(S->pool_lock);
}

static void lkS_checkstate (lk_State *S, lk_Service *svr) {
    lk_lock(S->lock);
    if (!svr->slot.weak) --S->nservices;
    if (S->nservices == 0) {
        S->dead = 1;
        lk_lock(S->queue_lock);
        lk_signal(S->queue_event);
        lk_unlock(S->queue_lock);
    }
    lk_unlock(S->lock);
}

static int lkS_delserviceG (lk_State *S, lk_Service *svr) {
    lkL_clearlisteners(S, svr);
    if (svr->slot.handler) {
        lk_Context ctx;
        lk_pushcontext(S, &ctx, &svr->slot);
        lk_try(S, &ctx, svr->slot.handler(S, &svr->slot, NULL));
        lk_popcontext(S, &ctx);
        svr->slot.handler = NULL;
    }
    lkS_freepolls(S, svr);
    if (svr->pending != 0) return LK_ERR;
    lkS_freeslotsG(S, svr);
    lkS_checkstate(S, svr);
    lk_freelock(svr->lock);
    assert(lkQ_empty(&svr->signals));
    if (svr != &S->root) {
        lk_lock(S->pool_lock);
        lk_poolfree(&S->services, svr);
        lk_unlock(S->pool_lock);
    }
    return LK_OK;
}

static void lkS_active (lk_State *S, lk_Service *svr) {
    if (!svr->slot.active) {
        svr->slot.active = 1;
        lk_lock(S->queue_lock);
        lkQ_enqueue(&S->main_queue, svr);
        lk_signal(S->queue_event);
        lk_unlock(S->queue_lock);
    }
}

static void lkS_callslot (lk_State *S, lk_SignalNode *node, lk_Context *ctx) {
    lk_Slot   *sender = node->sender;
    lk_Slot   *slot   = node->recipient;
    lk_Source *src    = node->data.source;
    int ret = LK_ERR, isack = node->data.isack;
    ctx->current  = slot;
    slot->current = node;
    if (isack) {
        lk_Handler *const refactor = sender->refactor ?
            sender->refactor : sender->service->slot.refactor;
        if (refactor != NULL)
            lk_try(S, ctx, ret = refactor(S, sender, &node->data));
    }
    if (ret == LK_ERR && src && src->callback
            && (isack || src->force) && src->service == slot->service)
        lk_try(S, ctx, ret = src->callback(S, sender, &node->data));
    if (ret == LK_ERR && slot->handler != NULL)
        lk_try(S, ctx, slot->handler(S, sender, &node->data));
    slot->current = NULL;
    if (slot->haslisteners) lkL_broadcast(slot, &node->data);
    lkE_delsignal(S, node);
}

static void lkS_callslotsS (lk_State *S, lk_Service *svr) {
    lk_Context ctx;
    lk_SignalNode *node;

    /* fetch all signal */
    lk_lock(svr->lock);
    lkQ_clear(&svr->signals, node);
    lk_unlock(svr->lock);

    /* call signal handler */
    lk_pushcontext(S, &ctx, &svr->slot);
    while (node != NULL) {
        lk_SignalNode *next = node->next;
        lkS_callslot(S, node, &ctx);
        node = next;
    }
    lk_popcontext(S, &ctx);
}

static void lkS_dispatchGS (lk_State *S, lk_Service *svr) {
    int should_delete = 0;
    assert(svr->slot.active);
    lkS_callslotsS(S, svr);

    lk_lock(svr->lock);
    if (!lkQ_empty(&svr->signals)) {
        lk_lock(S->queue_lock);
        lkQ_enqueue(&S->main_queue, svr);
        lk_unlock(S->queue_lock);
    }
    else if (lkP_isdead(svr) && svr->pending == 0)
        should_delete = 1;
    else
        svr->slot.active = 0;
    lk_unlock(svr->lock);

    if (should_delete && lkS_delserviceG(S, svr) != LK_OK)
        svr->slot.active = 0;
}

static int lkS_check (lk_State *S, const char *name, lk_Handler *h) {
    if (S == NULL || name == NULL || h == NULL)
        return LK_ERR;
    if (strlen(name) >= LK_MAX_NAMESIZE) {
        lk_log(S, "E[launch]" lk_loc("serivce name '%s' too long"), name);
        return LK_ERR;
    }
    return S->dead ? LK_ERR : LK_OK;
}

static int lkS_callinit (lk_State *S, lk_Service *svr) {
    lk_Context ctx;
    int ret = LK_ERR;
    lk_Handler *h = svr->slot.handler;
    lk_pushcontext(S, &ctx, &svr->slot);
    lk_try(S, &ctx, ret = h(S, NULL, NULL));
    lk_popcontext(S, &ctx);
    if (ret < LK_OK || lkP_isdead(svr)) {
        lk_log(S, "E[launch]" lk_loc("serivce '%s' initialize failure"),
                svr->slot.name);
        lkS_delserviceG(S, svr);
        return LK_ERR;
    }
    lk_lock(S->lock);
    ++S->nservices;
    if (S->logger == NULL && strcmp(svr->slot.name, "log") == 0)
        S->logger = &svr->slot;
    if (ret == LK_WEAK) {
        svr->slot.weak = 1;
        --S->nservices;
    }
    lk_unlock(S->lock);
    return LK_OK;
}

static lk_Service *lkS_callinitGS (lk_State *S, lk_Service *svr, lk_Handler *h, void *data) {
    lk_Signal sig = LK_RESPONSE;
    svr->slot.handler = h;
    svr->slot.data    = data;
    if (h && lkS_callinit(S, svr) != LK_OK)
        return NULL;
    sig.data = svr;
    lk_broadcast(S, "launch", &sig);
    lk_lock(svr->lock);
    svr->slot.active = 0;
    if (!lkQ_empty(&svr->signals))
        lkS_active(S, svr);
    lk_unlock(svr->lock);
    return svr;
}

LK_API lk_Service *lk_launch (lk_State *S, const char *name, lk_Handler *h, void *data) {
    lk_Service *svr;
    if (lkS_check(S, name, h) != LK_OK) return NULL;
    do {
        if ((svr = (lk_Service*)lkP_findslotG(S, name)) != NULL)
            return svr;
        svr = (lk_Service*)lkP_new(S, &S->services, (lk_Service*)name, NULL);
        if (svr == NULL) continue;
        if (lkS_initsevice(S, svr) == LK_OK) {
            lk_lock(S->lock);
            if (!lkP_register(S, &svr->slot)) svr = NULL;
            lk_unlock(S->lock);
        }
    } while (svr == NULL);
    return lkS_callinitGS(S, svr, h, data);
}


/* global routines */

static void lkG_worker(void *ud) {
    lk_State *S = (lk_State*)ud;
    lk_Service *svr;
    lk_lock(S->queue_lock);
    while (!S->dead) {
        lkQ_dequeue(&S->main_queue, svr);
        while (svr == NULL && !S->dead) {
            lk_waitevent(&S->queue_event, &S->queue_lock, -1);
            lkQ_dequeue(&S->main_queue, svr);
        }
        while (svr != NULL) {
            lk_unlock(S->queue_lock);
            lkS_dispatchGS(S, svr);
            lk_lock(S->queue_lock);
            lkQ_dequeue(&S->main_queue, svr);
        }
    }
    lk_signal(S->queue_event);
    lk_unlock(S->queue_lock);
}

static void *default_allocf (void *ud, void *ptr, size_t size, size_t osize) {
    (void)ud, (void)osize;
    if (size == 0) { free(ptr); return NULL; }
    return realloc(ptr, size);
}

static void lkG_clearservices (lk_State *S) {
    lk_Entry *e = NULL;
    while (lk_nextentry(&S->slot_names, &e)) {
        lk_Slot *slot = (lk_Slot*)e->key;
        if (slot->is_svr) {
            int ret;
            assert(slot->weak);
            slot->dead = 1;
            ret = lkS_delserviceG(S, (lk_Service*)slot);
            assert(ret == LK_OK);
        }
    }
    while (lk_nextentry(&S->config, &e))
        lk_deldata(S, (lk_Data*)e->key);
    lk_freetable(S, &S->slot_names);
    lk_freetable(S, &S->config);
}

static void lkG_delstate (lk_State *S) {
    size_t i;
    lkG_clearservices(S);
    for (i = 0; i < S->nthreads; ++i)
        lk_freethread(S->threads[i]);
    lk_freepool(S, &S->services);
    lk_freepool(S, &S->slots);
    lk_freepool(S, &S->polls);
    lk_freepool(S, &S->defers);
    lk_freepool(S, &S->signals);
    lk_freepool(S, &S->sources);
    lk_freepool(S, &S->listeners);
    lk_freepool(S, &S->smallpieces);
    lk_freeevent(S->queue_event);
    lk_freetls(S->tls_index);
    lk_freelock(S->config_lock);
    lk_freelock(S->queue_lock);
    lk_freelock(S->lock);
    S->allocf(S->alloc_ud, S, 0, sizeof(lk_State));
}

static int lkG_initstate (lk_State *S, const char *name) {
    name = name ? name : LK_NAME;
    if (lkS_initsevice(S, &S->root) != LK_OK)
        return LK_ERR;
    lk_strcpy(S->root.slot.name, name, LK_MAX_NAMESIZE);
    S->root.slot.S = S;
    lkQ_init(&S->main_queue);
    lk_initpool(&S->services, sizeof(lk_Service));
    lk_initpool(&S->slots, sizeof(lk_Slot));
    lk_initpool(&S->polls, sizeof(lk_Poll));
    lk_initpool(&S->defers, sizeof(lk_Defer));
    lk_initpool(&S->signals, sizeof(lk_SignalNode));
    lk_initpool(&S->sources, sizeof(lk_Source));
    lk_initpool(&S->listeners, sizeof(lk_Listener));
    lk_initpool(&S->smallpieces, LK_SMALLPIECE_LEN);
    lk_inittable(&S->config, sizeof(lk_PtrEntry));
    lk_inittable(&S->slot_names, sizeof(lk_Entry));
    lk_settable(S, &S->slot_names, S->root.slot.name);
    return LK_OK;
}

LK_API lk_State *lk_newstate (const char *name, lk_Allocf *allocf, void *ud) {
    lk_State *S;
    allocf = allocf ? allocf : default_allocf;
    S = (lk_State*)allocf(ud, NULL, sizeof(lk_State), 0);
    if (S == NULL) return NULL;
    memset(S, 0, sizeof(*S));
    S->allocf   = allocf;
    S->alloc_ud = ud;
    if (lk_inittls(&S->tls_index))     {
    if (lk_initevent(&S->queue_event)) {
    if (lk_initlock(&S->lock))         {
    if (lk_initlock(&S->queue_lock))   {
    if (lk_initlock(&S->config_lock))  {
    if (lk_initlock(&S->pool_lock))    {
    if (lkG_initstate(S, name) == LK_OK)
        return S;
      lk_freelock(S->pool_lock);
    } lk_freelock(S->config_lock);
    } lk_freelock(S->queue_lock);
    } lk_freelock(S->lock);
    } lk_freeevent(S->queue_event);
    } lk_freetls(S->tls_index);
    } free(S);
    return NULL;
}

LK_API void lk_close (lk_State *S) {
    lk_Context *ctx = lk_context(S);
    lk_Service *svr = ctx ? ctx->current->service : NULL;
    if (S == NULL) return;
    if (ctx == NULL && S->dead)
        lkG_delstate(S);
    else if (svr != NULL && !lkP_isdead(svr)) {
        lk_Signal sig = LK_RESPONSE;
        sig.data = svr;
        lk_broadcast(S, "close", &sig);
        lk_lock(S->lock);
        if (&svr->slot == S->logger)
            S->logger = NULL;
        lk_lock(svr->lock);
        lkP_isdead(svr) = 1;
        lkS_active(S, svr);
        lk_unlock(svr->lock);
        lk_unlock(S->lock);
    }
}

LK_API int lk_start (lk_State *S, int threads) {
    int i, count = 0;
    if (S == NULL) return 0;
    if (S->start) return S->nthreads;
    S->start = 1;
    lkS_callinitGS(S, &S->root, S->root.slot.handler, S->root.slot.data);
    if (S->root.slot.handler == NULL)
        ++S->nservices;
    count = threads <= 0 ? lk_cpucount() : threads;
    for (i = 0; i < count; ++i) {
        if (!lk_initthread(&S->threads[i], lkG_worker, S))
            break;
    }
    S->nthreads = (unsigned)i;
    lk_unlock(S->lock);
    return i;
}

LK_API int lk_cpucount (void) {
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (int)info.dwNumberOfProcessors;
#else
    return (int)sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

LK_API void lk_waitclose (lk_State *S) {
    if (S != NULL) {
#ifdef _WIN32
        WaitForMultipleObjects(S->nthreads, S->threads, TRUE, INFINITE);
#else
        size_t i;
        for (i = 0; i < S->nthreads; ++i)
            pthread_join(S->threads[i], NULL);
        S->nthreads = 0; /* not in win32: we should call CloseHandle() on win32 */
#endif
    }
}

LK_API char *lk_getconfig (lk_State *S, const char *key) {
    lk_PtrEntry *e;
    char *value = NULL;
    lk_lock(S->config_lock);
    if ((e = (lk_PtrEntry*)lk_gettable(&S->config, key)) != NULL)
        value = (char*)lk_newstring(S, (const char*)e->data);
    lk_unlock(S->config_lock);
    return value;
}

LK_API void lk_setconfig (lk_State *S, const char *key, const char *value) {
    lk_PtrEntry *e;
    char *data;
    size_t ksize, vsize;
    assert(key != NULL);
    lk_lock(S->config_lock);
    if (value == NULL) {
        e = (lk_PtrEntry*)lk_gettable(&S->config, key);
        if (e) lk_deldata(S, (lk_Data*)lk_key(e)), lk_key(e) = NULL;
        goto out;
    }
    e = (lk_PtrEntry*)lk_settable(S, &S->config, key);
    ksize = strlen(key);
    vsize = strlen(value);
    if (e->data && strlen((const char*)e->data) >= vsize) {
        memcpy(e->data, value, vsize+1);
        goto out;
    }
    data = (char*)lk_newdata(S, ksize+vsize+2);
    lk_key(e) = data;
    e->data = data + ksize + 1;
    memcpy(data, key, ksize+1);
    memcpy(e->data, value, vsize+1);
out: lk_unlock(S->config_lock);
}

LK_API int lk_log (lk_State *S, const char *fmt, ...) {
    va_list l;
    int ret;
    va_start(l, fmt);
    ret = lk_vlog(S, fmt, l);
    va_end(l);
    return ret;
}

LK_API int lk_vlog (lk_State *S, const char *fmt, va_list l) {
    lk_Slot *logger = S->logger;
    if (logger == NULL) return LK_OK;
    return lk_emitdata(logger, 0, lk_newvfstring(S, fmt, l));
}


LK_NS_END

#endif

/* win32cc: flags+='-Wextra -s -O3 -mdll -DLOKI_IMPLEMENTATION -std=c90 -pedantic -xc'
 * win32cc: output='loki.dll'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared -DLOKI_IMPLEMENTATION -xc'
 * unixcc: output='loki.so' */

