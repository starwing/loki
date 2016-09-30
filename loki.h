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

#ifndef LK_SLOTNAME_LAUNCH
# define LK_SLOTNAME_LAUNCH "on_service_launch"
#endif

#ifndef LK_SLOTNAME_CLOSE
# define LK_SLOTNAME_CLOSE "on_service_close"
#endif

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
LK_API void      lk_close    (lk_State *S);

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

LK_API int lk_retain  (lk_Service *svr);
LK_API int lk_release (lk_Service *svr);

LK_API int lk_broadcast (lk_State *S, const char *slot, const lk_Signal *sig);

LK_API lk_Service *lk_self (lk_State *S);


/* message routines */

#define LK_SIGNAL             { NULL, NULL, 0, 0, 0 }
#define LK_RESPONSE           { NULL, NULL, 0, 0, 1 }
#define lk_serviceslot(slot)  ((lk_Slot*)lk_service((lk_Slot*)(slot)))

LK_API lk_Slot *lk_newslot (lk_State *S, const char *name, lk_Handler *h, void *ud);
LK_API lk_Slot *lk_newpoll (lk_State *S, const char *name, lk_Handler *h, void *ud);
LK_API lk_Slot *lk_slot    (lk_State *S, const char *name);
LK_API lk_Slot *lk_current (lk_State *S);

LK_API int lk_wait (lk_State *S, lk_Signal *sig, int waitms);

LK_API void lk_initsource  (lk_State *S, lk_Source *src, lk_Handler *h, void *ud);
LK_API void lk_usesource   (lk_Source *src);
LK_API void lk_freesource  (lk_Source *src);
LK_API void lk_setcallback (lk_State *S, lk_Handler *h, void *ud);

LK_API int  lk_emit        (lk_Slot *slot, const lk_Signal *sig);
LK_API int  lk_emitstring  (lk_Slot *slot, unsigned type, const char *s);

LK_API void lk_sethook (lk_Slot *slot, lk_Handler *h, void *ud);
LK_API void lk_setdata (lk_Slot *slot, void *data);

LK_API void *lk_data (lk_Slot *slot);

LK_API const char *lk_name    (lk_Slot *slot);
LK_API lk_Service *lk_service (lk_Slot *slot);
LK_API lk_State   *lk_state   (lk_Slot *slot);

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
LK_API size_t   lk_usedata (lk_State *S, lk_Data *data);

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

LK_API lk_Entry *lk_newkey   (lk_State *S, lk_Table *t, lk_Entry *entry);
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

#ifndef LK_ENABLE_PCALL
#  define lk_throw(S,c) (void)(c)
#  define lk_try(S,c,a) do { a; } while (0)
#  define lk_JmpBuf     int  /* dummy variable */

#elif defined(__cplusplus) && !defined(LK_USE_LONGJMP)
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
    void         *userdata;
    lk_JmpBuf     b;
    int           retcode; /* error code */
} lk_Context;

LK_API lk_Context *lk_context  (lk_State *S);
LK_API void       *lk_userdata (lk_State *S);

LK_API void lk_pushcontext (lk_State *S, lk_Context *ctx, lk_Slot *slot);
LK_API void lk_popcontext  (lk_State *S, lk_Context *ctx);

LK_API int lk_discard (lk_State *S);
LK_API int lk_defer   (lk_State *S, lk_DeferHandler *h, void *ud);


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

struct lk_Slot {
    char           name[LK_MAX_SLOTNAME];
    unsigned char  flags;
    lk_State      *S;
    lk_Service    *service;
    void          *userdata;
    lk_Handler    *handler;
    lk_Handler    *refactor;
    lk_Handler    *hookf;
    void          *hook_ud;
    lk_Source     *source;
    lk_SignalNode *current;
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
    lk_Lock        lock;
    unsigned       pending;
    lkQ_entry(lk_Service);
    lkQ_type(lk_SignalNode) signals;
};

struct lk_State {
    lk_Service     root;
    int            nservices;
    int            nthreads;
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
    unsigned size     : 24;
    unsigned len      : 24;
    unsigned refcount : 16;
};

LK_API size_t lk_len  (lk_Data *data) { return data-- ? data->len  : 0; }
LK_API size_t lk_size (lk_Data *data) { return data-- ? data->size : 0; }

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
    LK_DEBUG_POOL(assert((signed)mpool->allocated >= 0));
    *(void**)obj = mpool->freed;
    mpool->freed = obj;
}

LK_API lk_Data *lk_newdata (lk_State *S, size_t size) {
    size_t rawlen = sizeof(lk_Data) + size;
    lk_Data *data = (lk_Data*)lk_malloc(S, rawlen);
    assert(size < LK_MAX_DATASIZE);
    data->size     = (unsigned)size;
    data->len      = 0;
    data->refcount = 0;
    if (rawlen <= LK_SMALLPIECE_LEN)
        data->size = LK_SMALLPIECE_LEN - sizeof(lk_Data);
    return data + 1;
}

LK_API size_t lk_usedata (lk_State *S, lk_Data *data) {
    size_t refcount;
    if (data-- == NULL) return 0;
    lk_lock(S->lock);
    refcount = ++data->refcount;
    lk_unlock(S->lock);
    return refcount;
}

LK_API size_t lk_deldata (lk_State *S, lk_Data *data) {
    size_t refcount = 0;
    if (data-- == NULL) return 0;
    lk_lock(S->lock);
    if (data->refcount > 1) refcount = --data->refcount;
    lk_unlock(S->lock);
    if (refcount == 0) lk_free(S, data, data->size + sizeof(lk_Data));
    return refcount;
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

LK_API void lk_freetable (lk_State *S, lk_Table *t)
{ lk_free(S, t->hash, t->size*t->entry_size); lk_inittable(t, t->entry_size); }

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

static unsigned lkH_calchash (const char *s, size_t len) {
    size_t l1;
    size_t step = (len >> LK_HASHLIMIT) + 1;
    unsigned h = (unsigned)len;
    for (l1 = len; l1 >= step; l1 -= step)
        h ^= (h<<5) + (h>>2) + (unsigned char)s[l1 - 1];
    return h;
}

static lk_Entry *lkH_get (lk_Table *t, const char *key, unsigned hash) {
    lk_Entry *e = lkH_mainposition(t, hash);
    for (;;) {
        if (e->key && (e->hash == hash && strcmp(e->key, key) == 0))
            return e;
        if (e->next == 0) return NULL;
        e = lk_index(e, e->next);
    }
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
        lk_Entry *newe = lk_newkey(S, &nt, olde);
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
    if (t->size == 0 || key == NULL) return NULL;
    return lkH_get(t, key, lkH_calchash(key, strlen(key)));
}

LK_API lk_Entry *lk_settable (lk_State *S, lk_Table *t, const char *key) {
    lk_Entry e, *ret;
    if (key == NULL) return NULL;
    e.key  = key;
    e.hash = lkH_calchash(key, strlen(key));
    if (t->size != 0 && (ret = lkH_get(t, key, e.hash)) != NULL)
        return ret;
    return lk_newkey(S, t, &e);
}

LK_API lk_Entry *lk_newkey (lk_State *S, lk_Table *t, lk_Entry *entry) {
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
    if (t->entry_size > sizeof(lk_Entry))
        memset(mp + 1, 0, t->entry_size - sizeof(lk_Entry));
    return mp;
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

LK_API void *lk_userdata (lk_State *S)
{ lk_Context *ctx = lk_context(S); return ctx ? ctx->userdata : NULL; }

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
        ctx->defers = NULL;
    }
}

LK_API void lk_pushcontext (lk_State *S, lk_Context *ctx, lk_Slot *slot) {
    ctx->prev     = lk_context(S);
    ctx->S        = S;
    ctx->current  = slot;
    ctx->defers   = NULL;
    ctx->userdata = slot ? slot->userdata : NULL;
    ctx->retcode  = LK_OK;
    lk_settls(S->tls_index, ctx);
}

LK_API void lk_popcontext (lk_State *S, lk_Context *ctx) {
    if (ctx == NULL) return;
    lkC_calldefers(S, ctx);
    lk_settls(S->tls_index, ctx->prev);
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

#define lkP_ispoll(obj)   ((((lk_Slot*)(obj))->flags & 0x01) != 0)
#define lkP_issvr(obj)    ((((lk_Slot*)(obj))->flags & 0x02) != 0)
#define lkP_isweak(obj)   ((((lk_Slot*)(obj))->flags & 0x04) != 0)
#define lkP_isdead(obj)   ((((lk_Slot*)(obj))->flags & 0x08) != 0)
#define lkP_isactive(obj) ((((lk_Slot*)(obj))->flags & 0x10) != 0)

#define lkP_setpoll(obj)   (((lk_Slot*)(obj))->flags |= 0x01)
#define lkP_setsvr(obj)    (((lk_Slot*)(obj))->flags |= 0x02)
#define lkP_setweak(obj)   (((lk_Slot*)(obj))->flags |= 0x04)
#define lkP_setdead(obj)   (((lk_Slot*)(obj))->flags |= 0x08)
#define lkP_setactive(obj) (((lk_Slot*)(obj))->flags |= 0x10)
#define lkP_clractive(obj) (((lk_Slot*)(obj))->flags &= ~0x10)

#define lkP_getter(name, type, field) \
LK_API type lk_##name (lk_Slot *slot) { return slot ? slot->field : NULL; }
#define lkP_setter(name, type, field) \
LK_API void lk_set##name (lk_Slot *s, type v) { if (s) s->field = v; }
lkP_getter(name,        const char *, name     )
lkP_getter(service,     lk_Service *, service  )
lkP_getter(state,       lk_State *,   S        )
lkP_getter(data,        void *,       userdata )
lkP_setter(data,        void *,       userdata )
lkP_getter(slothandler, lk_Handler *, handler  )
lkP_setter(slothandler, lk_Handler *, handler  )
lkP_getter(refactor,    lk_Handler *, refactor )
lkP_setter(refactor,    lk_Handler *, refactor )
#undef lkP_getter
#undef lkP_setter

LK_API lk_Slot *lk_current (lk_State *S)
{ lk_Context *ctx = lk_context(S); return ctx ? ctx->current : &S->root.slot; }

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
    if (S->nthreads != 0 && (lk_Slot*)e->key == slot)
        return slot;
    if (&slot->service->slot == slot)
        lk_freelock(slot->service->lock);
    lk_lock(S->pool_lock);
    if (lkP_issvr(slot))       lk_poolfree(&S->services, slot);
    else if (lkP_ispoll(slot)) lk_poolfree(&S->polls, slot);
    else                       lk_poolfree(&S->slots, slot);
    lk_unlock(S->pool_lock);
    return NULL;
}

static int lkP_delpoll (lk_State *S, lk_Poll *poll) {
    if (!lkP_isdead(poll)) {
        lk_lock(poll->lock);
        lkP_setdead(poll);
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
    lkP_setdead(poll);
    while (lk_wait(S, &sig, 0) == LK_OK)
        ;
    lk_popcontext(S, &ctx);
}

static int lkP_startpoll (lk_Poll *poll) {
    lk_State *S = poll->slot.S;
    lkQ_init(&poll->signals);
    if (lk_initlock(&poll->lock)) {
        if (lk_initevent(&poll->event)) {
            if (lk_initthread(&poll->thread, lkP_poller, poll))
                return LK_OK;
            lk_freeevent(poll->event);
        }
        lk_freelock(poll->lock);
    }
    lk_lock(S->pool_lock);
    lk_poolfree(&S->polls, poll);
    lk_unlock(S->pool_lock);
    return LK_ERR;
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

LK_API lk_Slot *lk_newslot (lk_State *S, const char *name, lk_Handler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    lk_Slot *slot = NULL;
    if (S == NULL || svr == NULL || lkP_check(S, "newslot", name) != LK_OK)
        return NULL;
    slot = lkP_new(S, &S->slots, svr, name);
    slot->handler  = h;
    slot->userdata = ud;
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

LK_API lk_Slot *lk_newpoll (lk_State *S, const char *name, lk_Handler *h, void *ud) {
    lk_Service *svr = lk_self(S);
    lk_Poll *poll;
    if (S == NULL || svr == NULL || lkP_check(S, "newpoll", name) != LK_OK)
        return NULL;
    poll = (lk_Poll*)lkP_new(S, &S->polls, svr, name);
    lkP_setpoll(poll);
    poll->slot.handler  = h;
    poll->slot.userdata = ud;
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

LK_API void lk_sethook (lk_Slot *slot, lk_Handler *h, void *ud) {
    if (slot == NULL) return;
    lk_lock(slot->service->lock);
    slot->hookf   = h;
    slot->hook_ud = ud;
    lk_unlock(slot->service->lock);
}

static void lkP_callhook (lk_Slot *slot, lk_Slot *sender, lk_Signal *sig) {
    lk_Handler *hookf = slot->hookf;
    void *ud;
    if (hookf == NULL) return;
    lk_lock(slot->service->lock);
    hookf = slot->hookf;
    ud    = slot->hook_ud;
    lk_unlock(slot->service->lock);
    if (hookf) {
        lk_Context ctx;
        lk_pushcontext(slot->S, &ctx, slot);
        ctx.userdata = ud;
        lk_try(S, &ctx, hookf(slot->S, sender, sig));
        lk_popcontext(slot->S, &ctx);
    }
}


/* emit signal */

static void lkS_active (lk_State *S, lk_Service *svr);

LK_API int lk_emitstring (lk_Slot *slot, unsigned type, const char *s)
{ return slot ? lk_emitdata(slot, type, lk_newstring(slot->S, s)) : LK_ERR; }

static int lkE_srcdeletor (lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    (void)sender;
    lk_lock(S->pool_lock);
    lk_poolfree(&S->sources, sig->source);
    lk_unlock(S->pool_lock);
    return LK_OK;
}

static lk_SignalNode *lkE_newsignal (lk_State *S, lk_Slot *slot, const lk_Signal *sig) {
    lk_Slot *sender = lk_current(S);
    lk_SignalNode *node;
    lk_Source *src;
    lk_lock(S->pool_lock);
    node = (lk_SignalNode*)lk_poolalloc(S, &S->signals);
    lk_unlock(S->pool_lock);
    node->recipient = slot;
    node->sender    = sender;
    node->data      = *sig;
    lk_retain(sender->service);
    if (node->data.source == NULL && sender->source != NULL) {
        node->data.source = sender->source;
        sender->source = NULL;
    }
    if ((src = node->data.source) != NULL) {
        lk_retain(src->service);
        lk_usesource(src);
    }
    if (node->data.isdata) lk_usedata(S, (lk_Data*)node->data.data);
    return node;
}

static void lkE_delsignal (lk_State *S, lk_SignalNode *node) {
    lk_Source *src = node->data.source;
    lk_Service *svr;
    if (node->data.isdata) lk_deldata(S, (lk_Data*)node->data.data);
    if (src != NULL && (svr = src->service) != NULL) {
        lk_freesource(src);
        lk_release(svr);
    }
    if ((svr = node->sender->service) != NULL)
        lk_release(svr);
    lk_lock(S->pool_lock);
    lk_poolfree(&S->signals, node);
    lk_unlock(S->pool_lock);
}

static int lkE_emitS (lk_Slot *slot, lk_SignalNode *node) {
    lk_Service *svr = slot->service;
    int ret = LK_ERR;
    lk_lock(svr->lock);
    if (svr->slot.S->nthreads != 0 && !lkP_isdead(svr)) {
        lk_Poll *poll = (lk_Poll*)slot;
        if (!lkP_ispoll(slot)) {
            lkQ_enqueue(&svr->signals, node);
            lkS_active(svr->slot.S, svr);
            ret = LK_OK;
        }
        else if (!lkP_isdead(poll)) {
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

static int lkE_filterslot (lk_Table *t, lk_Entry **pe, const char *name) {
    for (;;) {
        lk_Slot *slot;
        const char *slotname;
        if (!lk_nextentry(t, pe)) return 0;
        if ((name == NULL) != lkP_issvr(slot = (lk_Slot*)(*pe)->key))
            continue;
        if (name == NULL || ((slotname = strchr(slot->name, '.')) != NULL
                    && strcmp(slotname+1, name) == 0))
            return 1;
    }
}

LK_API void lk_initsource (lk_State *S, lk_Source *src, lk_Handler *h, void *ud) {
    memset(src, 0, sizeof(*src));
    src->service  = lk_self(S);
    src->callback = h;
    src->ud       = ud;
}

LK_API void lk_usesource (lk_Source *src) {
    assert(src && src->service);
    if (src->service == NULL) return;
    lk_lock(src->service->lock);
    ++src->refcount;
    lk_unlock(src->service->lock);
}

LK_API void lk_freesource (lk_Source *src) {
    lk_Signal sig = LK_SIGNAL;
    lk_State *S;
    unsigned refcount = 0;
    sig.source = src;
    assert(src->service != NULL);
    if (src->service == NULL) return;
    S = src->service->slot.S;
    lk_lock(src->service->lock);
    if (src->refcount >= 1) refcount = --src->refcount;
    lk_unlock(src->service->lock);
    if (refcount == 0 && src->deletor != NULL) {
        lk_Context ctx;
        lk_pushcontext(S, &ctx, &src->service->slot);
        lk_try(S, &ctx, src->deletor(S, NULL, &sig));
        lk_popcontext(S, &ctx);
    }
}

LK_API void lk_setcallback (lk_State *S, lk_Handler *h, void *ud) {
    lk_Slot *slot = lk_current(S);
    lk_Source *src;
    if (slot->source != NULL) lk_freesource(slot->source);
    lk_lock(S->pool_lock);
    src = (lk_Source*)lk_poolalloc(S, &S->sources);
    lk_unlock(S->pool_lock);
    lk_initsource(S, src, h, ud);
    src->deletor  = lkE_srcdeletor;
    slot->source  = src;
}

LK_API int lk_emit (lk_Slot *slot, const lk_Signal *sig) {
    lk_SignalNode *node;
    assert(slot != NULL);
    if (slot == NULL || sig == NULL) return LK_ERR;
    node = lkE_newsignal(slot->S, slot, sig);
    if (lkE_emitS(slot, node) != LK_OK) {
        lkE_delsignal(slot->S, node);
        return LK_ERR;
    }
    return LK_OK;
}

LK_API int lk_broadcast (lk_State *S, const char *name, const lk_Signal *sig) {
    lk_Slot *current = lk_current(S);
    lk_SignalNode *node = lkE_newsignal(S, current, sig);
    int count = 0;
    if (node != NULL) {
        lk_Table t;
        lk_Entry *e = NULL;
        lk_lock(S->lock);
        lk_copytable(S, &t, &S->slot_names);
        lk_unlock(S->lock);
        while (lkE_filterslot(&t, &e, name)) {
            lk_Slot *slot = (lk_Slot*)e->key;
            if (sig == NULL || lk_emit(slot, &node->data) == LK_OK)
                ++count;
        }
        lk_freetable(S, &t);
    }
    lkE_delsignal(S, node);
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
    lk_Slot *slot = &poll->slot;
    lk_SignalNode *node = NULL;
    if (poll == NULL || !lkP_ispoll(poll)) return LK_ERR;
    if (slot->current) {
        lkP_callhook(slot, slot->current->sender, &slot->current->data);
        lkE_delsignal(S, slot->current);
        slot->current = NULL;
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
    slot->current = node;
    if (sig) *sig = node->data;
    return LK_OK;
}


/* service routines */

LK_API lk_Service *lk_self (lk_State *S)
{ lk_Slot *slot = lk_current(S); return slot ? slot->service : NULL; }

static int lkS_initsevice (lk_State *S, lk_Service *svr) {
    lkP_setsvr(svr);
    lkP_setactive(svr);
    svr->slot.service = svr;
    svr->slots = &svr->slot;
    lkQ_init(&svr->signals);
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
        if (lkP_ispoll(slot = *pslots)
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
        if (lkP_issvr(slot = *pslots) || lkP_ispoll(slot))
            pslots = &slot->next;
        else {
            *pslots = slot->next;
            lk_poolfree(&S->slots, slot);
        }
    }
    lk_unlock(S->pool_lock);
}

static void lkS_release (lk_State *S, lk_Service *svr) {
    lk_lock(S->lock);
    if (!lkP_isweak(svr)) --S->nservices;
    if (S->nservices == 0) {
        lk_lock(S->queue_lock);
        lk_signal(S->queue_event);
        lk_unlock(S->queue_lock);
    }
    lk_unlock(S->lock);
}

static int lkS_delserviceG (lk_State *S, lk_Service *svr) {
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
    lkS_release(S, svr);
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
    if (!lkP_isactive(svr)) {
        lkP_setactive(svr);
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
    lkP_callhook(slot, node->sender, &node->data);
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
    assert(lkP_isactive(svr));
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
        lkP_clractive(svr);
    lk_unlock(svr->lock);

    if (should_delete && lkS_delserviceG(S, svr) != LK_OK)
        lkP_clractive(svr);
}

static int lkS_check (lk_State *S, const char *name, lk_Handler *h) {
    if (S == NULL || name == NULL || h == NULL)
        return LK_ERR;
    if (strlen(name) >= LK_MAX_NAMESIZE) {
        lk_log(S, "E[launch]" lk_loc("serivce name '%s' too long"), name);
        return LK_ERR;
    }
    return S->nthreads == 0 ? LK_ERR : LK_OK;
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
        lkP_setweak(svr);
        --S->nservices;
    }
    lk_unlock(S->lock);
    return LK_OK;
}

static lk_Service *lkS_callinitGS (lk_State *S, lk_Service *svr, lk_Handler *h, void *ud) {
    lk_Signal sig = LK_RESPONSE;
    svr->slot.handler  = h;
    svr->slot.userdata = ud;
    if (h && lkS_callinit(S, svr) != LK_OK)
        return NULL;
    sig.data = svr;
    lk_broadcast(S, LK_SLOTNAME_LAUNCH, &sig);
    lk_lock(svr->lock);
    lkP_clractive(svr);
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

LK_API int lk_retain (lk_Service *svr) {
    int pending;
    if (svr == NULL) return 0;
    lk_lock(svr->lock);
    pending = (int)++svr->pending;
    lk_unlock(svr->lock);
    return pending;
}

LK_API int lk_release (lk_Service *svr) {
    int pending = 0;
    if (svr == NULL) return 0;
    lk_lock(svr->lock);
    if (svr->pending > 0) pending = (int)--svr->pending;
    if (pending == 0 && lkP_isdead(svr)) lkS_active(svr->slot.S, svr);
    lk_unlock(svr->lock);
    return pending;
}


/* global routines */

static void lkG_worker(void *ud) {
    lk_State *S = (lk_State*)ud;
    lk_Service *svr;
    lk_lock(S->queue_lock);
    while (S->nservices != 0) {
        lkQ_dequeue(&S->main_queue, svr);
        while (svr == NULL && S->nservices != 0) {
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
        if (lkP_issvr(slot)) {
            int ret;
            assert(lkP_isweak(slot));
            ret = lkS_delserviceG(S, (lk_Service*)slot);
            assert(ret == LK_OK);
        }
    }
    while (lk_nextentry(&S->config, &e))
        lk_deldata(S, (lk_Data*)e->key);
    lk_freetable(S, &S->slot_names);
    lk_freetable(S, &S->config);
}

static int lkG_initstate (lk_State *S, const char *name) {
    name = name ? name : LK_NAME;
    if (lkS_initsevice(S, &S->root) != LK_OK)
        return LK_ERR;
    lk_strcpy(S->root.slot.name, name, LK_MAX_NAMESIZE);
    S->root.slot.S = S;
    S->nthreads = -1; /* no thread and no start */
    lkQ_init(&S->main_queue);
    lk_initpool(&S->services, sizeof(lk_Service));
    lk_initpool(&S->slots, sizeof(lk_Slot));
    lk_initpool(&S->polls, sizeof(lk_Poll));
    lk_initpool(&S->defers, sizeof(lk_Defer));
    lk_initpool(&S->signals, sizeof(lk_SignalNode));
    lk_initpool(&S->sources, sizeof(lk_Source));
    lk_initpool(&S->smallpieces, LK_SMALLPIECE_LEN);
    lk_inittable(&S->config, sizeof(lk_PtrEntry));
    lk_inittable(&S->slot_names, sizeof(lk_Entry));
    lk_settable(S, &S->slot_names, S->root.slot.name);
    return LK_OK;
}

static void lkG_delstate (lk_State *S) {
    lkG_clearservices(S);
    lk_freepool(S, &S->services);
    lk_freepool(S, &S->slots);
    lk_freepool(S, &S->polls);
    lk_freepool(S, &S->defers);
    lk_freepool(S, &S->signals);
    lk_freepool(S, &S->sources);
    lk_freepool(S, &S->smallpieces);
    lk_freeevent(S->queue_event);
    lk_freetls(S->tls_index);
    lk_freelock(S->config_lock);
    lk_freelock(S->queue_lock);
    lk_freelock(S->lock);
    S->allocf(S->alloc_ud, S, 0, sizeof(lk_State));
}

static void lkG_setconfig(lk_State *S, const char *key, const char *value) {
    if (value == NULL) {
        lk_PtrEntry *e = (lk_PtrEntry*)lk_gettable(&S->config, key);
        if (e) lk_deldata(S, (lk_Data*)lk_key(e)), lk_key(e) = NULL;
    }
    else {
        lk_PtrEntry *e = (lk_PtrEntry*)lk_settable(S, &S->config, key);
        size_t ksize = strlen(key);
        size_t vsize = strlen(value);
        char *data;
        if (e->data && strlen((const char*)e->data) >= vsize) {
            memcpy(e->data, value, vsize+1);
            return;
        }
        data = (char*)lk_newdata(S, ksize+vsize+2);
        lk_key(e) = data;
        e->data = data + ksize + 1;
        memcpy(data, key, ksize+1);
        memcpy(e->data, value, vsize+1);
    }
}

LK_API lk_State *lk_newstate (const char *name, lk_Allocf *allocf, void *ud) {
    enum { TLS, EVT, LCK, QLK, CLK, PLK, TOTAL };
    lk_Allocf *alloc = allocf ? allocf : default_allocf;
    lk_State *S = (lk_State*)alloc(ud, NULL, sizeof(lk_State), 0);
    unsigned ok = 0;
    if (S == NULL) return NULL;
    memset(S, 0, sizeof(*S));
    S->allocf = alloc, S->alloc_ud = ud;
    if (lk_inittls(&S->tls_index))     ok |= 1<<TLS;
    if (lk_initevent(&S->queue_event)) ok |= 1<<EVT;
    if (lk_initlock(&S->lock))         ok |= 1<<LCK;
    if (lk_initlock(&S->queue_lock))   ok |= 1<<QLK;
    if (lk_initlock(&S->config_lock))  ok |= 1<<CLK;
    if (lk_initlock(&S->pool_lock))    ok |= 1<<PLK;
    if (ok == (1<<TOTAL)-1 && lkG_initstate(S, name) == LK_OK) return S;
    if ((ok & (1<<PLK)) != 0) lk_freelock(S->pool_lock);
    if ((ok & (1<<CLK)) != 0) lk_freelock(S->config_lock);
    if ((ok & (1<<QLK)) != 0) lk_freelock(S->queue_lock);
    if ((ok & (1<<LCK)) != 0) lk_freelock(S->lock);
    if ((ok & (1<<EVT)) != 0) lk_freeevent(S->queue_event);
    if ((ok & (1<<TLS)) != 0) lk_freetls(S->tls_index);
    allocf(ud, S, 0, sizeof(lk_State));
    return NULL;
}

LK_API void lk_close (lk_State *S) {
    lk_Context *ctx = lk_context(S);
    lk_Service *svr = ctx && ctx->current ? ctx->current->service : NULL;
    if (ctx == NULL && S && S->nservices == 0)
        lkG_delstate(S);
    else if (svr != NULL && !lkP_isdead(svr)) {
        lk_Signal sig = LK_RESPONSE;
        sig.data = svr;
        lk_broadcast(S, LK_SLOTNAME_CLOSE, &sig);
        lk_lock(S->lock);
        if (&svr->slot == S->logger)
            S->logger = NULL;
        lk_unlock(S->lock);
        lk_lock(svr->lock);
        lkP_setdead(svr);
        lkS_active(S, svr);
        lk_unlock(svr->lock);
    }
}

LK_API int lk_start (lk_State *S, int threads) {
    int i, count = 0;
    if (S == NULL) return 0;
    if (S->nthreads > 0) return S->nthreads;
    lkS_callinitGS(S, &S->root, S->root.slot.handler, S->root.slot.userdata);
    if (S->root.slot.handler == NULL)
        ++S->nservices;
    count = threads <= 0 ? lk_cpucount() : threads;
    for (i = 0; i < count; ++i) {
        if (!lk_initthread(&S->threads[i], lkG_worker, S))
            break;
    }
    S->nthreads = i;
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
        int i;
#ifdef _WIN32
        WaitForMultipleObjects(S->nthreads, S->threads, TRUE, INFINITE);
        for (i = 0; i < S->nthreads; ++i)
            lk_freethread(S->threads[i]);
#else
        for (i = 0; i < S->nthreads; ++i)
            pthread_join(S->threads[i], NULL);
#endif
        S->nthreads = 0; /* not in win32: we should call CloseHandle() on win32 */
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
    assert(key != NULL);
    if (key == NULL) return;
    lk_lock(S->config_lock);
    lkG_setconfig(S, key, value);
    lk_unlock(S->config_lock);
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

