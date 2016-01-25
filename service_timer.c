#define LOKI_MODULE
#include "loki_services.h"

#include <assert.h>
#include <string.h>


#ifdef _WIN32

LK_API lk_Time lk_time(void) {
    static LARGE_INTEGER counterFreq, startTime;
    LARGE_INTEGER current;
    if (counterFreq.QuadPart == 0) {
        QueryPerformanceFrequency(&counterFreq);
        QueryPerformanceCounter(&startTime);
        assert(counterFreq.HighPart == 0);
    }
    QueryPerformanceCounter(&current);
    return (lk_Time)((current.QuadPart - startTime.QuadPart) * 1000
            / counterFreq.LowPart);
}

#else

LK_API lk_Time lk_time(void) {
#ifdef __APPLE__
    static mach_timebase_info_data_t time_info;
    static uint64_t start;
    if (!time_info.numer) {
        start = mach_absolute_time();
	(void)mach_timebase_info(&time_info);
    }
    uint64_t now = mach_absolute_time();
    return (zn_Time)((now - start) * time_info.numer / time_info.denom / 1000000);
#else
    static lk_Time start = ~(lk_Time)0;
    struct timespec ts;
    lk_Time time;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
        return 1;
    time = (lk_Time)((lk_Time)ts.tv_sec*1000+ts.tv_nsec/1000000);
    if (start == ~(lk_Time)0) {
        start = time;
        return 0;
    }
    return time - start;
#endif
}

#endif


/* implements */

#define lkT_getstate(svr)  ((lk_TimerState*)lk_data(svr))

#define LK_TIMER_NOINDEX (~(unsigned)0)
#define LK_FOREVER       (~(lk_Time)0)
#ifndef LK_MAX_SIZET
# define LK_MAX_SIZET    ((~(size_t)0)-100)
#endif

#define LK_MIN_TIMEHEAP 512

typedef struct lk_TimerState lk_TimerState;

struct lk_Timer {
    union { lk_Timer *next; void *ud; } u;
    lk_TimerHandler *handler;
    lk_Service *service;
    lk_TimerState *ts;
    unsigned index;
    lk_Time starttime;
    lk_Time emittime;
};

struct lk_TimerState {
    lk_State  *S;
    lk_Timer  *freed;
    lk_Timer **heap;
    lk_Slot   *poll;
    lk_Lock    lock;
    lk_Time nexttime;
    unsigned heap_used;
    unsigned heap_size;
};

static int lkT_resizeheap(lk_TimerState *ts, size_t size) {
    lk_Timer **heap;
    size_t realsize = LK_MIN_TIMEHEAP;
    while (realsize < size && realsize < LK_MAX_SIZET/sizeof(lk_Timer*)/2)
        realsize <<= 1;
    if (realsize < size) return 0;
    heap = (lk_Timer**)lk_realloc(ts->S, ts->heap, realsize*sizeof(lk_Timer*));
    ts->heap = heap;
    ts->heap_size = realsize;
    return 1;
}

static void lkT_canceltimer(lk_TimerState *ts, lk_Timer *timer) {
    unsigned index = timer->index;
    if (index == LK_TIMER_NOINDEX) return;
    timer->index = LK_TIMER_NOINDEX;
    if (ts->heap_used == 0 || timer == ts->heap[--ts->heap_used])
        return;
    timer = ts->heap[ts->heap_used];
    while (1) {
        unsigned left = (index<<1)|1, right = (index+1)<<1;
        unsigned newindex = right;
        if (left >= ts->heap_used) break;
        if (timer->emittime >= ts->heap[left]->emittime) {
            if (right >= ts->heap_used
                    || ts->heap[left]->emittime < ts->heap[right]->emittime)
                newindex = left;
        }
        else if (right >= ts->heap_used
                || timer->emittime <= ts->heap[right]->emittime)
            break;
        ts->heap[index] = ts->heap[newindex];
        ts->heap[index]->index = index;
        index = newindex;
    }
    ts->heap[index] = timer;
    timer->index = index;
}

static void lkT_starttimer(lk_TimerState *ts, lk_Timer *timer, lk_Time delayms) {
    unsigned index;
    if (timer->index != LK_TIMER_NOINDEX)
        lkT_canceltimer(ts, timer);
    if (ts->heap_size <= ts->heap_used)
        lkT_resizeheap(ts, ts->heap_size * 2);
    index = ts->heap_used++;
    timer->starttime = lk_time();
    timer->emittime = timer->starttime + delayms;
    while (index) {
        unsigned parent = (index-1)>>1;
        if (ts->heap[parent]->emittime <= timer->emittime)
            break;
        ts->heap[index] = ts->heap[parent];
        ts->heap[index]->index = index;
        index = parent;
    }
    ts->heap[index] = timer;
    timer->index = index;
    if (index == 0) {
        lk_Signal sig = LK_SIGNAL;
        ts->nexttime = timer->emittime;
        lk_emit(ts->poll, &sig);
    }
}

LK_API lk_Timer *lk_newtimer(lk_Service *svr, lk_TimerHandler *cb, void *ud) {
    lk_TimerState *ts = lkT_getstate(svr);
    lk_State *S = lk_state((lk_Slot*)svr);
    lk_Timer *timer;
    lk_lock(ts->lock);
    timer = ts->freed;
    if (timer == NULL)
        timer = (lk_Timer*)lk_malloc(S, sizeof(lk_Timer));
    else
        ts->freed = timer->u.next;
    timer->u.ud = ud;
    timer->handler = cb;
    timer->ts = ts;
    timer->service = lk_self(S);
    timer->index = LK_TIMER_NOINDEX;
    lk_unlock(ts->lock);
    return timer;
}

LK_API void lk_deltimer(lk_Timer *timer) {
    lk_TimerState *ts = timer->ts;
    lk_lock(ts->lock);
    lkT_canceltimer(ts, timer);
    timer->handler = NULL;
    timer->u.next = ts->freed;
    ts->freed = timer;
    lk_unlock(ts->lock);
}

LK_API void lk_starttimer(lk_Timer *timer, lk_Time delayms) {
    lk_TimerState *ts = timer->ts;
    lk_lock(ts->lock);
    lkT_starttimer(ts, timer, delayms);
    lk_unlock(ts->lock);
}

LK_API void lk_canceltimer(lk_Timer *timer) {
    lk_TimerState *ts = timer->ts;
    lk_lock(ts->lock);
    lkT_canceltimer(ts, timer);
    lk_unlock(ts->lock);
}

static void lkT_cleartimers(lk_TimerState *ts) {
    lk_free(ts->S, ts->heap);
    memset(ts, 0, sizeof(lk_TimerState));
    ts->nexttime = LK_FOREVER;
}

static void lkT_updatetimers(lk_TimerState *ts, lk_Time current) {
    if (ts->nexttime > current) return;
    while (ts->heap_used && ts->heap[0]->emittime <= current) {
        lk_Signal sig = LK_SIGNAL;
        lk_Timer *timer = ts->heap[0];
        lkT_canceltimer(ts, timer);
        timer->emittime = current;
        sig.data = timer;
        lk_emit((lk_Slot*)timer->service, &sig);
    }
    ts->nexttime = ts->heap_used == 0 ? LK_FOREVER : ts->heap[0]->emittime;
}

static lk_TimerState *lkT_newstate (lk_State *S) {
    lk_TimerState *ts = (lk_TimerState*)
        lk_malloc(S, sizeof(lk_TimerState));
    memset(ts, 0, sizeof(*ts));
    if (!lk_initlock(&ts->lock))
        lk_discard(S);
    ts->S = S;
    return ts;
}

static int lkT_poller (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_TimerState *ts = (lk_TimerState*)ud;
    lk_Time nexttime, current;
    (void)S; (void)sig;
    for (;;) {
        int waittime;
        lk_lock(ts->lock);
        lkT_updatetimers(ts, current = lk_time());
        nexttime = ts->nexttime;
        assert(nexttime > current);
        lk_unlock(ts->lock);
        waittime = nexttime == LK_FOREVER ? -1
            : (int)(nexttime - current);
        if (lk_wait(slot, NULL, waittime) == LK_ERR)
            break;
    }
    return LK_OK;
}

static int lkT_refactor (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_TimerState *ts = (lk_TimerState*)ud;
    (void)slot;
    if (sig != NULL) {
        lk_Timer *timer = (lk_Timer*)sig->data;
        if (timer->handler) {
            int ret = timer->handler(S, timer->u.ud, timer,
                    timer->emittime - timer->starttime);
            if (ret > 0) lk_starttimer(timer, ret);
            else {
                lk_lock(ts->lock);
                timer->u.next = ts->freed;
                ts->freed = timer;
                lk_unlock(ts->lock);
            }
        }
    }
    return LK_OK;
}

static int lkT_deletor (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_TimerState *ts = (lk_TimerState*)ud;
    (void)slot;
    if (sig == NULL) {
        lkT_cleartimers(ts);
        lk_freelock(ts->lock);
        lk_free(S, ts->heap);
        while (ts->freed != NULL) {
            lk_Timer *next = ts->freed->u.next;
            lk_free(S, ts->freed);
            ts->freed = next;
        }
        lk_free(S, ts);
    }
    return LK_OK;
}

LKMOD_API int loki_service_timer(lk_State *S) {
    lk_TimerState *ts = lkT_newstate(S);
    lk_Service *svr = lk_self(S);
    lk_setdata(svr, ts);
    ts->poll = lk_newpoll(S, "poll", lkT_poller, ts);
    lk_setslothandler((lk_Slot*)svr, lkT_deletor, ts);
    lk_setrefactor(svr, lkT_refactor, (void*)ts);
    return LK_WEAK;
}

/* win32cc: flags+='-Wextra -s -O3 -mdll -DLOKI_IMPLEMENTATION -std=c90 -pedantic'
 * win32cc: output='loki.dll'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared -DLOKI_IMPLEMENTATION'
 * unixcc: output='loki.so' */

