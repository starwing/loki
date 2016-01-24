#ifndef loki_services_h
#define loki_services_h


#include "loki.h"


#ifndef lk_Time
# ifdef LOKI_USE_64BIT_TIMER
typedef unsigned long long lk_Time;
# else
typedef unsigned lk_Time;
# endif
# define lk_Time lk_Time
#endif /* lk_Time */

typedef struct lk_Timer lk_Timer;

typedef lk_Time lk_TimerHandler (lk_State *S, void *ud, lk_Timer *timer, lk_Time delayed);


LK_API int lk_openlibs(lk_State *S);


/* timer service */

LKMOD_API int loki_service_timer(lk_State *S);

LK_API lk_Time lk_time(void);

LK_API lk_Timer *lk_newtimer (lk_Service *svr, lk_TimerHandler *h, void *ud);
LK_API void      lk_deltimer (lk_Timer *timer);

LK_API void lk_starttimer  (lk_Timer *timer, lk_Time delayms);
LK_API void lk_canceltimer (lk_Timer *timer);


#endif /* loki_services_h */

#if defined(LOKI_IMPLEMENTATION) && !defined(loki_services_implemented)
#define loki_services_implemented

LK_API int lk_openlibs(lk_State *S) {
    lk_preload(S, "timer", loki_service_timer);
    return LK_OK;
}


#endif
